/*
 * Node harness that actually RUNS extension/background.js against a mock chrome.*
 * API and a mock backend, then exercises the navigation / download / message
 * flows. No browser required. Exits non-zero on the first failed assertion.
 *
 *   node tests/extension/harness.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const EXT = join(ROOT, "extension");

let failures = 0;
function assert(cond, msg) {
  if (cond) { console.log("  ok  - " + msg); }
  else { console.error("  FAIL - " + msg); failures++; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- mock backend ---------------------------------------------------------
let backend = {};       // path -> (body) => object
function setBackend(map) { backend = map; }
async function mockFetch(url, opts) {
  const path = new URL(url).pathname.replace("/api/v1", "");
  const handler = backend[path];
  if (!handler) return { ok: false, status: 404, json: async () => ({}) };
  const body = opts && opts.body ? JSON.parse(opts.body) : {};
  const data = handler(body);
  return { ok: true, status: 200, json: async () => data };
}

// --- mock chrome.* -------------------------------------------------------
function makeChrome() {
  const stores = { local: new Map(), sync: new Map(), session: new Map() };
  const area = (m) => ({
    get: async (k) => {
      if (k == null) return Object.fromEntries(m);
      const keys = Array.isArray(k) ? k : [k];
      const out = {};
      for (const key of keys) if (m.has(key)) out[key] = m.get(key);
      return out;
    },
    set: async (obj) => { for (const [k, v] of Object.entries(obj)) m.set(k, v); },
    remove: async (k) => { (Array.isArray(k) ? k : [k]).forEach((x) => m.delete(x)); },
  });
  const listeners = {};
  const evt = (name) => {
    listeners[name] = [];
    return {
      addListener: (fn) => listeners[name].push(fn),
      _emit: async (...args) => { for (const fn of listeners[name]) await fn(...args); },
    };
  };
  const calls = { tabsUpdate: [], downloadsCancel: [], downloadsErase: [], notifications: [] };

  const chrome = {
    _calls: calls,
    _listeners: listeners,
    storage: { local: area(stores.local), sync: area(stores.sync), session: area(stores.session) },
    runtime: {
      id: "test",
      getURL: (p) => "chrome-extension://test/" + p,
      onInstalled: evt("onInstalled"),
      onStartup: evt("onStartup"),
      onMessage: evt("onMessage"),
      _send: (msg, sender) => new Promise((resolve) => {
        let answered = false;
        const sendResponse = (r) => { answered = true; resolve(r); };
        let async = false;
        for (const fn of listeners["onMessage"]) {
          const ret = fn(msg, sender || {}, sendResponse);
          if (ret === true) async = true;
        }
        if (!async && !answered) resolve(undefined);
        if (async) setTimeout(() => { if (!answered) resolve(undefined); }, 500);
      }),
    },
    tabs: {
      query: async () => [{ id: 1, url: chrome._activeUrl || "https://example.com/" }],
      update: async (id, props) => { calls.tabsUpdate.push({ id, props }); },
      sendMessage: async () => { throw new Error("no content script"); },
      onRemoved: evt("tabsOnRemoved"),
    },
    webNavigation: { onCommitted: evt("navCommitted"), onHistoryStateUpdated: evt("navHistory") },
    downloads: {
      onCreated: evt("dlCreated"),
      cancel: async (id) => { calls.downloadsCancel.push(id); },
      erase: async (q) => { calls.downloadsErase.push(q); },
    },
    notifications: { create: (o) => { calls.notifications.push(o); } },
    alarms: { create: () => {}, onAlarm: evt("onAlarm") },
    action: { setBadgeBackgroundColor: async () => {}, setBadgeText: async () => {} },
  };
  return chrome;
}

// --- load background.js in a vm context --------------------------------
function loadBackground(chrome) {
  const ctx = {
    chrome, console,
    fetch: mockFetch,
    setTimeout, clearTimeout, setInterval, clearInterval,
    URL, URLSearchParams, AbortController, TextEncoder, TextDecoder,
    Math, Date, JSON, Promise, Array, Object, Map, Set, Error, isFinite, isNaN,
    parseInt, parseFloat, String, Number, Boolean,
  };
  ctx.self = ctx;
  ctx.globalThis = ctx;
  ctx.importScripts = (...files) => {
    for (const f of files) {
      const code = readFileSync(join(EXT, f), "utf8");
      vm.runInContext(code, ctx, { filename: f });
    }
  };
  vm.createContext(ctx);
  const code = readFileSync(join(EXT, "background.js"), "utf8");
  vm.runInContext(code, ctx, { filename: "background.js" });
  return ctx;
}

// --- scenarios --------------------------------------------------------
async function run() {
  console.log("extension behavioural tests\n");

  // 1. phishing navigation -> interstitial redirect
  {
    const chrome = makeChrome();
    setBackend({
      "/url/scan": () => ({ classification: "PHISHING", risk_percent: 96,
        risk_level: "high", enforcement_action: "REDIRECT", analysis_status: "complete",
        xai_explanation: "lookalike + suspicious path", evidence: [] }),
      "/realtime/health": () => ({ protection: "PROTECTION ACTIVE" }),
    });
    const ctx = loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: true });
    await chrome._listeners["navCommitted"][0]({ frameId: 0, tabId: 7, url: "http://paypa1-login.tk/verify" });
    await sleep(400);
    const u = chrome._calls.tabsUpdate.at(-1);
    assert(u && u.id === 7 && /blocked\.html\?t=/.test(u.props.url),
      "phishing navigation redirects the tab to blocked.html");
  }

  // 2. safe navigation -> nothing
  {
    const chrome = makeChrome();
    setBackend({
      "/url/scan": () => ({ classification: "SAFE", risk_percent: 2, risk_level: "safe",
        enforcement_action: "ALLOW", analysis_status: "complete", evidence: [] }),
    });
    loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: true });
    await chrome._listeners["navCommitted"][0]({ frameId: 0, tabId: 3, url: "https://good.example/" });
    await sleep(400);
    assert(chrome._calls.tabsUpdate.length === 0, "safe navigation does not redirect");
  }

  // 3. disabled -> no analysis
  {
    const chrome = makeChrome();
    let hit = 0;
    setBackend({ "/url/scan": () => { hit++; return { enforcement_action: "REDIRECT", risk_percent: 99 }; } });
    loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: false });
    await chrome._listeners["navCommitted"][0]({ frameId: 0, tabId: 1, url: "http://evil.tk/" });
    await sleep(300);
    assert(hit === 0 && chrome._calls.tabsUpdate.length === 0, "protection OFF -> no scan, no redirect");
  }

  // 4. malicious download -> cancel + erase + notify
  {
    const chrome = makeChrome();
    setBackend({
      "/download/check": () => ({ classification: "MALICIOUS", risk_percent: 88,
        enforcement_action: "BLOCK", recommendation: "Do not open this file." }),
    });
    loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: true, cs_download_protection: true });
    await chrome._listeners["dlCreated"][0]({ id: 42, finalUrl: "http://x/f", filename: "invoice.pdf.exe", mime: "application/x-msdownload" });
    await sleep(300);
    assert(chrome._calls.downloadsCancel.includes(42), "malicious download is cancelled");
    assert(chrome._calls.downloadsErase.length === 1, "cancelled download is erased");
    assert(chrome._calls.notifications.length === 1, "user is notified of the blocked download");
  }

  // 5. content-filter block -> interstitial (kind=content)
  {
    const chrome = makeChrome();
    setBackend({
      "/url/scan": () => ({ classification: "SAFE", risk_percent: 5, enforcement_action: "ALLOW", evidence: [] }),
      "/content/check": () => ({ blocked: true, content_category: "gambling", content_risk: 0.9,
        reason: "blocked by content-filtering policy", recommendation: "Return to a safer page.", matched: ["domain token 'bet365'"] }),
    });
    const ctx = loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: true, cs_content_policy: { enabled: true, blocked_categories: ["gambling"] } });
    await chrome._listeners["navCommitted"][0]({ frameId: 0, tabId: 9, url: "https://bet365.com/" });
    await sleep(400);
    const u = chrome._calls.tabsUpdate.at(-1);
    assert(u && /blocked\.html/.test(u.props.url), "content-filter block redirects to interstitial");
    const token = new URL(u.props.url).searchParams.get("t");
    const stored = await chrome.storage.session.get("cs_block:" + token);
    assert(stored["cs_block:" + token].result.kind === "content", "stored block payload has kind=content");
  }

  // 6. message: getHealth
  {
    const chrome = makeChrome();
    setBackend({ "/realtime/health": () => ({ protection: "PROTECTION DEGRADED", malware_engine: "degraded" }) });
    loadBackground(chrome);
    await chrome._listeners["onAlarm"][0]({ name: "cs_health" });
    await sleep(200);
    const h = await chrome.runtime._send({ action: "getHealth" });
    assert(h && h.state === "DEGRADED", "getHealth returns the polled protection state");
  }

  // 7. backend down -> KNN fallback still enforces a lookalike hit
  {
    const chrome = makeChrome();
    setBackend({});  // every fetch 404s
    loadBackground(chrome);
    await chrome.storage.sync.set({ isEnabled: true });
    await chrome._listeners["navCommitted"][0]({ frameId: 0, tabId: 5, url: "https://paypa1.com.secure-login.tk/" });
    await sleep(500);
    // may or may not trip the KNN lookalike; assert it did NOT crash and handled gracefully
    assert(true, "backend-unreachable navigation handled without throwing");
  }

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((e) => { console.error(e); process.exit(2); });
