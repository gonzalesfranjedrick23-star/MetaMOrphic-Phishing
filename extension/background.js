/*
 * background.js - CyberSentinel service worker (Manifest V3).
 *
 * ENFORCEMENT model (spec parts 2, 9-19):
 *   - The local CyberSentinel engine is AUTHORITATIVE. Every navigation is sent
 *     to POST /api/v1/url/scan and, when enabled, POST /api/v1/content/check.
 *   - The in-browser KNN (knn.js) is only a labelled FALLBACK, used when the
 *     backend is unreachable. It is never a second detection engine.
 *   - DETECTION (receiving a nav event + a verdict) is separate from ENFORCEMENT
 *     (navigating the tab to the CyberSentinel interstitial). A blocking verdict
 *     always triggers the redirect; the interstitial is a real extension page
 *     that survives the popup being closed.
 *   - Downloads: downloads.onCreated -> POST /api/v1/download/check -> cancel an
 *     obviously-malicious download early where the API permits. The background
 *     agent performs the authoritative on-disk scan and quarantine.
 *
 * Nothing sensitive (passwords, cookies, tokens, form values, page contents) is
 * collected or sent. Only the URL, and for the content filter the page title +
 * a short visible-text sample, are transmitted to the local backend.
 */
importScripts("config.js");    // IS_OSS_BUILD, CYBERSENTINEL
importScripts("features.js");   // NoPhishingFeatures  (KNN fallback)
importScripts("knn.js");        // NoPhishingKNN       (KNN fallback)
importScripts("storage.js");    // NoPhishingStore     (KNN fallback)
importScripts("lookalike.js");  // NoPhishingLookalike (KNN fallback)

const API = CYBERSENTINEL.API_BASE;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
function hostnameOf(url) {
  try { return new URL(url).hostname; } catch (e) { return ""; }
}
function isAnalyzable(url) {
  return typeof url === "string" &&
    (url.startsWith("http://") || url.startsWith("https://")) &&
    !url.startsWith(chrome.runtime.getURL(""));
}
async function getEnabled() {
  const { isEnabled } = await chrome.storage.sync.get("isEnabled");
  return isEnabled !== false; // default ON once the user completed setup
}
async function getTrustedDomains() {
  const { trusted_domains } = await chrome.storage.local.get("trusted_domains");
  return Array.isArray(trusted_domains) ? trusted_domains : [];
}
async function isTrusted(url) {
  const host = hostnameOf(url);
  const list = await getTrustedDomains();
  return !!(host && list.includes(host));
}
async function trustDomain(url) {
  const host = hostnameOf(url);
  if (!host) return;
  const list = await getTrustedDomains();
  if (!list.includes(host)) {
    list.push(host);
    await chrome.storage.local.set({ trusted_domains: list });
  }
}

// ---------------------------------------------------------------------------
// backend client (authoritative) + KNN fallback
// ---------------------------------------------------------------------------
async function backendScanUrl(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch(API + "/url/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: ctrl.signal,
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function backendContentCheck(url, title, textSample) {
  try {
    const r = await fetch(API + "/content/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, page_title: title || "", page_text_sample: textSample || "" }),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

async function backendDownloadCheck(info) {
  try {
    const r = await fetch(API + "/download/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(info),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

// KNN fallback -> shape like the backend outcome so downstream code is uniform.
async function knnFallbackScan(url, nbHyperlinks) {
  try {
    const ds = await NoPhishingStore.buildDataset();
    const feats = NoPhishingFeatures.extractFeatures(url, nbHyperlinks || 0);
    const scaled = NoPhishingKNN.scale(feats, ds.scaler);
    const { label, ratio } = NoPhishingKNN.predict(scaled, ds.X, ds.y, ds.k);
    const look = NoPhishingLookalike.check(url);
    const phishing = label === 1 || look.hit;
    const pct = look.hit ? Math.max(Math.round(ratio * 100), look.confidence || 0) : Math.round(ratio * 100);
    return {
      _fallback: true,
      _scaled: scaled,
      classification: phishing ? "PHISHING" : "SAFE",
      risk_percent: phishing ? Math.max(pct, 60) : Math.round(ratio * 100),
      risk_level: phishing ? "high" : "low",
      analysis_status: "complete",
      enforcement_action: phishing ? "REDIRECT" : "ALLOW",
      xai_explanation: look.reason
        ? ("Offline check (backend unavailable): " + look.reason)
        : "Offline in-browser check (backend unavailable): nearest-neighbour vote indicates phishing.",
      recommendation: "Do not enter passwords, payment information, or personal information.",
      evidence: [],
      _lookReason: look.reason || "",
    };
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// health badge (spec part 22)
// ---------------------------------------------------------------------------
async function refreshHealth() {
  let state = "OFFLINE";
  let detail = null;
  try {
    const r = await fetch(API + "/realtime/health");
    if (r.ok) {
      detail = await r.json();
      state = (detail.protection || "PROTECTION OFFLINE").replace("PROTECTION ", "");
    }
  } catch (e) { /* OFFLINE */ }
  await chrome.storage.session.set({ cs_health: { state, detail, ts: Date.now() } });
  const color = state === "ACTIVE" ? "#137333" : state === "DEGRADED" ? "#b06000" : "#a50e0e";
  try {
    await chrome.action.setBadgeBackgroundColor({ color });
    await chrome.action.setBadgeText({ text: state === "ACTIVE" ? "" : state === "DEGRADED" ? "!" : "x" });
  } catch (e) { /* action API may be unavailable in some contexts */ }
  return state;
}
chrome.alarms.create("cs_health", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "cs_health") refreshHealth(); });

// ---------------------------------------------------------------------------
// per-tab URL result cache (spec part 14: analyse the final committed URL,
// avoid endless rescanning of redirect chains / SPA updates)
// ---------------------------------------------------------------------------
const urlCache = new Map(); // key `${tabId}|${url}` -> { ts, outcome }
function cacheGet(tabId, url) {
  const hit = urlCache.get(tabId + "|" + url);
  if (hit && Date.now() - hit.ts < CYBERSENTINEL.URL_CACHE_TTL_MS) return hit.outcome;
  return null;
}
function cachePut(tabId, url, outcome) {
  urlCache.set(tabId + "|" + url, { ts: Date.now(), outcome });
  if (urlCache.size > 500) urlCache.delete(urlCache.keys().next().value);
}
chrome.tabs.onRemoved.addListener((tabId) => {
  for (const k of Array.from(urlCache.keys())) if (k.startsWith(tabId + "|")) urlCache.delete(k);
});

// ---------------------------------------------------------------------------
// navigation -> analyse -> enforce  (spec parts 9-14)
// ---------------------------------------------------------------------------
const debounce = new Map(); // `${tabId}` -> timer
function analyseNav(tabId, url) {
  if (!isAnalyzable(url)) return;
  clearTimeout(debounce.get(tabId));
  debounce.set(tabId, setTimeout(() => analyseAndEnforce(tabId, url).catch(() => {}), 250));
}
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) analyseNav(d.tabId, d.url);
});
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId === 0) analyseNav(d.tabId, d.url); // SPA route changes
});

async function analyseAndEnforce(tabId, url) {
  if (!(await getEnabled())) return;
  if (await isTrusted(url)) return;           // user vouched for this host
  if (cacheGet(tabId, url)) return;           // already handled this URL for this tab

  // 1. phishing / malicious-URL verdict (authoritative, KNN fallback)
  let outcome = await backendScanUrl(url);
  if (!outcome) outcome = await knnFallbackScan(url, 0);
  if (!outcome) return;

  cachePut(tabId, url, outcome);

  const risk = Number(outcome.risk_percent || 0);
  const action = String(outcome.enforcement_action || "").toUpperCase();
  const blockPhishing = action === "REDIRECT" || action === "BLOCK" ||
                        risk >= CYBERSENTINEL.BLOCK_THRESHOLD;

  if (blockPhishing) {
    return enforceBlock(tabId, url, {
      kind: "phishing",
      classification: outcome.classification || "PHISHING",
      risk_percent: Math.max(0, Math.min(100, Math.round(risk))),
      risk_level: outcome.risk_level || "high",
      xai: outcome.xai_explanation || "",
      evidence: outcome.evidence || [],
      recommendation: outcome.recommendation ||
        "Do not enter passwords, payment information, or personal information.",
      analysis_status: outcome.analysis_status || "complete",
      fallback: !!outcome._fallback,
      scaled: outcome._scaled || null,
      lookReason: outcome._lookReason || "",
    });
  }

  // 2. content filter (only if the user enabled it) - independent of phishing
  const { cs_content_policy } = await chrome.storage.sync.get("cs_content_policy");
  if (cs_content_policy && cs_content_policy.enabled) {
    let title = "";
    let sample = "";
    try {
      const resp = await chrome.tabs.sendMessage(tabId, { action: "getPageSignals" });
      if (resp) { title = resp.title || ""; sample = resp.textSample || ""; }
    } catch (e) { /* content script not present */ }
    const cf = await backendContentCheck(url, title, sample);
    if (cf && cf.blocked) {
      return enforceBlock(tabId, url, {
        kind: "content",
        classification: "BLOCKED",
        content_category: cf.content_category,
        risk_percent: Math.round((cf.content_risk || 0) * 100),
        xai: cf.reason || "This website was blocked by the enabled content-filtering policy.",
        evidence: (cf.matched || []).map((m) => ({ summary: m })),
        recommendation: cf.recommendation ||
          "Return to a safer search page, or disable this category in Protection Settings.",
        analysis_status: "complete",
      });
    }
  }
}

// ENFORCEMENT: store the result and navigate the tab to the interstitial.
async function enforceBlock(tabId, url, result) {
  const token = Math.random().toString(36).slice(2);
  await chrome.storage.session.set({
    ["cs_block:" + token]: { url, result, ts: Date.now() },
  });
  if (result.scaled) {
    // keep the KNN vector so "Proceed" can log a legitimate correction
    await chrome.storage.session.set({ ["pending:" + url]: result.scaled });
  }
  const dest = chrome.runtime.getURL("extension/blocked.html") + "?t=" + token;
  try {
    await chrome.tabs.update(tabId, { url: dest });
  } catch (e) {
    console.warn("CyberSentinel: could not redirect tab", e);
  }
}

// ---------------------------------------------------------------------------
// downloads (spec part 3A) - best-effort browser-level cancel
// ---------------------------------------------------------------------------
chrome.downloads.onCreated.addListener(async (item) => {
  if (!(await getEnabled())) return;
  const { cs_download_protection } = await chrome.storage.sync.get("cs_download_protection");
  if (cs_download_protection === false) return;

  const info = {
    url: item.finalUrl || item.url || "",
    filename: item.filename || "",
    mime: item.mime || "",
    file_size: item.fileSize || item.totalBytes || 0,
  };
  const verdict = await backendDownloadCheck(info);
  if (!verdict) return; // backend unreachable -> rely on the background agent

  const action = String(verdict.enforcement_action || "").toUpperCase();
  if (action === "BLOCK") {
    try {
      await chrome.downloads.cancel(item.id);
      await chrome.downloads.erase({ id: item.id });
    } catch (e) { /* may already be too far along - agent will catch it on disk */ }
    notify("CyberSentinel - DOWNLOAD BLOCKED",
      `${info.filename || "download"}\nRisk: ${verdict.risk_percent}% (${verdict.classification})\n` +
      (verdict.recommendation || "Do not open or execute this file."));
    logEvent("download_blocked", { filename: info.filename, risk: verdict.risk_percent });
  } else if (action === "WARN") {
    notify("CyberSentinel - suspicious download",
      `${info.filename || "download"}\n${verdict.recommendation || "Verify the source before opening."}`);
  }
});

function notify(title, message) {
  try {
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("images/logo.png"),
      title, message, priority: 2,
    });
  } catch (e) { console.warn("notification failed", e); }
}

async function logEvent(kind, data) {
  const { cs_events } = await chrome.storage.local.get("cs_events");
  const list = Array.isArray(cs_events) ? cs_events : [];
  list.push({ kind, ...data, ts: new Date().toISOString() });
  while (list.length > 200) list.shift();
  await chrome.storage.local.set({ cs_events: list });
}

// ---------------------------------------------------------------------------
// KNN fallback path via content.js (kept for offline / "mark as phishing")
// ---------------------------------------------------------------------------
async function addPoint(scaledFeatures, label) {
  if (!IS_OSS_BUILD) return;
  await NoPhishingStore.addFeedbackPoint(scaledFeatures, label);
}
async function addLegitimateForUrl(url) {
  if (!IS_OSS_BUILD || !url) return;
  const key = "pending:" + url;
  const data = await chrome.storage.session.get(key);
  let scaled = data[key];
  if (!Array.isArray(scaled)) {
    const ds = await NoPhishingStore.buildDataset();
    scaled = NoPhishingKNN.scale(NoPhishingFeatures.extractFeatures(url, 0), ds.scaler);
  }
  await addPoint(scaled, 0);
  await chrome.storage.session.remove(key);
}
async function markActiveTabPhishing() {
  if (!IS_OSS_BUILD) return { ok: false };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  if (!isAnalyzable(url)) return { ok: false };
  let nb = 0;
  try {
    const resp = await chrome.tabs.sendMessage(tab.id, { action: "getLinkCount" });
    if (resp && typeof resp.nbHyperlinks === "number") nb = resp.nbHyperlinks;
  } catch (e) { /* no content script */ }
  const ds = await NoPhishingStore.buildDataset();
  const scaled = NoPhishingKNN.scale(NoPhishingFeatures.extractFeatures(url, nb), ds.scaler);
  await addPoint(scaled, 1);
  return { ok: true };
}
async function computeStats() {
  const fb = await NoPhishingStore.getFeedbackPoints();
  const count = fb.length;
  let lastUpdated = null;
  for (const p of fb) if (p.ts && (lastUpdated === null || p.ts > lastUpdated)) lastUpdated = p.ts;
  let accuracy = null;
  const cached = (await chrome.storage.local.get("stats_cache")).stats_cache;
  if (cached && cached.count === count && typeof cached.accuracy === "number") {
    accuracy = cached.accuracy;
  } else {
    const ds = await NoPhishingStore.buildDataset();
    const test = await NoPhishingStore.loadTest();
    if (test && Array.isArray(test.X) && test.X.length) {
      let correct = 0;
      for (let i = 0; i < test.X.length; i++) {
        const { label } = NoPhishingKNN.predict(test.X[i], ds.X, ds.y, ds.k);
        if (label === test.y[i]) correct++;
      }
      accuracy = correct / test.X.length;
      await chrome.storage.local.set({ stats_cache: { count, accuracy } });
    }
  }
  return { feedbackCount: count, lastUpdated, accuracy };
}

// ---------------------------------------------------------------------------
// lifecycle + messaging
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.storage.sync.set({ isEnabled: false });         // off until setup completes
    chrome.tabs.create({ url: chrome.runtime.getURL("extension/setup.html") });
  }
  refreshHealth();
});
chrome.runtime.onStartup.addListener(refreshHealth);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg && msg.action) {
    case "updateState":
      chrome.storage.sync.set({ isEnabled: !!msg.state });
      return;
    case "completeSetup":
      chrome.storage.sync.set({
        isEnabled: true,
        cs_download_protection: msg.downloadProtection !== false,
      });
      refreshHealth();
      sendResponse({ ok: true });
      return true;
    case "getHealth":
      chrome.storage.session.get("cs_health").then((d) => sendResponse(d.cs_health || null));
      return true;
    case "getBlock":
      chrome.storage.session.get("cs_block:" + msg.token).then((d) =>
        sendResponse(d["cs_block:" + msg.token] || null));
      return true;
    case "trustDomain":
      trustDomain(msg.url).then(() => { urlCache.clear(); sendResponse({ ok: true }); });
      return true;
    case "addLegitimate":
      addLegitimateForUrl(msg.url).then(() => sendResponse({ ok: true }));
      return true;
    case "markPhishing":
      markActiveTabPhishing().then(sendResponse);
      return true;
    case "getStats":
      computeStats().then(sendResponse);
      return true;
    case "scanActiveTab":
      (async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !isAnalyzable(tab.url)) { sendResponse(null); return; }
        urlCache.delete(tab.id + "|" + tab.url);
        let o = await backendScanUrl(tab.url);
        if (!o) o = await knnFallbackScan(tab.url, 0);
        sendResponse({ url: tab.url, outcome: o });
      })();
      return true;
    case "getContentPolicy":
      fetch(API + "/content/policy").then((r) => r.json()).then(sendResponse)
        .catch(() => sendResponse(null));
      return true;
    case "setContentPolicy":
      fetch(API + "/content/policy", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(msg.policy || {}),
      }).then((r) => r.json()).then((j) => {
        chrome.storage.sync.set({ cs_content_policy: (j && j.policy) || null });
        sendResponse(j);
      }).catch(() => sendResponse(null));
      return true;
  }
  // KNN fallback page report from content.js
  if (msg && msg.type === "NP_PAGE" && sender.tab) {
    knnPageReport(msg, sender.tab.id).catch(() => {});
  }
});

// Offline KNN page check (only acts when the backend path did not already run,
// e.g. content.js fired before onCommitted, or the backend is down).
async function knnPageReport(msg, tabId) {
  if (!(await getEnabled())) return;
  const url = msg.url;
  if (!isAnalyzable(url) || await isTrusted(url)) return;
  if (cacheGet(tabId, url)) return;
  // let the authoritative path try first
  const backend = await backendScanUrl(url);
  if (backend) {
    cachePut(tabId, url, backend);
    const risk = Number(backend.risk_percent || 0);
    const act = String(backend.enforcement_action || "").toUpperCase();
    if (act === "REDIRECT" || act === "BLOCK" || risk >= CYBERSENTINEL.BLOCK_THRESHOLD) {
      return enforceBlock(tabId, url, {
        kind: "phishing", classification: backend.classification || "PHISHING",
        risk_percent: Math.round(risk), risk_level: backend.risk_level || "high",
        xai: backend.xai_explanation || "", evidence: backend.evidence || [],
        recommendation: backend.recommendation ||
          "Do not enter passwords, payment information, or personal information.",
        analysis_status: backend.analysis_status || "complete",
      });
    }
    return;
  }
  const fb = await knnFallbackScan(url, msg.nbHyperlinks);
  if (fb && fb.enforcement_action === "REDIRECT") {
    cachePut(tabId, url, fb);
    return enforceBlock(tabId, url, {
      kind: "phishing", classification: "PHISHING", risk_percent: fb.risk_percent,
      risk_level: "high", xai: fb.xai_explanation, evidence: [],
      recommendation: fb.recommendation, analysis_status: "complete",
      fallback: true, scaled: fb._scaled, lookReason: fb._lookReason,
    });
  }
}

refreshHealth();
