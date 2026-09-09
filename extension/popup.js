/*
 * popup.js - CyberSentinel toolbar popup.
 *
 * Real-time protection runs in the service worker; this popup only reflects and
 * configures it. Closing the popup does not stop detection or enforcement.
 */
document.addEventListener("DOMContentLoaded", function () {
  var CATS = ["adult", "gambling", "violence", "drugs", "hate", "malware_hosting"];

  // ---- protection master toggle + health -----------------------------------
  var toggle = document.getElementById("toggleSwitch");
  chrome.storage.sync.get("isEnabled", function (d) {
    toggle.checked = d.isEnabled !== false;
  });
  toggle.addEventListener("change", function () {
    chrome.runtime.sendMessage({ action: "updateState", state: this.checked });
  });

  function renderHealth(h) {
    var dot = document.getElementById("protDot");
    var state = document.getElementById("protState");
    var detail = document.getElementById("protDetail");
    var s = (h && h.state) || "OFFLINE";
    dot.className = "dot " + s.toLowerCase();
    state.textContent = "Protection " + s;
    if (h && h.detail) {
      var d = h.detail;
      detail.textContent = "engine: " + (d.malware_engine || "?") +
        "  ·  monitor: " + (d.file_monitor || "?") +
        (d.queue_depth != null ? "  ·  queue: " + d.queue_depth : "");
    } else {
      detail.textContent = "CyberSentinel backend not reachable on 127.0.0.1:5000";
    }
  }
  chrome.runtime.sendMessage({ action: "getHealth" }, renderHealth);

  // ---- current site verdict ----------------------------------------------
  function renderSite(res) {
    var host = document.getElementById("siteHost");
    var verdict = document.getElementById("siteVerdict");
    var why = document.getElementById("siteWhy");
    if (!res || !res.outcome) {
      host.textContent = "This page cannot be scanned";
      verdict.textContent = "—";
      why.textContent = "";
      return;
    }
    var o = res.outcome;
    try { host.textContent = new URL(res.url).hostname; } catch (e) { host.textContent = res.url; }
    var cls = o.classification || "UNKNOWN";
    var pct = Math.round(Number(o.risk_percent) || 0);
    verdict.textContent = cls + "  ·  " + pct + "%";
    verdict.style.color =
      cls === "SAFE" ? "#22c55e" :
      (cls === "PHISHING" || cls === "MALICIOUS" || cls === "HIGH RISK") ? "#ef4444" :
      cls === "UNKNOWN" ? "#94a3b8" : "#f59e0b";
    why.textContent = (o.xai_explanation || "").slice(0, 240);
    if (o._fallback) why.textContent = "(offline check) " + why.textContent;
  }
  function scan() {
    document.getElementById("siteVerdict").textContent = "Scanning…";
    chrome.runtime.sendMessage({ action: "scanActiveTab" }, renderSite);
  }
  document.getElementById("scanBtn").addEventListener("click", scan);
  scan();

  // ---- content filter ---------------------------------------------------
  var cfToggle = document.getElementById("cfToggle");
  var cfCats = document.getElementById("cfCats");
  var currentPolicy = { enabled: false, blocked_categories: [] };

  CATS.forEach(function (cat) {
    var lbl = document.createElement("label");
    var cb = document.createElement("input");
    cb.type = "checkbox"; cb.dataset.cat = cat;
    lbl.appendChild(cb);
    lbl.appendChild(document.createTextNode(" " + cat.replace("_", " ")));
    cb.addEventListener("change", pushPolicy);
    cfCats.appendChild(lbl);
  });

  function renderPolicy(j) {
    var p = (j && j.policy) || currentPolicy;
    currentPolicy = p;
    cfToggle.checked = !!p.enabled;
    cfCats.querySelectorAll("input").forEach(function (cb) {
      cb.checked = (p.blocked_categories || []).indexOf(cb.dataset.cat) !== -1;
      cb.disabled = !p.enabled;
    });
  }
  function pushPolicy() {
    var cats = [];
    cfCats.querySelectorAll("input").forEach(function (cb) { if (cb.checked) cats.push(cb.dataset.cat); });
    var policy = { enabled: cfToggle.checked, blocked_categories: cats };
    chrome.runtime.sendMessage({ action: "setContentPolicy", policy: policy }, renderPolicy);
  }
  cfToggle.addEventListener("change", pushPolicy);
  chrome.runtime.sendMessage({ action: "getContentPolicy" }, function (j) {
    if (j) renderPolicy(j);
  });

  // ---- download protection -------------------------------------------
  var dlToggle = document.getElementById("dlToggle");
  chrome.storage.sync.get("cs_download_protection", function (d) {
    dlToggle.checked = d.cs_download_protection !== false;
  });
  dlToggle.addEventListener("change", function () {
    chrome.storage.sync.set({ cs_download_protection: this.checked });
  });

  // ---- trusted sites -------------------------------------------------
  var list = document.getElementById("trustedList");
  var empty = document.getElementById("trustedEmpty");
  function renderTrusted() {
    chrome.storage.local.get("trusted_domains", function (d) {
      var domains = Array.isArray(d.trusted_domains) ? d.trusted_domains : [];
      list.innerHTML = "";
      empty.style.display = domains.length ? "none" : "block";
      domains.forEach(function (host) {
        var li = document.createElement("li");
        var span = document.createElement("span"); span.textContent = host;
        var btn = document.createElement("button");
        btn.className = "remove"; btn.textContent = "✕";
        btn.addEventListener("click", function () {
          chrome.storage.local.get("trusted_domains", function (dd) {
            var next = (dd.trusted_domains || []).filter(function (x) { return x !== host; });
            chrome.storage.local.set({ trusted_domains: next }, renderTrusted);
          });
        });
        li.appendChild(span); li.appendChild(btn); list.appendChild(li);
      });
    });
  }
  renderTrusted();

  // ---- OSS self-learning -------------------------------------------
  if (typeof IS_OSS_BUILD !== "undefined" && IS_OSS_BUILD) {
    var oss = document.getElementById("ossSection");
    oss.style.display = "block";
    var status = document.getElementById("feedbackStatus");
    function stats() {
      chrome.runtime.sendMessage({ action: "getStats" }, function (s) {
        if (!s) return;
        document.getElementById("statCount").textContent = s.feedbackCount + " added";
        document.getElementById("statUpdated").textContent =
          s.lastUpdated ? new Date(s.lastUpdated).toLocaleString() : "—";
        document.getElementById("statAcc").textContent =
          s.accuracy == null ? "—" : Math.round(s.accuracy * 100) + "%";
      });
    }
    stats();
    document.getElementById("markPhishingBtn").addEventListener("click", function () {
      this.disabled = true;
      var self = this;
      chrome.runtime.sendMessage({ action: "markPhishing" }, function (r) {
        self.disabled = false;
        status.textContent = r && r.ok ? "Marked as phishing. Thanks!" : "Cannot mark this page.";
        setTimeout(function () { status.textContent = ""; }, 4000);
        if (r && r.ok) stats();
      });
    });
  }
});
