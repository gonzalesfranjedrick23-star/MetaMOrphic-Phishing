/*
 * blocked.js - the CyberSentinel interstitial (phishing OR content-filter).
 *
 * The verdict was stored by the service worker under cs_block:<token> before it
 * navigated this tab here. This page reads it back and renders the risk, the XAI
 * evidence and the recommendation. It NEVER touches the blocked site and only
 * navigates away on an explicit button press. "Go to Google" uses the fixed safe
 * URL from config.js.
 */
(function () {
  "use strict";
  var SAFE = (self.CYBERSENTINEL && self.CYBERSENTINEL.SAFE_LANDING) || "https://www.google.com/";

  var params = new URLSearchParams(location.search);
  var token = params.get("t");

  var el = {
    title: document.getElementById("title"),
    site: document.getElementById("site"),
    score: document.getElementById("score"),
    level: document.getElementById("level"),
    bar: document.getElementById("barFill"),
    xai: document.getElementById("xai"),
    evidence: document.getElementById("evidence"),
    rec: document.getElementById("rec"),
    status: document.getElementById("status"),
    google: document.getElementById("google"),
    back: document.getElementById("back"),
    proceed: document.getElementById("proceed"),
  };

  el.google.addEventListener("click", function () { location.replace(SAFE); });
  el.back.addEventListener("click", function () {
    if (history.length > 1) history.back(); else location.replace(SAFE);
  });

  function evidenceItems(result) {
    var items = [];
    (result.evidence || []).forEach(function (e) {
      if (!e) return;
      if (typeof e === "string") { items.push(e); return; }
      if (e.summary) { items.push(e.summary); return; }
      if (e.reason && e.detector) { items.push(e.detector + ": " + e.reason); return; }
      if (e.description) { items.push(e.description); }
    });
    if (result.lookReason) items.push(result.lookReason);
    if (!items.length) {
      items.push(result.kind === "content"
        ? "Matched the enabled content-filtering policy" + (result.content_category ? " (" + result.content_category + ")" : "")
        : "Multiple URL / domain / page characteristics associated with phishing");
    }
    return items;
  }

  function render(url, result) {
    var isContent = result.kind === "content";
    document.title = "CyberSentinel - " + (isContent ? "Content Blocked" : "Website Blocked");
    el.title.textContent = isContent ? "Content Access Blocked" : "Potential Phishing Website";
    el.title.className = isContent ? "content" : "";
    el.site.textContent = url || "";

    var pct = Math.max(0, Math.min(100, Math.round(Number(result.risk_percent) || 0)));
    el.score.textContent = pct + "%";
    el.level.textContent = isContent
      ? ("category: " + (result.content_category || "blocked"))
      : ("risk level: " + (result.risk_level || "high"));
    el.bar.style.width = pct + "%";

    if (result.xai) el.xai.textContent = result.xai;

    el.evidence.innerHTML = "";
    evidenceItems(result).forEach(function (t) {
      var li = document.createElement("li");
      li.textContent = t;
      el.evidence.appendChild(li);
    });

    el.rec.textContent = result.recommendation ||
      (isContent
        ? "Return to a safer search page, or disable this category in Protection Settings."
        : "Do not enter passwords, payment information, or personal information on this website.");

    var bits = [];
    if (result.analysis_status && result.analysis_status !== "complete") {
      bits.push("Analysis status: " + result.analysis_status);
    }
    if (result.fallback) bits.push("Offline check (CyberSentinel backend was unreachable).");
    el.status.textContent = bits.join("  ");

    if (!isContent) {
      el.proceed.hidden = false;
      el.proceed.addEventListener("click", function () {
        chrome.runtime.sendMessage({ action: "trustDomain", url: url }, function () {
          chrome.runtime.sendMessage({ action: "addLegitimate", url: url }, function () {
            location.replace(url);
          });
        });
      });
    }
  }

  if (!token) {
    el.evidence.innerHTML = "<li>This warning has expired. Use the buttons below.</li>";
    el.proceed.hidden = true;
    return;
  }

  chrome.runtime.sendMessage({ action: "getBlock", token: token }, function (data) {
    if (!data || !data.result) {
      el.evidence.innerHTML = "<li>This warning has expired or could not be loaded.</li>";
      return;
    }
    render(data.url, data.result);
  });
})();
