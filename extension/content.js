/*
 * content.js - runs on every http/https page (document_idle).
 *
 * Reports the page URL + hyperlink count to the service worker (KNN fallback
 * path), and answers two on-demand requests:
 *   - getLinkCount    : <a> count, for the popup's "Mark as phishing"
 *   - getPageSignals  : page <title> + a short VISIBLE-TEXT sample, used only by
 *                       the optional content filter. No form values, inputs,
 *                       passwords, cookies or full page HTML are ever read.
 *
 * Nothing is sent off the device - only to the local CyberSentinel backend.
 */
(function () {
  function linkCount() {
    return document.querySelectorAll("a").length;
  }

  function pageSignals() {
    let text = "";
    try {
      text = (document.body && document.body.innerText ? document.body.innerText : "")
        .replace(/\s+/g, " ")
        .slice(0, 1500);
    } catch (e) { text = ""; }
    return { title: (document.title || "").slice(0, 200), textSample: text };
  }

  try {
    chrome.runtime.sendMessage({
      type: "NP_PAGE",
      url: location.href,
      title: document.title || "",
      host: location.hostname,
      path: location.pathname,
      nbHyperlinks: linkCount(),
    });
  } catch (e) {
    // Extension context can be invalidated during reloads/updates - ignore.
  }

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg) return;
    if (msg.action === "getLinkCount") {
      sendResponse({ nbHyperlinks: linkCount() });
    } else if (msg.action === "getPageSignals") {
      sendResponse(pageSignals());
    }
  });
})();
