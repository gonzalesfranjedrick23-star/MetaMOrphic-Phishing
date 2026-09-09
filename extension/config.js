/*
 * config.js — build-time configuration, loaded first in every context
 * (service worker via importScripts, popup/warning pages via <script>).
 *
 * IS_OSS_BUILD gates the open-source self-learning feedback features:
 * feedback collection, the popup's "Mark as phishing" / "Export feedback"
 * buttons, and recording a "legitimate" correction when the user proceeds past
 * a warning. The Chrome Web Store build sets this to false (see build_cws.py),
 * which strips all of the above — the store build never collects feedback.
 */
var IS_OSS_BUILD = true;

// Expose as a global for both service-worker and page contexts.
if (typeof self !== "undefined") self.IS_OSS_BUILD = IS_OSS_BUILD;

/*
 * CyberSentinel runtime configuration. The central engine (the local
 * CyberSentinel backend / background agent) is authoritative; the in-browser
 * KNN is only a labelled fallback used when the backend is unreachable.
 */
var CYBERSENTINEL = {
  // Local API served by the CyberSentinel backend / background agent.
  API_BASE: "http://127.0.0.1:5000/api/v1",
  // risk_percent at or above which a page is BLOCKED (interstitial). Below this
  // and above WARN_THRESHOLD the popup shows a caution but the page is allowed.
  BLOCK_THRESHOLD: 60,
  WARN_THRESHOLD: 40,
  // Safe destination for the "Go to Google" action on the interstitial.
  // Must be a fixed, safe URL - never a user-controlled or unsafe address.
  SAFE_LANDING: "https://www.google.com/",
  SAFE_SEARCH: "https://www.google.com/search?q=",
  // How often the service worker polls /realtime/health for the status badge.
  HEALTH_INTERVAL_MS: 30000,
  // Per-tab URL result cache TTL (avoids rescanning on redirect chains / SPA).
  URL_CACHE_TTL_MS: 60000,
};

if (typeof self !== "undefined") self.CYBERSENTINEL = CYBERSENTINEL;
