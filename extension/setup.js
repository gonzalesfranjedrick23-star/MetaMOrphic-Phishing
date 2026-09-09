/*
 * setup.js - first-run consent. Protection is OFF until the user clicks Enable.
 */
(function () {
  "use strict";
  var enable = document.getElementById("enable");
  var later = document.getElementById("later");
  var dl = document.getElementById("dl");

  enable.addEventListener("click", function () {
    chrome.runtime.sendMessage(
      { action: "completeSetup", downloadProtection: dl.checked },
      function () {
        document.getElementById("setup").style.display = "none";
        document.getElementById("done").style.display = "block";
      }
    );
  });

  later.addEventListener("click", function () {
    chrome.runtime.sendMessage({ action: "updateState", state: false });
    window.close();
  });
})();
