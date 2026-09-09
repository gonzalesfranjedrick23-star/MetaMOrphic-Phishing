"""Extension manifest + asset integrity (spec parts 13, 19).

Verifies MV3, the permissions the code actually uses, that no over-broad
permission is requested, and that every referenced file exists. Also checks the
new interstitial/setup pages carry no inline scripts (CSP: script-src 'self').
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_manifest_v3():
    assert MANIFEST["manifest_version"] == 3
    assert MANIFEST["background"]["service_worker"] == "extension/background.js"


def test_permissions_are_exactly_what_the_code_uses():
    perms = set(MANIFEST["permissions"])
    # each of these is exercised by background.js
    assert perms == {"tabs", "storage", "webNavigation", "downloads", "notifications", "alarms"}
    # no over-broad / unrelated permissions
    for forbidden in ("<all_urls>", "cookies", "history", "webRequest",
                      "webRequestBlocking", "management", "proxy", "debugger",
                      "nativeMessaging", "clipboardRead"):
        assert forbidden not in perms
    assert MANIFEST["host_permissions"] == ["http://*/*", "https://*/*"]


def test_all_referenced_files_exist():
    refs = [
        MANIFEST["background"]["service_worker"],
        MANIFEST["action"]["default_popup"],
        *MANIFEST["content_scripts"][0]["js"],
        *MANIFEST["icons"].values(),
        *MANIFEST["action"]["default_icon"].values(),
    ]
    for r in refs:
        assert (ROOT / r).exists(), f"manifest references missing file: {r}"


def test_service_worker_uses_only_declared_apis():
    sw = (ROOT / "extension/background.js").read_text(encoding="utf-8")
    used = set(re.findall(r"chrome\.(\w+)", sw))
    allowed = {"runtime", "storage", "tabs", "webNavigation", "downloads",
               "notifications", "alarms", "action"}
    assert used <= allowed, f"background.js uses undeclared chrome APIs: {used - allowed}"


@pytest.mark.parametrize("page", ["blocked.html", "setup.html", "popup.html"])
def test_pages_have_no_inline_scripts(page):
    html = (ROOT / "extension" / page).read_text(encoding="utf-8")
    # every <script> must have a src=; no inline JS, no inline on* handlers
    for m in re.finditer(r"<script\b([^>]*)>", html):
        assert "src=" in m.group(1), f"{page} has an inline <script>"
    assert not re.search(r"\son\w+\s*=", html), f"{page} has an inline event handler"


def test_pages_reference_their_scripts():
    for page, script in (("blocked.html", "blocked.js"),
                         ("setup.html", "setup.js"),
                         ("popup.html", "popup.js")):
        html = (ROOT / "extension" / page).read_text(encoding="utf-8")
        assert f'src="{script}"' in html
        assert (ROOT / "extension" / script).exists()


def test_content_script_only_reads_visible_signals():
    cs = (ROOT / "extension/content.js").read_text(encoding="utf-8")
    # must not read form/input values, cookies, localStorage of the page
    for bad in ("document.cookie", ".value", "localStorage", "sessionStorage",
                'querySelectorAll("input"', "FormData"):
        assert bad not in cs, f"content.js reads sensitive page data: {bad}"
