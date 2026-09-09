"""Runs extension/background.js in a Node vm against a mock chrome.* + mock
backend, and checks the real enforcement flows (nav -> interstitial, download
cancel, content filter, health, offline fallback). Skips if node is absent.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "extension" / "harness.mjs"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_extension_background_enforcement_flows():
    proc = subprocess.run(
        ["node", str(HARNESS)],
        capture_output=True, text=True, timeout=120, cwd=str(ROOT),
    )
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
    assert proc.returncode == 0, "extension behavioural harness failed:\n" + proc.stdout + proc.stderr
    assert "ALL PASS" in proc.stdout
    for expected in (
        "phishing navigation redirects the tab to blocked.html",
        "malicious download is cancelled",
        "content-filter block redirects to interstitial",
        "protection OFF -> no scan",
    ):
        assert expected in proc.stdout
