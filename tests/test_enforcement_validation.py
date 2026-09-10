"""Runs scripts/validate_enforcement.py (real agent + real API + Node harness)
and asserts no category came back FAIL."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.slow
def test_full_enforcement_validation():
    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_enforcement.py")],
        capture_output=True, text=True, timeout=240, cwd=str(ROOT),
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
    )
    print(p.stdout[-4000:])
    if p.returncode != 0:
        print("STDERR:", p.stderr[-2000:])
    assert "STATUS" in p.stdout
    fails = [line for line in p.stdout.splitlines() if " FAIL " in line]
    assert not fails, "enforcement validation had FAIL rows:\n" + "\n".join(fails)
    # the safety-critical ones must be PASS (not just PARTIAL)
    for critical in ("REAL-TIME MALWARE", "QUARANTINE ", "QUARANTINE DELETE",
                     "PHISHING AUTO-DETECTION", "PHISHING BLOCKING", "CONTENT FILTER"):
        line = next((l for l in p.stdout.splitlines() if l.strip().startswith(critical.strip())), "")
        assert " PASS " in line, f"{critical!r} not PASS: {line}"
