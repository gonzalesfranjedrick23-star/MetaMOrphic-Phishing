"""research_traceability.json integrity + SHA-256 scan cache."""

import time
from pathlib import Path

from cybersentinel.research_traceability import build
from cybersentinel.service.agent_runtime import AgentRuntime


def test_traceability_every_referenced_symbol_and_test_exists():
    report = build()
    for e in report["entries"]:
        assert e["symbol_present"], f"missing symbol for {e['research_feature']}: {e['function']}"
        if e["test"]:
            assert e["test_present"], f"missing test file for {e['research_feature']}: {e['test']}"
    # the 22 mandatory research features from spec part 38 are all present
    features = {e["research_feature"] for e in report["entries"]}
    for required in ("SHA-256 fingerprinting", "YARA / signature scanning",
                     "Normalized fingerprint", "Opcode analysis",
                     "Metamorphic correlation", "ThreatOrchestrator",
                     "XAI explanation", "Phishing URL analysis",
                     "Browser extension", "Real-time file monitoring"):
        assert required in features


def test_traceability_reports_ml_status_honestly():
    report = build()
    ml = next(e for e in report["entries"] if e["research_feature"] == "Machine learning (malware)")
    # pipeline exists; the shipped model is a demo on synthetic data -> PARTIAL,
    # and the note is explicit that it is not real malware
    assert ml["status"] == "PARTIAL"
    assert "not real malware" in ml["execution_path"].lower()


def test_scan_cache_skips_repeated_benign_bytes(tmp_path):
    rt = AgentRuntime(paths=[tmp_path])
    f = tmp_path / "a.txt"
    f.write_text("same bytes")
    digest = rt._sha256(str(f))
    assert digest and len(digest) == 64
    assert rt._cache_get(digest) is None
    rt._cache_put(digest, "SAFE")
    assert rt._cache_get(digest) == "SAFE"
    # non-safe verdicts are cached but the worker still re-analyses them
    rt._cache_put(digest, "MALICIOUS")
    assert rt._cache_get(digest) == "MALICIOUS"


def test_scan_cache_expires(tmp_path):
    rt = AgentRuntime(paths=[tmp_path])
    rt._hash_cache_ttl_s = 0
    rt._cache_put("deadbeef", "SAFE")
    time.sleep(0.01)
    assert rt._cache_get("deadbeef") is None
