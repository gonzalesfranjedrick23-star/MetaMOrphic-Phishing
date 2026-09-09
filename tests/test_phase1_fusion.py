"""Phase 1 - shared result schema + evidence-aware fusion.

Guards the class of bug the audit found: a failed / unavailable / not-applicable
analysis being rendered as SAFE, and a single strong detector being out-voted by
a median of mostly-zero scores.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from cybersentinel.common.risk_scorer import RiskScorer, RiskLevel, ModelPrediction
from cybersentinel.common.result import is_abstention, classification_for
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.malware_engine.analyzer import MalwareEngine
from cybersentinel.phishing_engine.analyzer import PhishingEngine

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _orch():
    orch = ThreatOrchestrator()
    for i, a in enumerate(MalwareEngine().analyzers):
        orch.register_malware_engine(f"malware_layer_{i + 1}", a)
    for i, a in enumerate(PhishingEngine().analyzers):
        orch.register_phishing_engine(f"phishing_layer_{i + 1}", a)
    return orch


# --- risk engine ---------------------------------------------------------

def test_single_signature_detector_is_not_outvoted():
    rs = RiskScorer()
    preds = [
        ModelPrediction("malware_yara", 0.9, 0.95, "sig",
                        {"signature_match": True, "analysis_status": "match"}),
        ModelPrediction("generic_analyzer", 0.0, 0.4, "clean", {"analysis_status": "complete"}),
        ModelPrediction("malware_byte", 0.05, 0.5, "clean", {"analysis_status": "complete"}),
        ModelPrediction("malware_metamorphic", 0.1, 0.4, "clean", {"analysis_status": "complete"}),
    ]
    a = rs.score(preds)
    assert a.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert 0 <= a.risk_score <= 100


def test_all_abstained_is_unknown_never_safe():
    rs = RiskScorer()
    preds = [
        ModelPrediction("malware_yara", 0.0, 0.0, "unavailable",
                        {"analysis_status": "unavailable", "available": False}),
        ModelPrediction("malware_pe", 0.0, 0.0, "n/a",
                        {"analysis_status": "not_applicable", "available": False}),
        ModelPrediction("malware_graph", 0.0, 0.0, "failed",
                        {"analysis_status": "analysis_failed", "available": False}),
    ]
    a = rs.score(preds)
    assert a.risk_level == RiskLevel.UNKNOWN
    assert a.risk_level != RiskLevel.SAFE
    assert a.recommendation == "review_by_user"
    assert a.analysis_status in ("incomplete", "failed")


def test_not_applicable_only_still_completes():
    rs = RiskScorer()
    preds = [
        ModelPrediction("malware_yara", 0.0, 0.7, "no match", {"analysis_status": "no_match"}),
        ModelPrediction("malware_pe", 0.0, 0.0, "n/a",
                        {"analysis_status": "not_applicable", "available": False}),
    ]
    a = rs.score(preds)
    assert a.analysis_status == "complete"
    assert a.risk_level == RiskLevel.SAFE


def test_scores_always_bounded():
    rs = RiskScorer()
    for p in (-5.0, 0.0, 0.3, 1.0, 5.0, 999.0):
        preds = [ModelPrediction("x", min(max(p, 0.0), 1.0), 0.8, "r", {"analysis_status": "complete"})]
        a = rs.score(preds)
        assert 0.0 <= a.risk_score <= 100.0


def test_is_abstention_rules():
    assert is_abstention({"analysis_status": "unavailable"})
    assert is_abstention({"available": False})
    assert is_abstention({}, confidence=0.0, probability=0.0)
    assert not is_abstention({"analysis_status": "no_match"}, confidence=0.7)
    assert not is_abstention({"analysis_status": "match"})


def test_classification_mapping():
    assert classification_for("critical", "url") == "PHISHING"
    assert classification_for("high", "file") == "HIGH RISK"
    assert classification_for("critical", "file") == "MALICIOUS"
    assert classification_for("unknown", "file") == "UNKNOWN"
    assert classification_for("low", "file") == "SAFE"


# --- end to end via orchestrator ---------------------------------------

def test_eicar_file_is_flagged_not_safe():
    orch = _orch()
    with tempfile.TemporaryDirectory() as d:
        p = Path(d, "eicar.txt")
        p.write_bytes(EICAR)
        res = asyncio.run(orch.analyze_file(str(p)))
    o = res.outcome
    assert o["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
    assert o["risk_percent"] > 40
    assert "malware_yara" in o["contributing_models"]
    assert set(o) >= {
        "classification", "risk_score", "risk_percent", "risk_level",
        "analysis_status", "evidence", "xai_explanation", "recommendation",
    }


def test_eicar_disguised_as_png_still_flagged():
    orch = _orch()
    with tempfile.TemporaryDirectory() as d:
        p = Path(d, "holiday.png")
        p.write_bytes(EICAR)
        res = asyncio.run(orch.analyze_file(str(p)))
    assert res.outcome["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")


def test_benign_text_is_safe_and_complete():
    orch = _orch()
    with tempfile.TemporaryDirectory() as d:
        p = Path(d, "notes.txt")
        p.write_text("shopping list: milk, bread, eggs\n" * 40)
        res = asyncio.run(orch.analyze_file(str(p)))
    o = res.outcome
    assert o["classification"] == "SAFE"
    assert o["analysis_status"] == "complete"
    assert 0 <= o["risk_percent"] <= 20


def test_missing_file_is_unknown_not_safe():
    orch = _orch()
    res = asyncio.run(orch.analyze_file(r"C:\definitely\not\here\nope.bin"))
    assert res.outcome["classification"] == "UNKNOWN"
    assert res.outcome["risk_level"] != "safe"


def test_shared_schema_for_url():
    orch = _orch()
    res = asyncio.run(orch.analyze_url("http://paypa1-verify-account.tk/login/confirm"))
    o = res.outcome
    assert o["analysis_type"] == "url"
    assert o["classification"] in ("PHISHING", "SUSPICIOUS")
    assert o["xai_explanation"]


def test_uncertain_knn_vote_does_not_block_benign_example_domain():
    """A 2-of-3 KNN result is not a high-confidence phishing verdict by itself."""
    orch = _orch()
    res = asyncio.run(orch.analyze_url("https://example.com"))
    o = res.outcome

    assert o["classification"] == "SAFE"
    assert o["risk_percent"] < 40
