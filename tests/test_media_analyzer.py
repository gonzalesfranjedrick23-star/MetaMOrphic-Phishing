"""MediaAnalyzer wired into the central MalwareEngine."""

import asyncio
from pathlib import Path

from cybersentinel.malware_engine.analyzer import MalwareEngine, MediaAnalyzer


def test_media_analyzer_is_registered():
    names = [a.__class__.__name__ for a in MalwareEngine().analyzers]
    assert "MediaAnalyzer" in names


def test_pe_input_is_not_applicable():
    import tempfile
    d = Path(tempfile.mkdtemp())
    p = d / "a.exe"
    p.write_bytes(b"MZ" + b"\x00" * 300)
    r = asyncio.run(MediaAnalyzer().analyze(str(p)))
    assert r.evidence["analysis_status"] == "not_applicable"
    assert r.evidence["available"] is False


def test_image_with_embedded_executable_is_flagged(tmp_path):
    p = tmp_path / "holiday.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200 + b"MZ\x90\x00" + b"\x00" * 600)
    r = asyncio.run(MediaAnalyzer().analyze(str(p)))
    assert r.model_name == "malware_media"
    assert r.malicious_probability >= 0.4
    assert any("embedded" in i.lower() for i in r.evidence["indicators"])


def test_clean_pdf_is_contributing_zero(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(b"%PDF-1.4\n" + b"just text content here\n" * 50 + b"%%EOF")
    r = asyncio.run(MediaAnalyzer().analyze(str(p)))
    assert r.malicious_probability == 0.0
    assert r.evidence["analysis_status"] == "analyzed"  # ran, found nothing -> counts as clean vote


def test_eicar_in_pdf_end_to_end_still_malicious(tmp_path):
    """MediaAnalyzer must not dilute a YARA signature hit."""
    import cybersentinel.orchestrator as orch_mod
    orch = orch_mod.ThreatOrchestrator()
    for i, a in enumerate(MalwareEngine().analyzers):
        orch.register_malware_engine(f"m{i}", a)
    p = tmp_path / "invoice.pdf"
    p.write_bytes(rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    res = asyncio.run(orch.analyze_file(str(p)))
    assert res.outcome["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
