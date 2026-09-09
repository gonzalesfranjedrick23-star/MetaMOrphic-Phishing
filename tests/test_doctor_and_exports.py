from cybersentinel import GenericAnalyzer, FileAnalyzerRegistry
from cybersentinel.doctor import run_doctor


def test_public_export_surface():
    assert GenericAnalyzer.__name__ == "GenericAnalyzer"
    assert FileAnalyzerRegistry.__name__ == "FileAnalyzerRegistry"


def test_doctor_realtime_report_shape():
    report = run_doctor(realtime=True)
    assert "dependencies" in report
    assert "realtime" in report
    # YARA-X must be available and the signature engine must be usable
    assert report["realtime"].get("YARA / Signature") == "PASS"
    # a no-evidence assessment must never come back as SAFE
    assert report["realtime"].get("No-evidence -> UNKNOWN") == "PASS"


def test_doctor_eicar_trace_detects():
    report = run_doctor(eicar=True)
    trace = report["trace"]
    assert trace["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
    assert trace["risk_percent"] > 40
