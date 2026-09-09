"""Phase 2 - structured scan log (Part 23) + Flask-independent status (Part 22)."""

import asyncio
import tempfile
import time
from pathlib import Path

from cybersentinel.common.event_bus import EventType
from cybersentinel.service.agent_runtime import AgentRuntime
from cybersentinel.service.scan_log import ScanLog, StatusFile

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_scan_log_records_required_fields(tmp_path):
    log = ScanLog(tmp_path)
    outcome = {
        "sha256": "abc", "classification": "MALICIOUS", "risk_percent": 88.0,
        "risk_level": "critical", "analysis_status": "complete",
        "contributing_models": ["malware_yara"], "abstained_models": ["malware_pe"],
        "evidence": [{"detector": "malware_yara", "data": {"magic": "PE/COFF"}}],
    }
    entry = log.record_file_scan("C:/x/y.exe", outcome, 12.3, action="quarantine")
    for key in ("ts", "file", "sha256", "format", "classification", "risk_percent",
                "analysis_status", "evidence_count", "duration_ms", "action"):
        assert key in entry
    assert entry["format"] == "PE/COFF"
    assert log.tail(10)[-1]["classification"] == "MALICIOUS"


def test_scan_log_never_stores_file_contents(tmp_path):
    log = ScanLog(tmp_path)
    log.record_file_scan("C:/x/secret.txt",
                         {"sha256": "h", "evidence": [{"data": {"strings": ["p4ssw0rd"]}}]},
                         1.0)
    raw = (tmp_path / "agent_scans.jsonl").read_text()
    assert "p4ssw0rd" not in raw  # only counts/metadata are logged


def test_status_file_roundtrip(tmp_path):
    sf = StatusFile(tmp_path)
    sf.note_scan({"classification": "MALICIOUS", "action": "quarantine"})
    sf.note_scan({"classification": "SAFE", "action": "none"})
    sf.write({"running": True, "watcher": "watchdog", "paths": ["C:/Downloads"]})
    snap = StatusFile.read(tmp_path)
    assert snap["malware_protection"] == "ACTIVE"
    assert snap["files_analyzed"] == 2
    assert snap["threats_detected"] == 1
    assert snap["quarantined"] == 1


def test_agent_writes_scan_log_and_status_end_to_end(tmp_path, monkeypatch):
    watch = tmp_path / "watch"
    watch.mkdir()
    runtime = AgentRuntime(paths=[watch], stability_checks=2, poll_interval=0.1)
    # keep logs inside the temp dir
    runtime.log_dir = tmp_path / "logs"
    runtime.scan_log = ScanLog(runtime.log_dir)
    runtime.status_file = StatusFile(runtime.log_dir)

    done = []
    runtime.event_bus.subscribe(EventType.ANALYSIS_COMPLETED, lambda e: done.append(e))
    runtime.start()
    try:
        (watch / "report.txt").write_text("quarterly numbers\n" * 20)
        (watch / "x.dat").write_bytes(EICAR)
        deadline = time.time() + 20
        while time.time() < deadline and len(done) < 2:
            time.sleep(0.2)
    finally:
        runtime.stop()

    scans = runtime.scan_log.tail(10)
    assert len(scans) >= 2
    assert any(s["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS") for s in scans)
    snap = StatusFile.read(runtime.log_dir)
    assert snap is not None
    assert snap["files_analyzed"] >= 2
