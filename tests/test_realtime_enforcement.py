"""Real-time file protection - full path, real AgentRuntime, real filesystem.

Proves: file event -> stabilize -> queue -> central malware engine ->
ThreatOrchestrator -> enforcement (quarantine) -> notification, and that a
benign file completes with no action. Also records per-stage latency (part 21)
and checks manual vs real-time consistency (part 16).
"""

import asyncio
import time
from pathlib import Path

import pytest

from cybersentinel.common.event_bus import EventType
from cybersentinel.service.agent_runtime import AgentRuntime
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.malware_engine.analyzer import MalwareEngine

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SYNTH_METAMORPHIC = b"MZ" + b"\x00" * 60 + b"UPX0\x00\x00\x00\x00" + (b"\x90" * 400) + \
    b"\x00".join([b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory"]) + \
    bytes(range(256)) * 40 + EICAR


@pytest.fixture
def agent(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    rt = AgentRuntime(paths=[watch], stability_checks=2, poll_interval=0.1)
    rt.log_dir = tmp_path / "logs"
    from cybersentinel.service.scan_log import ScanLog, StatusFile
    rt.scan_log = ScanLog(rt.log_dir)
    rt.status_file = StatusFile(rt.log_dir)
    events = []
    for et in (EventType.FILE_CREATED, EventType.ANALYSIS_STARTED,
               EventType.ANALYSIS_COMPLETED, EventType.THREAT_DETECTED,
               EventType.THREAT_QUARANTINED):
        rt.event_bus.subscribe(et, lambda e, et=et: events.append((et.value, time.monotonic(), e.data)))
    rt._events = events
    rt.start()
    yield rt, watch, events
    rt.stop()


def _wait_for(events, kind, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        hit = [e for e in events if e[0] == kind]
        if hit:
            return hit[-1]
        time.sleep(0.15)
    return None


def test_benign_file_completes_with_no_enforcement(agent):
    rt, watch, events = agent
    (watch / "report.txt").write_text("quarterly figures and notes\n" * 40)
    done = _wait_for(events, "analysis_completed")
    assert done is not None, "benign file was never analysed"
    assert done[2]["classification"] == "SAFE"
    assert not any(e[0] == "threat_detected" for e in events)
    assert not any(e[0] == "threat_quarantined" for e in events)
    scans = rt.scan_log.tail(5)
    assert scans and scans[-1]["classification"] == "SAFE"


def test_eicar_download_is_detected_quarantined_notified(agent):
    rt, watch, events = agent
    # simulate a browser download: temp name first, then rename to final
    tmp = watch / "installer.exe.crdownload"
    tmp.write_bytes(EICAR)
    time.sleep(0.4)
    final = watch / "installer.exe"
    tmp.rename(final)

    threat = _wait_for(events, "threat_detected")
    assert threat is not None, "EICAR download never raised THREAT_DETECTED"
    assert threat[2]["classification"] in ("MALICIOUS", "HIGH RISK")
    assert threat[2]["risk_score"] > 40
    assert threat[2]["explanation"]                       # XAI present (part 3/17)

    quar = _wait_for(events, "threat_quarantined")
    assert quar is not None, "malicious download was not quarantined"
    qpath = Path(quar[2]["quarantine"]["quarantine_path"])
    assert qpath.exists() and qpath.suffix == ".quarantine"   # not executable
    assert not final.exists()                                 # original isolated

    notes = rt.notifier.history if rt.notifier else []
    assert any(n.get("risk_level", "").upper() in ("HIGH", "CRITICAL") for n in notes), \
        "no desktop notification for the malicious download"

    # temp .crdownload must NOT have been scanned as a completed file
    scanned_paths = [s["file"] for s in rt.scan_log.tail(20)]
    assert not any(p.endswith(".crdownload") for p in scanned_paths)


def test_synthetic_metamorphic_artifact_full_pipeline(agent):
    rt, watch, events = agent
    (watch / "sample.bin").write_bytes(SYNTH_METAMORPHIC)
    done = _wait_for(events, "analysis_completed")
    assert done is not None
    assert done[2]["classification"] in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
    scan = rt.scan_log.tail(3)[-1]
    assert scan["evidence_count"] >= 1
    assert scan["analysis_status"] in ("complete", "incomplete")
    assert "malware_yara" in scan["contributing"] or "malware_metamorphic" in scan["contributing"]


def test_duplicate_events_are_deduplicated(agent):
    rt, watch, events = agent
    f = watch / "same.txt"
    f.write_text("content")
    for _ in range(6):                       # hammer with modifications
        f.write_text("content")
        time.sleep(0.05)
    time.sleep(3)
    completed = [e for e in events if e[0] == "analysis_completed"
                 and e[2].get("file_path", "").endswith("same.txt")]
    assert 1 <= len(completed) <= 3, f"same file scanned {len(completed)} times (expected <= 3)"


def test_manual_and_realtime_use_the_same_engine(agent, tmp_path):
    rt, watch, events = agent
    sample = watch / "x.dat"
    sample.write_bytes(EICAR)
    rt_done = _wait_for(events, "analysis_completed")
    assert rt_done is not None
    rt_cls = rt_done[2]["classification"]

    # manual path (no agent) on identical bytes
    manual_file = tmp_path / "x_manual.dat"
    manual_file.write_bytes(EICAR)
    orch = ThreatOrchestrator()
    for i, a in enumerate(MalwareEngine().analyzers):
        orch.register_malware_engine(f"m{i}", a)
    manual = asyncio.run(orch.analyze_file(str(manual_file)))
    assert manual.outcome["classification"] == rt_cls, \
        f"manual={manual.outcome['classification']} realtime={rt_cls}"


def test_latency_is_measured_from_real_timestamps(agent):
    rt, watch, events = agent
    t_create = time.monotonic()
    (watch / "timed.txt").write_text("hello " * 100)
    started = _wait_for(events, "analysis_started")
    completed = _wait_for(events, "analysis_completed")
    assert started and completed
    detect_ms = (started[1] - t_create) * 1000
    scan_ms = (completed[1] - started[1]) * 1000
    assert detect_ms > 0 and scan_ms > 0
    assert detect_ms < 15000 and scan_ms < 15000     # sane bounds, real numbers
    # the agent's own scan-log records a duration too
    assert rt.scan_log.tail(1)[-1]["duration_ms"] >= 0
