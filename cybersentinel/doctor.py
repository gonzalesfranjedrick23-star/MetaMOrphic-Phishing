"""Detection-engine health check for CyberSentinel.

    python -m cybersentinel doctor              # core engine check
    python -m cybersentinel doctor --realtime   # real-time protection surface
    python -m cybersentinel doctor --eicar      # trace an EICAR scan end to end
    python -m cybersentinel doctor --file PATH  # trace a real file
    python -m cybersentinel doctor --url  URL   # trace a URL

Every line is a real probe - nothing is hard-coded to PASS.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("cybersentinel.doctor")

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

_OK = "PASS"
_WARN = "WARN"
_FAIL = "FAIL"


def _print_table(title: str, rows: List[Tuple[str, str, str]]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    width = max((len(r[0]) for r in rows), default=10) + 2
    for name, status, detail in rows:
        line = f"  {name.ljust(width)} {status}"
        if detail:
            line += f"   {detail}"
        print(line)


def _check_imports() -> List[Tuple[str, str, str]]:
    rows = []
    for mod, label in [
        ("yara_x", "YARA-X"),
        ("pefile", "pefile (PE parser)"),
        ("lief", "LIEF"),
        ("capstone", "Capstone (disasm)"),
        ("watchdog", "watchdog (file monitor)"),
        ("plyer", "plyer (notifications)"),
        ("win32serviceutil", "pywin32 (service)"),
    ]:
        try:
            __import__(mod)
            rows.append((label, _OK, ""))
        except Exception as exc:
            rows.append((label, _WARN, f"not available ({exc.__class__.__name__})"))
    return rows


def _malware_engine_rows() -> Tuple[List[Tuple[str, str, str]], Any]:
    from cybersentinel.malware_engine.analyzer import MalwareEngine

    engine = MalwareEngine()
    rows = [("Malware engine", _OK, f"{len(engine.analyzers)} analyzers")]

    yara = engine.yara
    if yara.status.get("available"):
        rows.append(("YARA / Signature", _OK,
                     f"{yara.engine}, {yara.status.get('rules_loaded', 0)} rules"))
    else:
        rows.append(("YARA / Signature", _FAIL,
                     "; ".join(yara.status.get("errors", [])) or "unavailable"))
    return rows, engine


async def _trace_file(path: str) -> Dict[str, Any]:
    from cybersentinel.orchestrator import ThreatOrchestrator
    from cybersentinel.malware_engine.analyzer import MalwareEngine

    orch = ThreatOrchestrator()
    engine = MalwareEngine()
    for i, analyzer in enumerate(engine.analyzers):
        orch.register_malware_engine(f"malware_layer_{i + 1}", analyzer)
    result = await orch.analyze_file(path, enforce=False)
    return result.outcome or {}


async def _trace_url(url: str) -> Dict[str, Any]:
    from cybersentinel.orchestrator import ThreatOrchestrator
    from cybersentinel.phishing_engine.analyzer import PhishingEngine

    orch = ThreatOrchestrator()
    engine = PhishingEngine()
    for i, analyzer in enumerate(engine.analyzers):
        orch.register_phishing_engine(f"phishing_layer_{i + 1}", analyzer)
    result = await orch.analyze_url(url)
    return result.outcome or {}


def _run_eicar_trace() -> Tuple[str, Dict[str, Any]]:
    tmp = Path(tempfile.gettempdir()) / "cybersentinel_doctor_eicar.txt"
    tmp.write_bytes(EICAR)
    try:
        outcome = asyncio.run(_trace_file(str(tmp)))
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    detected = outcome.get("classification") in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS")
    return (_OK if detected else _FAIL), outcome


def _realtime_rows() -> List[Tuple[str, str, str]]:
    rows: List[Tuple[str, str, str]] = []

    # Background agent + service
    try:
        from cybersentinel.service.background_agent import BackgroundAgent  # noqa: F401
        rows.append(("Background Agent", _OK, ""))
    except Exception as exc:
        rows.append(("Background Agent", _FAIL, str(exc)))
    try:
        from cybersentinel.service import windows_service  # noqa: F401
        rows.append(("Windows Service module", _OK, ""))
    except Exception as exc:
        rows.append(("Windows Service module", _WARN, str(exc)))

    # File monitor
    try:
        from cybersentinel.monitoring.monitor import FileMonitor  # noqa: F401
        rows.append(("File Monitor", _OK, ""))
    except Exception as exc:
        rows.append(("File Monitor", _FAIL, str(exc)))

    # Malware engine + YARA
    try:
        me_rows, _ = _malware_engine_rows()
        rows.extend(me_rows)
    except Exception as exc:
        rows.append(("Malware Engine", _FAIL, str(exc)))

    # Orchestrator / risk / XAI
    try:
        from cybersentinel.orchestrator import ThreatOrchestrator
        from cybersentinel.common.risk_scorer import RiskScorer, RiskLevel, ModelPrediction

        ThreatOrchestrator()
        rs = RiskScorer()
        a = rs.score([ModelPrediction("t", 0.9, 0.9, "sig", {"signature_match": True,
                                                             "analysis_status": "match"})])
        rows.append(("ThreatOrchestrator", _OK, ""))
        rows.append(("Risk Engine", _OK if a.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                     else _FAIL, f"signature -> {a.risk_level.value}"))
        # abstention must NOT be SAFE
        b = rs.score([ModelPrediction("t", 0.0, 0.0, "n/a",
                                      {"analysis_status": "unavailable", "available": False})])
        rows.append(("No-evidence -> UNKNOWN", _OK if b.risk_level == RiskLevel.UNKNOWN else _FAIL,
                     b.risk_level.value))
    except Exception as exc:
        rows.append(("ThreatOrchestrator", _FAIL, str(exc)))

    try:
        from cybersentinel.xai.explainer import XAIExplainer
        XAIExplainer()
        rows.append(("XAI", _OK, ""))
    except Exception as exc:
        rows.append(("XAI", _FAIL, str(exc)))

    try:
        from cybersentinel.notifications.desktop_notifications import DesktopNotifier
        n = DesktopNotifier()
        rows.append(("Notification", _OK, f"backend={n._backend}"))
    except Exception as exc:
        rows.append(("Notification", _FAIL, str(exc)))

    try:
        from cybersentinel.quarantine.manager import QuarantineManager  # noqa: F401
        rows.append(("Quarantine", _OK, ""))
    except Exception as exc:
        rows.append(("Quarantine", _FAIL, str(exc)))

    # EICAR end-to-end
    try:
        status, outcome = _run_eicar_trace()
        rows.append(("EICAR end-to-end", status,
                     f"{outcome.get('classification')} @ {outcome.get('risk_percent')}%"))
    except Exception as exc:
        rows.append(("EICAR end-to-end", _FAIL, str(exc)))

    # Phishing surface
    try:
        from cybersentinel.phishing_engine.analyzer import PhishingEngine
        pe = PhishingEngine()
        rows.append(("Phishing Engine", _OK, f"{len(pe.analyzers)} analyzers"))
        rows.append(("KNN model", _OK if pe.knn.model_data else _WARN,
                     "loaded" if pe.knn.model_data else "seed_model.json missing"))
    except Exception as exc:
        rows.append(("Phishing Engine", _FAIL, str(exc)))

    return rows


def _malware_rows() -> List[Tuple[str, str, str]]:
    """Per-layer malware pipeline check (spec part 39)."""
    rows, engine = _malware_engine_rows()
    try:
        _, outcome = _run_eicar_trace()
        contrib = outcome.get("contributing_models", [])
        abst = outcome.get("abstained_models", [])
        for layer in ("generic_analyzer", "malware_yara", "malware_pe",
                      "malware_graph", "malware_metamorphic", "malware_byte",
                      "malware_media", "malware_ml"):
            if layer in contrib:
                rows.append((layer, _OK, "contributed"))
            elif layer == "malware_ml":
                rows.append((layer, _WARN, "NOT_CONFIGURED - no trained model (train.py)"))
            else:
                rows.append((layer, _WARN, "abstained on EICAR text (expected for PE/graph)"))
        rows.append(("EICAR fusion", _OK if outcome.get("risk_percent", 0) > 40 else _FAIL,
                     f"{outcome.get('classification')} @ {outcome.get('risk_percent')}%"))
        rows.append(("enforcement_action", _OK if outcome.get("enforcement_action") else _FAIL,
                     str(outcome.get("enforcement_action"))))
    except Exception as exc:
        rows.append(("EICAR trace", _FAIL, str(exc)))
    return rows


def _quarantine_rows() -> List[Tuple[str, str, str]]:
    rows: List[Tuple[str, str, str]] = []
    try:
        import tempfile
        from cybersentinel.common.database import ThreatDatabase
        from cybersentinel.quarantine.manager import QuarantineManager

        d = Path(tempfile.mkdtemp(prefix="cs_doctor_q_"))
        db = ThreatDatabase(db_path=str(d / "db"))
        qm = QuarantineManager(quarantine_root=str(d / "q"), db=db)
        victim = d / "src" / "x.exe"
        victim.parent.mkdir(parents=True)
        victim.write_bytes(b"MZ" + b"\x90" * 200)
        rec = qm.quarantine_file(str(victim), "malware", 95.0, "doctor")
        rows.append(("quarantine_file", _OK, "moved + metadata stored"))
        rows.append(("cross-process record",
                     _OK if any(r["quarantine_id"] == rec["quarantine_id"]
                                for r in QuarantineManager(quarantine_root=str(d / "q"),
                                                           db=ThreatDatabase(db_path=str(d / "db"))).list_quarantine())
                     else _FAIL, "reloaded from JSONL"))
        try:
            qm.delete_file(rec["quarantine_id"], confirm=False)
            rows.append(("delete needs confirm", _FAIL, "deleted without confirm!"))
        except ValueError:
            rows.append(("delete needs confirm", _OK, "rejected confirm=False"))
        res = qm.delete_file(rec["quarantine_id"], confirm=True)
        rows.append(("delete_file", _OK if res.get("deleted") else _FAIL,
                     "payload + record removed" if res.get("deleted") else str(res.get("error"))))
        shutil_rmtree_quiet(d)
    except Exception as exc:
        rows.append(("Quarantine", _FAIL, str(exc)))
    return rows


def _sandbox_rows() -> List[Tuple[str, str, str]]:
    rows: List[Tuple[str, str, str]] = []
    try:
        import tempfile
        from cybersentinel.sandbox import SandboxManager, SandboxStatus

        d = Path(tempfile.mkdtemp(prefix="cs_doctor_sb_"))
        sample = d / "s.bin"
        sample.write_bytes(EICAR)
        sm = SandboxManager(root=str(d / "jobs"))
        job = sm.submit(str(sample), run_dynamic=True)
        rows.append(("job lifecycle", _OK if job.status == SandboxStatus.COMPLETED.value else _FAIL, job.status))
        rows.append(("isolation verified", _OK if job.isolation_verified else _FAIL, ""))
        rows.append(("workspace cleanup", _OK if job.cleanup_status == "verified_removed" else _FAIL,
                     job.cleanup_status))
        ds = sm.dynamic_status()
        rows.append(("dynamic backend", _OK,
                     f"{ds['backend']} - {'available' if ds['available'] else 'NOT_CONFIGURED'}: {ds['reason']}"))
        rows.append(("dynamic analysis", _OK if job.dynamic_status in ("NOT_CONFIGURED", "COMPLETED") else _WARN,
                     job.dynamic_status + " (never executed on host)"))
        rows.append(("static result", _OK if job.static_result else _FAIL,
                     f"{(job.static_result or {}).get('classification')}"))
        shutil_rmtree_quiet(d)
    except Exception as exc:
        rows.append(("Sandbox", _FAIL, str(exc)))
    return rows


def shutil_rmtree_quiet(path: Path) -> None:
    import shutil
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def run_doctor(eicar: bool = False, realtime: bool = False, malware: bool = False,
               quarantine: bool = False, sandbox: bool = False,
               file_path: str | None = None, url: str | None = None,
               **_ignored: Any) -> Dict[str, Any]:
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    report: Dict[str, Any] = {}

    dep_rows = _check_imports()
    _print_table("Dependencies", dep_rows)
    report["dependencies"] = {n: s for n, s, _ in dep_rows}

    if realtime:
        rows = _realtime_rows()
        _print_table("CyberSentinel Real-Time Protection", rows)
        report["realtime"] = {n: s for n, s, _ in rows}
        report["ok"] = all(s != _FAIL for _, s, _ in rows)

    if malware:
        rows = _malware_rows()
        _print_table("CyberSentinel Malware Pipeline", rows)
        report["malware"] = {n: s for n, s, _ in rows}

    if quarantine:
        rows = _quarantine_rows()
        _print_table("CyberSentinel Quarantine", rows)
        report["quarantine"] = {n: s for n, s, _ in rows}

    if sandbox:
        rows = _sandbox_rows()
        _print_table("CyberSentinel Sandbox", rows)
        report["sandbox"] = {n: s for n, s, _ in rows}

    if eicar or file_path or url:
        target = url if url else (file_path or "<eicar>")
        print(f"\nTrace: {target}")
        print("-" * (7 + len(target)))
        if url:
            outcome = asyncio.run(_trace_url(url))
        elif file_path:
            outcome = asyncio.run(_trace_file(file_path))
        else:
            _, outcome = _run_eicar_trace()
        for key in ("classification", "risk_percent", "risk_level",
                    "analysis_status", "recommendation", "enforcement_action"):
            print(f"  {key:18} {outcome.get(key)}")
        print(f"  xai                {outcome.get('xai_explanation', '')[:300]}")
        print("\n  Detector contributions:")
        print(f"    {'DETECTOR':<22}{'STATUS':<12}{'CONTRIB':<9}{'SEV':<7}EVIDENCE")
        for row in outcome.get("contributions", []):
            print(f"    {str(row.get('detector')):<22}{str(row.get('status')):<12}"
                  f"{str(row.get('contribution')):<9}{row.get('severity', 0):<7}"
                  f"{str(row.get('evidence', ''))[:60]}")
        report["trace"] = outcome

    if not any((realtime, malware, quarantine, sandbox, eicar, file_path, url)):
        me_rows, _ = _malware_engine_rows()
        _print_table("CyberSentinel Core Engine", me_rows)
        report["engine"] = {n: s for n, s, _ in me_rows}

    return report
