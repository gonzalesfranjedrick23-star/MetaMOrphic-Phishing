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


def run_doctor(eicar: bool = False, realtime: bool = False,
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
                    "analysis_status", "recommendation"):
            print(f"  {key:16} {outcome.get(key)}")
        print(f"  contributing     {outcome.get('contributing_models')}")
        print(f"  abstained        {outcome.get('abstained_models')}")
        print(f"  xai              {outcome.get('xai_explanation', '')[:300]}")
        report["trace"] = outcome

    if not realtime and not (eicar or file_path or url):
        me_rows, _ = _malware_engine_rows()
        _print_table("CyberSentinel Core Engine", me_rows)
        report["engine"] = {n: s for n, s, _ in me_rows}

    return report
