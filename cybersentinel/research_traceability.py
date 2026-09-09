"""Research-to-code traceability map (spec part 38).

Maps each research requirement -> file / function / execution path / test /
status. `python -m cybersentinel.research_traceability` verifies every
referenced symbol and test actually exists, then writes research_traceability.json.

Status values:
  IMPLEMENTED  - present, exercised, has a test
  PARTIAL      - present but limited (e.g. heuristic-only, offset-based)
  MISSING      - not implemented
  NOT_CONFIGURED - deliberately stubbed (needs external infra), reported honestly
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]

# feature, module, symbol, execution_path, test_file, status
MAP: List[tuple] = [
    ("SHA-256 fingerprinting",
     "cybersentinel.common.database", "compute_file_hash",
     "GenericAnalyzer.analyze -> evidence['sha256']; agent _sha256 cache",
     "tests/test_phase3_quarantine.py", "IMPLEMENTED"),
    ("File-format / MIME / magic identification",
     "cybersentinel.malware_engine.analyzer", "GenericAnalyzer._magic_bytes",
     "MalwareEngine -> GenericAnalyzer.analyze",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("PE identification",
     "cybersentinel.malware_engine.pe_disassembler", "PEDisassembler._looks_like_pe",
     "GraphAnalyzer.analyze / PEAnalyzer.analyze",
     "tests/test_pe_disassembly.py", "IMPLEMENTED"),
    ("YARA / signature scanning",
     "cybersentinel.malware_engine.analyzer", "YARAAnalyzer.analyze",
     "MalwareEngine -> YARAAnalyzer (yara-x engine, built-in fallback)",
     "tests/test_yara_analyzer.py", "IMPLEMENTED"),
    ("PE structure / header / section analysis",
     "cybersentinel.malware_engine.analyzer", "PEAnalyzer.analyze",
     "MalwareEngine -> PEAnalyzer (pefile: sections, entropy, RWX, imports)",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("Entropy / statistical analysis",
     "cybersentinel.malware_engine.analyzer", "GenericAnalyzer._compute_entropy",
     "GenericAnalyzer + PEAnalyzer (per-section) + MetamorphicMalwareDetector",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("String extraction",
     "cybersentinel.malware_engine.analyzer", "GenericAnalyzer._extract_strings",
     "GenericAnalyzer.analyze; MetamorphicMalwareDetector._extract_readable_strings",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("Suspicious API pattern analysis",
     "cybersentinel.malware_engine.metamorphic_detector", "MetamorphicMalwareDetector._check_api_patterns",
     "MetamorphicMalwareDetector.analyze_binary; PEAnalyzer suspicious imports",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("Obfuscation / packing analysis",
     "cybersentinel.malware_engine.metamorphic_detector", "MetamorphicMalwareDetector._check_obfuscation",
     "MetamorphicMalwareDetector.analyze_binary; PEAnalyzer packer sections",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("Polymorphic indicators",
     "cybersentinel.malware_engine.metamorphic_detector", "MetamorphicMalwareDetector._check_polymorphic_markers",
     "MetamorphicMalwareDetector.analyze_binary",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("Normalized fingerprint",
     "cybersentinel.malware_engine.metamorphic_detector", "MetamorphicMalwareDetector._layer_report",
     "evidence.layers[*].normalized_sha256 (whitespace-normalised digest)",
     "tests/test_phase4_integration.py", "PARTIAL"),
    ("Opcode analysis",
     "cybersentinel.malware_engine.pe_disassembler", "PEDisassembler.disassemble_bytes",
     "GraphAnalyzer.analyze -> capstone (fallback: byte-stride)",
     "tests/test_pe_disassembly.py", "PARTIAL"),
    ("Graph / disassembly analysis",
     "cybersentinel.malware_engine.analyzer", "GraphAnalyzer.analyze",
     "MalwareEngine -> GraphAnalyzer (no GNN model; instruction-flow approximation)",
     "tests/test_pe_disassembly.py", "PARTIAL"),
    ("Metamorphic correlation",
     "cybersentinel.malware_engine.metamorphic_detector", "MetamorphicMalwareDetector.analyze",
     "MalwareEngine -> MetamorphicMalwareDetector -> ModelPrediction(malware_metamorphic)",
     "tests/test_phase4_integration.py", "IMPLEMENTED"),
    ("Heuristic scoring",
     "cybersentinel.malware_engine.pe_disassembler", "PEDisassembler._score_risk",
     "GraphAnalyzer + MetamorphicMalwareDetector.analyze_binary",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("Machine learning (malware)",
     "cybersentinel.malware_engine.ml.classifier", "MLAnalyzer.analyze",
     "MalwareEngine -> MLAnalyzer (feature extract -> calibrated model). Pipeline "
     "implemented (train.py: CV model compare -> threshold search -> calibration -> "
     "metrics); NO trained model ships - no labelled malware corpus in repo - "
     "so the analyzer ABSTAINS until train.py is run on real data.",
     "tests/test_malware_ml.py", "PARTIAL"),
    ("ML training + calibration + metrics",
     "cybersentinel.malware_engine.ml.train", "train_pipeline",
     "python -m cybersentinel.malware_engine.ml.train --benign-dir --threat-dir",
     "tests/test_malware_ml.py", "IMPLEMENTED"),
    ("ThreatOrchestrator",
     "cybersentinel.orchestrator", "ThreatOrchestrator.analyze_file",
     "web/api.py + agent_runtime -> orchestrator.analyze_file/analyze_url",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("Ensemble / evidence fusion",
     "cybersentinel.common.risk_scorer", "RiskScorer.score",
     "orchestrator -> RiskScorer.score (weighted noisy-OR, bounded 0-1)",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("Risk scoring (0-100, bounded)",
     "cybersentinel.common.risk_scorer", "RiskScorer.normalize_score",
     "RiskScorer.score -> validate_score",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("XAI explanation",
     "cybersentinel.xai.explainer", "XAIExplainer.explain_prediction",
     "orchestrator._build_outcome -> outcome['xai_explanation']",
     "tests/test_xai_explainer.py", "IMPLEMENTED"),
    ("Enforcement policy",
     "cybersentinel.common.result", "enforcement_for",
     "orchestrator._build_outcome -> outcome['enforcement_action']",
     "tests/test_phase3_enforcement.py", "IMPLEMENTED"),
    ("Quarantine lifecycle",
     "cybersentinel.quarantine.manager", "QuarantineManager.delete_file",
     "orchestrator._handle_file_threat -> quarantine_file; API delete/restore",
     "tests/test_phase3_quarantine.py", "IMPLEMENTED"),
    ("Sandbox lifecycle",
     "cybersentinel.sandbox.manager", "SandboxManager.submit",
     "on-demand isolated static analysis; dynamic = NOT_CONFIGURED",
     "tests/test_sandbox.py", "NOT_CONFIGURED"),
    ("Real-time file monitoring",
     "cybersentinel.monitoring.monitor", "FileMonitor",
     "agent_runtime -> FileMonitor (watchdog) -> event bus -> analysis queue",
     "tests/test_realtime_agent.py", "IMPLEMENTED"),
    ("Background service (OS)",
     "cybersentinel.service.windows_service", "install_service",
     "cybersentinel agent install/run/start/stop (Windows Service via pywin32)",
     "tests/test_realtime_agent.py", "IMPLEMENTED"),
    ("Desktop notifications",
     "cybersentinel.notifications.desktop_notifications", "DesktopNotifier.emit",
     "orchestrator._handle_file_threat -> notifier.emit (plyer / PowerShell)",
     "tests/test_realtime_agent.py", "IMPLEMENTED"),
    ("Structured scan logging",
     "cybersentinel.service.scan_log", "ScanLog.record_file_scan",
     "agent_runtime._record_scan -> logs/agent_scans.jsonl",
     "tests/test_phase2_logging.py", "IMPLEMENTED"),
    ("SHA-256 scan cache",
     "cybersentinel.service.agent_runtime", "AgentRuntime._cache_get",
     "agent _analysis_worker: repeated benign bytes skip full re-scan",
     "tests/test_phase2_logging.py", "IMPLEMENTED"),
    ("Performance metrics / ROC-AUC / latency",
     "cybersentinel.evaluation.metrics", "evaluate_binary",
     "cybersentinel.evaluation: roc_auc / sweep_thresholds / latency_stats",
     "tests/test_evaluation_metrics.py", "IMPLEMENTED"),
    ("Phishing URL analysis",
     "cybersentinel.phishing_engine.analyzer", "URLFeatureAnalyzer.analyze",
     "PhishingEngine.analyze_all -> orchestrator.analyze_url",
     "tests/test_phase1_fusion.py", "IMPLEMENTED"),
    ("Domain / lookalike / typosquatting",
     "cybersentinel.phishing_engine.analyzer", "DomainLookalikeAnalyzer.analyze",
     "PhishingEngine.analyze_all; extension/lookalike.js",
     "tests/test_phase1_fusion.py", "PARTIAL"),
    ("KNN classifier",
     "cybersentinel.phishing_engine.analyzer", "KNNPhishingAnalyzer.analyze",
     "PhishingEngine.analyze_all; extension/knn.js (in-browser)",
     "tests/test_phase1_fusion.py", "PARTIAL"),
    ("Browser extension",
     "", "extension/background.js",
     "manifest.json (MV3) -> background.js -> POST /api/v1/url/scan",
     "tests/test_phase4_integration.py", "PARTIAL"),
]


def _check_symbol(module: str, symbol: str) -> bool:
    if not module:
        return (ROOT / symbol).exists()
    try:
        mod = importlib.import_module(module)
    except Exception:
        return False
    obj: Any = mod
    for part in symbol.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return False
    return True


def build() -> Dict[str, Any]:
    entries = []
    for feature, module, symbol, path, test, status in MAP:
        sym_ok = _check_symbol(module, symbol)
        test_ok = (not test) or (ROOT / test).exists()
        verified = sym_ok and test_ok and status != "MISSING"
        entries.append({
            "research_feature": feature,
            "file": module.replace(".", "/") + ".py" if module else symbol,
            "function": symbol if module else "",
            "execution_path": path,
            "test": test,
            "status": status,
            "symbol_present": sym_ok,
            "test_present": test_ok,
            "verified": verified,
        })
    summary = {
        "total": len(entries),
        "implemented": sum(e["status"] == "IMPLEMENTED" for e in entries),
        "partial": sum(e["status"] == "PARTIAL" for e in entries),
        "not_configured": sum(e["status"] == "NOT_CONFIGURED" for e in entries),
        "missing": sum(e["status"] == "MISSING" for e in entries),
        "verified": sum(e["verified"] for e in entries),
    }
    return {"summary": summary, "entries": entries}


def main() -> int:
    report = build()
    out = ROOT / "research_traceability.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    s = report["summary"]
    print(f"research_traceability.json written: {s['verified']}/{s['total']} verified "
          f"({s['implemented']} implemented, {s['partial']} partial, "
          f"{s['not_configured']} not_configured, {s['missing']} missing)")
    bad = [e for e in report["entries"]
           if not e["symbol_present"] or (e["test"] and not e["test_present"])]
    for e in bad:
        print(f"  ! {e['research_feature']}: symbol={e['symbol_present']} test={e['test_present']}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
