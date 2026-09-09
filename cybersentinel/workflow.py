"""Universal file-analysis workflow for CyberSentinel.

This workflow deliberately avoids any shortcut such as:
    if not is_pe: return SAFE

It routes files according to content/magic/MIME and runs the generic +
YARA/signature + specialized evidence path that the repository already has,
then feeds the resulting evidence into the shared RiskScorer and XAI story.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import mimetypes
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cybersentinel.common.risk_scorer import RiskScorer, RiskLevel
from cybersentinel.common.risk_scorer import ModelPrediction
from cybersentinel.malware_engine.analyzer import MalwareEngine, GenericAnalyzer, FileAnalyzerRegistry, YARAAnalyzer
from cybersentinel.xai.explainer import XAIExplainer

logger = logging.getLogger(__name__)


class UniversalAnalysisWorkflow:
    """Central workflow that ensures a file is analyzed by universal evidence pipeline.

    It intentionally preserves all evidence and never treats 'not applicable'
    or 'analysis unavailable' as a safe signal. The engine is content-aware and
    does not force file security decisions to a PE-only student path.
    """

    def __init__(self, malware_engine: Optional[MalwareEngine] = None):
        self.malware_engine = malware_engine or MalwareEngine()
        self.registry = FileAnalyzerRegistry()
        self.risk_scorer = RiskScorer()
        self.xai = XAIExplainer()

    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        file_path = str(file_path)
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return {
                "classification": "UNKNOWN",
                "risk_score": 0.0,
                "risk_percent": 0.0,
                "risk_level": "unknown",
                "evidence": [],
                "detectors": [],
                "xai_explanation": "File input was not found or was not a regular file.",
                "analysis_status": "analysis_incomplete",
            }

        # Always run generic evidence generation, including SHA-256, size,
        # MIME, magic, entropy, extension mismatch, etc.
        predictions: List[ModelPrediction] = []
        generic_result = await self.malware_engine.generic.analyze(file_path)
        if generic_result:
            predictions.append(generic_result)

        # If a YARA analyzer is available, run the signature engine on all supported files.
        yara_result = await self.malware_engine.yara.analyze(file_path)
        if yara_result:
            predictions.append(yara_result)

        # Specialized non-PE analyzers such as PE/graph are not applicable by design, but
        # kept as evidence with status NOT_APPLICABLE rather than SAFE.
        # Here we let the existing analyzers run and preserve their output in evidence.
        # If they return 'not applicable' evidence, no extra default is introduced.
        for analyzer in self.malware_engine.analyzers:
            if analyzer.__class__.__name__ in {"GenericAnalyzer", "YARAAnalyzer"}:
                continue
            try:
                result = await analyzer.analyze(file_path)
                if result:
                    predictions.append(result)
            except Exception as exc:
                logger.warning(f"Specialized analyzer skipped due to exception: {analyzer.__class__.__name__}: {exc}")
                predictions.append(
                    ModelPrediction(
                        model_name=analyzer.__class__.__name__.lower(),
                        malicious_probability=0.0,
                        confidence=0.0,
                        reasoning=f"{analyzer.__class__.__name__} failed: {exc}",
                        evidence={"detector": analyzer.__class__.__name__, "available": False, "status": "ANALYSIS_FAILED", "analysis_status": "analysis_failed"},
                    )
                )

        # Combine evidence and produce a canonical risk object.
        risk_assessment = self.risk_scorer.score(predictions)

        # Build a deterministic evidence list from predictions.
        evidence = []
        detectors = []
        for pred in predictions:
            detectors.append(pred.model_name)
            obj = {
                "detector": pred.model_name,
                "available": True,
                "status": "SUSPICIOUS" if pred.malicious_probability >= 0.5 else "CLEAN",
                "severity": round(pred.malicious_probability, 4),
                "evidence": pred.evidence,
            }
            if isinstance(pred.evidence, dict) and pred.evidence.get("analysis_status") in {"analysis_failed", "not_applicable", "unavailable_or_no_match"}:
                obj["status"] = "NOT_APPLICABLE" if pred.evidence.get("analysis_status") == "not_applicable" else "ANALYSIS_INCOMPLETE"
            evidence.append(obj)

        # XAI explanation: route through evidence-driven explainer.
        xai_summary = self.xai.explain_prediction(predictions)
        explanation = xai_summary.get("summary") or "No direct evidence available."

        # Map risk score shape requested by user.
        risk_score = float(risk_assessment.risk_score)
        risk_percent = self.risk_scorer.validate_score(risk_score)
        classification = self._classify(risk_assessment.risk_level)

        return {
            "classification": classification,
            "risk_score": round(risk_score, 2),
            "risk_percent": round(risk_percent, 2),
            "risk_level": risk_assessment.risk_level.value,
            "evidence": evidence,
            "detectors": detectors,
            "xai_explanation": explanation,
            "analysis_status": "complete" if predictions else "analysis_incomplete",
        }

    def _classify(self, level: RiskLevel) -> str:
        if level == RiskLevel.SAFE:
            return "SAFE"
        if level == RiskLevel.LOW:
            return "SUSPICIOUS"
        if level == RiskLevel.MEDIUM:
            return "SUSPICIOUS"
        if level == RiskLevel.HIGH:
            return "HIGH RISK"
        if level == RiskLevel.CRITICAL:
            return "MALICIOUS"
        return "UNKNOWN"
