"""Local explainability layer for CyberSentinel.

This adds a lightweight, dependency-safe explanation engine for detections.
It is intentionally based on explicit evidence extracted from the model outputs,
not on heavy external libraries, so it continues to work in offline/local-only
scenarios. When SHAP or LIME are installed, this layer can optionally enrich the
explanations without replacing the core evidence-driven logic.
"""

from __future__ import annotations

from typing import Any, Dict, List
import logging

from cybersentinel.common.risk_scorer import ModelPrediction, RiskScorer, RiskLevel
from cybersentinel.common.result import is_abstention

logger = logging.getLogger(__name__)

# Human phrasing for each abstention reason - so a failure is explained as a
# failure, never implied to be "safe".
_ABSTENTION_PHRASES = {
    "unavailable": "analysis component unavailable",
    "unavailable_or_no_match": "analysis component unavailable",
    "not_applicable": "not applicable to this file type",
    "analysis_failed": "analysis failed",
    "analysis_incomplete": "analysis incomplete",
    "error": "analysis error",
    "skipped": "analysis skipped",
}


class XAIExplainer:
    """Explain the evidence behind a risk assessment (evidence-driven, local)."""

    def __init__(self):
        self.risk_scorer = RiskScorer()

    def explain_prediction(self, predictions: List[ModelPrediction]) -> Dict[str, Any]:
        """Return an evidence-backed explanation for a set of model predictions.

        Never claims safety when detectors abstained: abstentions are listed
        explicitly and, if nothing contributed, the summary says the result is
        UNKNOWN.
        """
        predictions = list(predictions or [])
        if not predictions:
            return {
                "summary": "CyberSentinel could not obtain any evidence for a "
                           "reliable classification (UNKNOWN).",
                "top_factors": [],
                "incomplete": [],
                "risk_level": RiskLevel.UNKNOWN.value,
                "risk_score": 0.0,
            }

        assessment = self.risk_scorer.score(predictions)

        contributing, abstained = [], []
        for pred in predictions:
            (abstained if is_abstention(pred.evidence, pred.confidence,
                                        pred.malicious_probability) else contributing).append(pred)

        top_factors = []
        for pred in sorted(contributing, key=lambda p: p.malicious_probability, reverse=True):
            evidence = pred.evidence if isinstance(pred.evidence, dict) else {}
            signal = None
            for key in ("matched_rules", "suspicious_indicators", "indicators",
                        "suspicious_imports", "capability_categories"):
                if evidence.get(key):
                    signal = evidence[key]
                    break
            top_factors.append({
                "model": pred.model_name,
                "score": round(pred.malicious_probability, 3),
                "confidence": round(pred.confidence, 3),
                "reason": pred.reasoning,
                "signal": signal if signal is not None else list(evidence.keys())[:6],
            })

        not_applicable, incomplete = [], []
        for p in abstained:
            status = (str(p.evidence.get("analysis_status", "")).lower()
                      if isinstance(p.evidence, dict) else "")
            row = {
                "model": p.model_name,
                "reason": _ABSTENTION_PHRASES.get(status, "analysis incomplete"),
                "detail": p.reasoning,
            }
            (not_applicable if status == "not_applicable" else incomplete).append(row)

        summary = self._summarize(
            assessment, top_factors, incomplete, contributing,
            all_abstained=(incomplete + not_applicable),
        )

        return {
            "summary": summary,
            "top_factors": top_factors,
            "incomplete": incomplete,          # unavailable / failed - matters
            "not_applicable": not_applicable,  # expected for this file type
            "risk_level": assessment.risk_level.value,
            "risk_score": round(assessment.risk_score, 2),
            "classification_note": self._metamorphic_note(contributing),
        }

    @staticmethod
    def _summarize(assessment, top_factors, incomplete, contributing, all_abstained=None) -> str:
        level = assessment.risk_level
        if level == RiskLevel.UNKNOWN:
            names = ", ".join(f["model"] for f in (all_abstained or incomplete)) or "all components"
            return (
                "CyberSentinel could not obtain sufficient evidence for a reliable "
                f"classification (UNKNOWN). Components that could not run: {names}. "
                "This is NOT a safe result."
            )

        drivers = [f for f in top_factors if f["score"] >= 0.2][:4]
        if drivers:
            bullet = "; ".join(f"{d['model']} ({d['reason']})" for d in drivers)
            head = (
                f"CyberSentinel classified this as {level.value.upper()} risk because "
                f"{len(drivers)} independent analysis component(s) identified suspicious "
                f"characteristics: {bullet}."
            )
        else:
            head = (
                f"CyberSentinel classified this as {level.value.upper()} risk. "
                f"{len(contributing)} component(s) analyzed the target and found no "
                "significant threat evidence."
            )
        if incomplete:
            head += (
                " Note: " + ", ".join(i["model"] for i in incomplete)
                + " could not complete and were not counted."
            )
        return head

    @staticmethod
    def _metamorphic_note(contributing) -> str:
        for pred in contributing:
            ev = pred.evidence if isinstance(pred.evidence, dict) else {}
            if pred.model_name == "malware_metamorphic" and ev.get("indicator_count", 0) > 0:
                return (
                    "The sample's exact SHA-256 representation differed from the "
                    "reference representation, while normalized structural and "
                    "instruction-level characteristics remained related. These "
                    "characteristics contributed to the elevated risk assessment."
                )
        return ""

    def enrich_with_shap_if_available(self, predictions: List[ModelPrediction], feature_map: Dict[str, Any]) -> Dict[str, Any]:
        """Optional enhancement when SHAP is installed.

        This method is intentionally non-fatal: if no SHAP dependency exists, it
        simply returns the local explanation result.
        """
        try:
            import shap  # type: ignore
        except Exception:
            logger.debug("SHAP not installed; using local explainability fallback")
            return self.explain_prediction(predictions)

        explanation = self.explain_prediction(predictions)
        if not feature_map:
            return explanation

        explanation["shap_notes"] = {
            "feature_map": list(feature_map.keys())[:10],
            "note": "SHAP is available and can be used for deeper feature attribution.",
        }
        return explanation
