"""
Risk Scorer: Unified risk assessment across all detection engines.

Combines predictions from malware, phishing, and behavioral engines
into a single, calibrated risk score (0-100).
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
import statistics
import math

from .result import is_abstention


@dataclass
class RiskScore:
    """Canonical internal score object for the shared risk engine.

    value_0_1 is the one normalized internal representation.
    display_percent is the externally bounded display representation.
    """
    value_0_1: float
    display_percent: float
    category: str


class RiskLevel(Enum):
    """Risk severity levels."""

    SAFE = "safe"              # 0-20: Benign
    LOW = "low"                # 20-40: Minimal risk
    MEDIUM = "medium"          # 40-60: Suspicious, needs review
    HIGH = "high"              # 60-80: Likely malicious
    CRITICAL = "critical"      # 80-100: Definitely malicious
    UNKNOWN = "unknown"        # analysis could not be completed - NOT safe


@dataclass
class ModelPrediction:
    """Prediction from a single model."""
    
    model_name: str              # e.g., "phishing_knn", "malware_graph", "behavioral_yara"
    malicious_probability: float # 0.0-1.0, probability of being malicious
    confidence: float           # 0.0-1.0, confidence in the prediction
    reasoning: str              # Why this prediction was made
    evidence: Dict[str, Any]    # Raw model evidence
    
    def to_risk_score(self) -> float:
        """Convert to risk score (0-100)."""
        return self.malicious_probability * 100.0


@dataclass
class RiskAssessment:
    """Complete risk assessment for a file or URL."""

    risk_score: float              # 0-100
    risk_level: RiskLevel          # SAFE, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    individual_predictions: List[ModelPrediction]  # Predictions from all models
    consensus_count: int           # How many models agree it's malicious
    model_disagreement: bool       # True if models significantly disagree
    recommendation: str            # What to do (allow, warn, block, quarantine)
    explanation: str               # Human-readable explanation

    # Evidence-integrity fields: which detectors actually voted vs abstained.
    analysis_status: str = "complete"           # complete | incomplete | failed
    contributing_models: List[str] = field(default_factory=list)
    abstained_models: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"RiskAssessment(score={self.risk_score:.1f}, level={self.risk_level.value})"


class RiskScorer:
    """
    Combines predictions from multiple threat detection models
    into a unified risk score and recommendation.

    Every displayed or returned risk output must pass through the
    centralized score validator so no API/UI consumer can show a
    score above 100 or below 0.
    """

    @staticmethod
    def normalize_score(raw: Any) -> float:
        """Central, typed normalization for user-facing risk scores.

        Accepts likely malformed values and converts them into a safe bounded
        display scalar. It accepts value kinds expected from the repository:
        numeric, strings, None, NaN, infinity, and scaled probability values.
        """
        if raw is None:
            return 0.0
        if isinstance(raw, bool):
            return 100.0 if raw else 0.0
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                return 0.0
            try:
                value = float(text.replace('%', ''))
            except Exception:
                return 0.0
            if not math.isfinite(value):
                return 0.0
            return RiskScorer.normalize_score(value)
        if isinstance(raw, (int, float)):
            value = float(raw)
            if not math.isfinite(value):
                return 0.0
            if value < 0:
                value = 0.0
            if value > 100:
                value = 100.0
            # If the input arrives already as a probability in [0,1], treat that
            # as the internal scale and convert exactly once to the display range.
            if 0.0 <= value <= 1.0:
                value = value * 100.0
            return max(0.0, min(100.0, value))
        return 0.0

    @staticmethod
    def validate_score(score: float) -> float:
        """Bound every risk score to the allowed 0-100 percentage range."""
        return RiskScorer.normalize_score(score)

    @staticmethod
    def to_internal_score(score: Union[float, int, str, None]) -> RiskScore:
        """Create a canonical internal score object from any raw score input."""
        display = RiskScorer.normalize_score(score)
        internal = display / 100.0 if display != 0 else 0.0
        category = RiskLevel.SAFE.value if display < 20 else (
            RiskLevel.LOW.value if display < 40 else (
                RiskLevel.MEDIUM.value if display < 60 else (
                    RiskLevel.HIGH.value if display < 80 else RiskLevel.CRITICAL.value
                )
            )
        )
        return RiskScore(value_0_1=max(0.0, min(1.0, internal)), display_percent=display, category=category)

    def __init__(self):
        """Initialize the risk scorer."""
        # Thresholds for risk levels
        self.thresholds = {
            RiskLevel.SAFE: (0, 20),
            RiskLevel.LOW: (20, 40),
            RiskLevel.MEDIUM: (40, 60),
            RiskLevel.HIGH: (60, 80),
            RiskLevel.CRITICAL: (80, 100),
        }
        
        # Model weights (relative trust; 1.0 = baseline). Every analyzer that can
        # actually run in this build has an entry so weighting is never silently
        # defaulted for a live detector.
        self.model_weights: Dict[str, float] = {
            # phishing
            "phishing_knn": 1.0,
            "phishing_url_features": 1.1,
            "phishing_domain_lookalike": 1.3,
            "phishing_enhanced": 1.2,
            "phishing_dom": 1.2,
            "phishing_nlp": 1.1,
            "phishing_visual": 1.0,
            # malware
            "malware_yara": 1.5,          # signature = very high confidence
            "malware_graph": 1.3,
            "malware_metamorphic": 1.2,
            "malware_pe": 1.15,
            "malware_media": 1.15,
            "malware_ml": 1.15,   # a trained model; bootstrap model is synthetic-data only
            "malware_byte": 1.0,
            "generic_analyzer": 0.8,      # metadata / format only
            "malware_behavior": 1.2,
            "anomaly_detector": 1.0,
        }

        # Disagreement threshold: if std dev of predictions > this, flag disagreement
        self.disagreement_threshold = 25.0

    # --- fusion tuning ----------------------------------------------------
    NOISY_OR_FLOOR = 0.20      # probs below this don't compound in the OR
    SIGNATURE_FLOOR = 0.75     # a signature match / near-certain hit -> at least HIGH
    CRITICAL_FLOOR = 0.90      # a near-certain hit -> at least CRITICAL

    def _weight(self, model_name: str) -> float:
        return self.model_weights.get(model_name, 1.0)

    @staticmethod
    def _status_from_abstentions(abstained: List["ModelPrediction"]) -> str:
        """A run where the only abstentions were "not applicable to this type"
        is still COMPLETE. An unavailable/failed component makes it INCOMPLETE.
        """
        if not abstained:
            return "complete"
        reasons = {
            str(p.evidence.get("analysis_status", "")).lower()
            if isinstance(p.evidence, dict) else ""
            for p in abstained
        }
        from .result import EXPECTED_ABSTENTIONS
        if reasons <= EXPECTED_ABSTENTIONS:
            return "complete"
        return "incomplete"
    
    def score(self, predictions: List[ModelPrediction]) -> RiskAssessment:
        """Fuse multiple detector predictions into one calibrated assessment.

        Evidence-integrity rules (this is where "failure -> SAFE" bugs live, so
        they are enforced explicitly):

        1. Detectors that *could not analyze* the sample (YARA unavailable, PE
           analysis not applicable, disassembly failed, ML unavailable, ...)
           ABSTAIN. Their zero is not counted as a "benign" vote.
        2. If every detector abstained -> RiskLevel.UNKNOWN, never SAFE.
        3. Fusion over the detectors that *did* vote uses a weighted noisy-OR
           (any credible detector can raise the score) plus the single strongest
           signal - never a median/mean that buries a minority detection.
        4. A signature match or a near-certain hit floors the score at HIGH
           (or CRITICAL), so one authoritative detector is never out-voted.
        5. The result is produced once on the 0..1 scale and converted once to
           the 0..100 display scale, then bounded.
        """
        predictions = list(predictions or [])

        contributing: List[ModelPrediction] = []
        abstained: List[ModelPrediction] = []
        for pred in predictions:
            if is_abstention(pred.evidence, pred.confidence, pred.malicious_probability):
                abstained.append(pred)
            else:
                contributing.append(pred)

        # Rule 2: nothing could analyze this -> UNKNOWN (explicitly not SAFE).
        if not contributing:
            status = "failed" if any(
                isinstance(p.evidence, dict)
                and str(p.evidence.get("analysis_status", "")).lower() in ("analysis_failed", "error")
                for p in predictions
            ) else "incomplete"
            explanation = self._generate_explanation(
                predictions, RiskLevel.UNKNOWN, 0, len(predictions), False, abstained
            )
            return RiskAssessment(
                risk_score=0.0,
                risk_level=RiskLevel.UNKNOWN,
                individual_predictions=predictions,
                consensus_count=0,
                model_disagreement=False,
                recommendation="review_by_user",
                explanation=explanation,
                analysis_status=status,
                contributing_models=[],
                abstained_models=[p.model_name for p in abstained],
            )

        # Rule 3: weighted noisy-OR over contributing detectors + strongest
        # *calibrated* signal.  A model's probability alone is not an
        # authoritative verdict: a 2-of-3 KNN vote, for example, reports
        # 66.7% malicious probability but only 33.3% confidence.  Using the
        # raw maximum here would turn that uncertain vote into a HIGH-risk
        # result even when every structural detector found nothing.
        probs = [max(0.0, min(1.0, p.malicious_probability)) for p in contributing]
        calibrated_probs = [
            prob * max(0.0, min(1.0, pred.confidence))
            for pred, prob in zip(contributing, probs)
        ]
        strongest = max(calibrated_probs)

        inv_product = 1.0
        for pred, prob in zip(contributing, probs):
            if prob < self.NOISY_OR_FLOOR:
                continue
            weight = min(1.5, self._weight(pred.model_name)) / 1.5      # 0..1
            conf = 0.5 + 0.5 * max(0.0, min(1.0, pred.confidence))      # 0.5..1
            effective = prob * (0.4 + 0.6 * weight) * conf
            inv_product *= (1.0 - max(0.0, min(1.0, effective)))
        noisy_or = 1.0 - inv_product

        risk_01 = max(strongest, noisy_or)

        # Rule 4: authoritative-detector floor.
        signature_match = any(
            isinstance(p.evidence, dict) and p.evidence.get("signature_match") is True
            for p in contributing
        )
        if signature_match or strongest >= 0.85:
            risk_01 = max(risk_01, self.SIGNATURE_FLOOR)
        if strongest >= self.CRITICAL_FLOOR:
            risk_01 = max(risk_01, 0.90)

        risk_01 = max(0.0, min(1.0, risk_01))

        # Rule 5: single conversion to the bounded display scale.
        risk_score = self.validate_score(risk_01 * 100.0)
        risk_level = self._get_risk_level(risk_score)

        consensus_count = sum(1 for p in contributing if p.malicious_probability > 0.5)

        contrib_scores = [p.to_risk_score() for p in contributing]
        score_std_dev = statistics.stdev(contrib_scores) if len(contrib_scores) > 1 else 0.0
        model_disagreement = score_std_dev > self.disagreement_threshold

        recommendation = self._get_recommendation(
            risk_level, consensus_count, len(contributing), model_disagreement
        )
        explanation = self._generate_explanation(
            predictions, risk_level, consensus_count, len(contributing),
            model_disagreement, abstained
        )

        analysis_status = self._status_from_abstentions(abstained)

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            individual_predictions=predictions,
            consensus_count=consensus_count,
            model_disagreement=model_disagreement,
            recommendation=recommendation,
            explanation=explanation,
            analysis_status=analysis_status,
            contributing_models=[p.model_name for p in contributing],
            abstained_models=[p.model_name for p in abstained],
        )

    def _get_risk_level(self, score: float) -> RiskLevel:
        """Map a 0-100 risk score to a risk level."""
        for level, (low, high) in self.thresholds.items():
            if low <= score < high:
                return level
        return RiskLevel.CRITICAL
    
    def _get_recommendation(
        self,
        risk_level: RiskLevel,
        consensus_count: int,
        total_models: int,
        disagreement: bool
    ) -> str:
        """Generate action recommendation."""

        if risk_level == RiskLevel.UNKNOWN:
            return "review_by_user"

        if disagreement and risk_level == RiskLevel.MEDIUM:
            # Conflicting evidence - ask for user input
            return "review_by_user"

        if risk_level == RiskLevel.SAFE:
            return "allow"
        elif risk_level == RiskLevel.LOW:
            return "allow_monitor"
        elif risk_level == RiskLevel.MEDIUM:
            return "warn_user"
        elif risk_level == RiskLevel.HIGH:
            return "quarantine"
        else:  # CRITICAL
            return "quarantine_and_alert"
    
    def _generate_explanation(
        self,
        predictions: List[ModelPrediction],
        risk_level: RiskLevel,
        consensus_count: int,
        total_models: int,
        disagreement: bool,
        abstained: Optional[List[ModelPrediction]] = None,
    ) -> str:
        """Generate a human-readable explanation of the assessment."""

        abstained = abstained or []
        lines = [f"Risk Level: {risk_level.value.upper()}"]

        if risk_level == RiskLevel.UNKNOWN:
            lines.append(
                "CyberSentinel could not obtain sufficient evidence for a reliable "
                "classification. This is NOT a safe result."
            )
            if abstained:
                lines.append("Analysis components that could not run:")
                for pred in abstained:
                    lines.append(f"  - {pred.model_name}: {pred.reasoning}")
            return "\n".join(lines)

        agreement_pct = (consensus_count / total_models * 100) if total_models > 0 else 0
        lines.append(
            f"Model Agreement: {consensus_count}/{total_models} contributing models "
            f"({agreement_pct:.0f}%)"
        )

        abstained_ids = {id(p) for p in abstained}
        contributing = [p for p in predictions if id(p) not in abstained_ids]
        top_predictions = sorted(
            contributing, key=lambda p: p.malicious_probability, reverse=True
        )[:4]
        lines.append("Evidence:")
        for pred in top_predictions:
            lines.append(f"  • {pred.model_name}: {pred.reasoning}")

        if abstained:
            names = ", ".join(p.model_name for p in abstained)
            lines.append(f"Incomplete analysis components (not counted): {names}")

        if disagreement:
            lines.append("Note: Model disagreement detected. Review details carefully.")

        return "\n".join(lines)
    
    def set_model_weight(self, model_name: str, weight: float) -> None:
        """Adjust weight for a specific model."""
        if 0.0 <= weight <= 2.0:
            self.model_weights[model_name] = weight
        else:
            raise ValueError("Model weight must be between 0.0 and 2.0")
    
    def get_model_weights(self) -> Dict[str, float]:
        """Get all model weights."""
        return self.model_weights.copy()
