"""Canonical CyberSentinel analysis result.

Every access mode (manual website upload, real-time background file protection,
real-time browser phishing protection) must return this exact shape so the UI,
the extension, the desktop warning, and the logs all speak one language.

    {
        "classification":   "SAFE" | "SUSPICIOUS" | "HIGH RISK" | "MALICIOUS"
                             | "PHISHING" | "UNKNOWN",
        "risk_score":        float,     # 0.0 - 1.0  (internal normalized scale)
        "risk_percent":      float,     # 0.0 - 100.0 (display scale, always bounded)
        "risk_level":        "safe" | "low" | "medium" | "high" | "critical" | "unknown",
        "analysis_status":   "complete" | "incomplete" | "failed",
        "evidence":          [ EvidenceItem, ... ],
        "xai_explanation":   str,
        "recommendation":    str,
    }

Malware and phishing carry different *evidence*, but the envelope never changes.

Design rules enforced here:
- A failed / unavailable / not-applicable analysis is NEVER rendered as SAFE.
  It becomes UNKNOWN with analysis_status "incomplete" or "failed".
- risk_percent is always clamped to [0, 100].
- classification is derived only from the shared risk engine, never by summing
  individual detector percentages.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Classification(str, Enum):
    """User-facing verdict labels shared by malware and phishing."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    MALICIOUS = "MALICIOUS"
    PHISHING = "PHISHING"
    UNKNOWN = "UNKNOWN"


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class EnforcementAction(str, Enum):
    """What the enforcement layer should actually do with this result."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    REDIRECT = "REDIRECT"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"


def enforcement_for(
    classification: str,
    risk_level: str,
    analysis_type: str,
    analysis_status: str = "complete",
    *,
    quarantine_enabled: bool = True,
    block_high_risk: bool = True,
) -> str:
    """Central enforcement policy (spec parts 6 & 32).

    One place decides the action so manual scan, real-time agent, and the
    browser extension stay consistent. A failed/incomplete analysis never
    becomes ALLOW.
    """
    status = (analysis_status or "complete").lower()
    level = (risk_level or "unknown").lower()
    cls = (classification or "UNKNOWN").upper()

    if level == "unknown" or cls == "UNKNOWN":
        return EnforcementAction.ANALYSIS_INCOMPLETE.value
    if status in ("failed",):
        return EnforcementAction.ANALYSIS_INCOMPLETE.value

    if analysis_type == "url":
        if cls == "PHISHING" or level in ("high", "critical"):
            return EnforcementAction.REDIRECT.value
        if cls == "SUSPICIOUS" or level == "medium":
            return EnforcementAction.WARN.value
        return EnforcementAction.ALLOW.value

    if analysis_type == "content":  # content-filter result
        return EnforcementAction.REDIRECT.value if cls in ("BLOCKED", "MALICIOUS") \
            else EnforcementAction.ALLOW.value

    # file / malware
    if cls == "MALICIOUS" or level == "critical":
        return EnforcementAction.QUARANTINE.value if quarantine_enabled else EnforcementAction.BLOCK.value
    if cls == "HIGH RISK" or level == "high":
        if quarantine_enabled:
            return EnforcementAction.QUARANTINE.value
        return EnforcementAction.BLOCK.value if block_high_risk else EnforcementAction.WARN.value
    if cls == "SUSPICIOUS" or level == "medium":
        return EnforcementAction.WARN.value
    return EnforcementAction.ALLOW.value


# Evidence-status vocabulary used inside every detector's `evidence` dict.
# The risk engine reads these to decide whether a detector *contributed* a real
# vote or *abstained* (could not analyze). Abstentions never lower the score.
CONTRIBUTING_STATUSES = {"complete", "match", "matched", "no_match", "clean", "analyzed"}
ABSTENTION_STATUSES = {
    "analysis_failed",
    "analysis_incomplete",
    "not_applicable",
    "not_configured",           # optional component, no config - expected, not an error
    "unavailable",
    "unavailable_or_no_match",  # legacy value still emitted by older code paths
    "error",
    "skipped",
}

# Abstention reasons that are EXPECTED for a given input / setup and so do not
# make the overall analysis "incomplete" (they are still listed, and the XAI
# still names them).
EXPECTED_ABSTENTIONS = {"not_applicable", "not_configured", ""}


@dataclass
class EvidenceItem:
    """One detector's contribution to the assessment."""

    detector: str
    status: str                       # "contributed" | "abstained"
    reason: str                       # e.g. "not_applicable", "match", "no_match"
    severity: float = 0.0             # 0.0 - 1.0 this detector's own malicious prob
    weight: float = 1.0
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisOutcome:
    """The canonical result object returned by all three access modes."""

    classification: str
    risk_score: float                 # 0.0 - 1.0
    risk_percent: float               # 0.0 - 100.0
    risk_level: str
    analysis_status: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    xai_explanation: str = ""
    recommendation: str = "review_by_user"
    enforcement_action: str = EnforcementAction.WARN.value

    # --- non-breaking extras (present but not part of the required envelope) ---
    analysis_type: Optional[str] = None       # "file" | "url"
    target: Optional[str] = None              # file path or URL
    sha256: Optional[str] = None
    contributing_models: List[str] = field(default_factory=list)
    abstained_models: List[str] = field(default_factory=list)
    consensus_count: int = 0
    model_count: int = 0
    analysis_time_ms: float = 0.0
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification,
            "risk_score": round(float(self.risk_score), 4),
            "risk_percent": round(float(self.risk_percent), 2),
            "risk_level": self.risk_level,
            "analysis_status": self.analysis_status,
            "evidence": self.evidence,
            "xai_explanation": self.xai_explanation,
            "recommendation": self.recommendation,
            "enforcement_action": self.enforcement_action,
            "contributions": contribution_report(self.evidence),
            "analysis_type": self.analysis_type,
            "target": self.target,
            "sha256": self.sha256,
            "contributing_models": self.contributing_models,
            "abstained_models": self.abstained_models,
            "consensus_count": self.consensus_count,
            "model_count": self.model_count,
            "analysis_time_ms": round(float(self.analysis_time_ms), 2),
            "request_id": self.request_id,
        }


def is_abstention(evidence: Any, confidence: float = 0.0, probability: float = 0.0) -> bool:
    """Decide whether a detector abstained (could not analyze) vs voted.

    Abstention rules:
    - explicit ``analysis_status`` in the abstention vocabulary, or
    - ``available`` is False, or
    - the detector reported zero confidence AND zero probability (no signal).

    A detector that *ran* and found nothing (``no_match`` / ``clean``) is NOT an
    abstention - it is a genuine low-risk vote.
    """
    if isinstance(evidence, dict):
        status = str(evidence.get("analysis_status", "")).lower()
        if status in ABSTENTION_STATUSES:
            return True
        if status in CONTRIBUTING_STATUSES:
            return False
        if evidence.get("available") is False:
            return True
    return confidence <= 0.0 and probability <= 0.0


def _severity_band(sev: float) -> str:
    if sev >= 0.7:
        return "HIGH"
    if sev >= 0.35:
        return "MEDIUM"
    if sev > 0.0:
        return "LOW"
    return "NONE"


def contribution_report(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-detector contribution view (spec part 15).

    For each detector: its contribution band, status, and a one-line piece of
    evidence - so a researcher can see which layers actually drove the verdict.
    """
    rows: List[Dict[str, Any]] = []
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        sev = float(item.get("severity", 0.0) or 0.0)
        signal = ""
        for key in ("matched_rules", "indicators", "suspicious_indicators",
                    "suspicious_imports", "threats", "matched"):
            v = data.get(key)
            if v:
                signal = str(v[0] if isinstance(v, list) and v else v)[:120]
                break
        rows.append({
            "detector": item.get("detector"),
            "status": item.get("status", "?"),          # contributed | abstained
            "reason": item.get("reason", ""),
            "contribution": _severity_band(sev) if item.get("status") == "contributed" else "-",
            "severity": round(sev, 3),
            "weight": item.get("weight", 1.0),
            "evidence": signal or item.get("summary", "")[:120],
        })
    # contributing detectors first, by descending severity
    rows.sort(key=lambda r: (r["status"] != "contributed", -r["severity"]))
    return rows


def classification_for(risk_level: str, analysis_type: str) -> str:
    """Map a risk level + analysis type to a shared classification label."""
    level = (risk_level or "unknown").lower()
    if level == "unknown":
        return Classification.UNKNOWN.value
    if analysis_type == "url":
        if level in ("safe", "low"):
            return Classification.SAFE.value
        if level == "medium":
            return Classification.SUSPICIOUS.value
        return Classification.PHISHING.value          # high / critical
    # file / malware
    if level in ("safe", "low"):
        return Classification.SAFE.value
    if level == "medium":
        return Classification.SUSPICIOUS.value
    if level == "high":
        return Classification.HIGH_RISK.value
    return Classification.MALICIOUS.value             # critical
