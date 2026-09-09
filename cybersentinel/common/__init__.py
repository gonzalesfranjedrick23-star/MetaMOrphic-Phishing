"""
Common utilities for CyberSentinel.

Includes event bus, risk scoring, and database components
shared across all engines.
"""

from .event_bus import (
    EventBus,
    Event,
    EventType,
    get_event_bus,
)
from .risk_scorer import (
    RiskScorer,
    RiskLevel,
    ModelPrediction,
    RiskAssessment,
)
from .database import (
    ThreatDatabase,
    ThreatRecord,
    QuarantineRecord,
    compute_file_hash,
)
from .result import (
    AnalysisOutcome,
    Classification,
    AnalysisStatus,
    EnforcementAction,
    EvidenceItem,
    is_abstention,
    classification_for,
    enforcement_for,
)

__all__ = [
    # Canonical result
    "AnalysisOutcome",
    "Classification",
    "AnalysisStatus",
    "EnforcementAction",
    "EvidenceItem",
    "is_abstention",
    "classification_for",
    "enforcement_for",
    # Event bus
    "EventBus",
    "Event",
    "EventType",
    "get_event_bus",
    
    # Risk scoring
    "RiskScorer",
    "RiskLevel",
    "ModelPrediction",
    "RiskAssessment",
    
    # Database
    "ThreatDatabase",
    "ThreatRecord",
    "QuarantineRecord",
    "compute_file_hash",
]
