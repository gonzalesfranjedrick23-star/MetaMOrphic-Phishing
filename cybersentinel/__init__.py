"""
CyberSentinel: Multilayered Real-Time Threat Detection Platform

A unified threat detection system combining:
- Malware analysis (CFG-based with graph neural networks)
- Phishing detection (URL/DOM analysis with KNN)
- Real-time monitoring (file/process watching)
- Explainable AI (SHAP/LIME integration)
- Safe quarantine (isolated threat storage)

Local-first architecture: 100% core detection works offline.
External intelligence: Optional, never required.
"""

__version__ = "0.2.0"
__author__ = "CyberSentinel Team"

# Core exports
from .common.event_bus import EventBus, Event, EventType
from .common.risk_scorer import RiskScorer, RiskLevel
from .common.database import ThreatDatabase
from .orchestrator import ThreatOrchestrator
from .phishing_engine import PhishingEngine
from .malware_engine import MalwareEngine, GenericAnalyzer, FileAnalyzerRegistry

__all__ = [
    # Common
    "EventBus",
    "Event",
    "EventType",
    "RiskScorer",
    "RiskLevel",
    "ThreatDatabase",
    
    # Orchestration
    "ThreatOrchestrator",
    
    # Engines
    "PhishingEngine",
    "MalwareEngine",
]
