"""
Orchestrator: Central coordinator for all threat detection engines.

Manages workflow:
1. Receive events (file created, URL visited)
2. Route to appropriate engines (malware, phishing)
3. Collect predictions
4. Compute risk score
5. Generate explanation
6. Recommend action (allow, warn, quarantine)
"""

import asyncio
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import logging

from cybersentinel.common import (
    EventBus,
    Event,
    EventType,
    get_event_bus,
    RiskScorer,
    RiskLevel,
    ModelPrediction,
    RiskAssessment,
    ThreatDatabase,
    AnalysisOutcome,
    classification_for,
    enforcement_for,
)
from cybersentinel.xai.explainer import XAIExplainer


logger = logging.getLogger(__name__)


@dataclass
class AnalysisRequest:
    """Request to analyze a file or URL."""
    
    request_id: str
    analysis_type: str  # "file" or "url"
    target: str        # File path or URL
    priority: int = 0  # 0=normal, 1=high, 2=critical


@dataclass
class AnalysisResult:
    """Result of an analysis."""

    request_id: str
    risk_assessment: RiskAssessment
    analysis_time_ms: float
    outcome: Optional[Dict[str, Any]] = None   # canonical shared schema (result.py)
    xai: Optional[Dict[str, Any]] = None       # XAIExplainer output
    quarantine: Optional[Dict[str, Any]] = None

    def __repr__(self) -> str:
        return f"AnalysisResult(score={self.risk_assessment.risk_score:.1f}, time={self.analysis_time_ms:.0f}ms)"


class ThreatOrchestrator:
    """
    Central orchestrator coordinating all threat detection engines.
    
    Workflow:
    1. Listen for file/URL events
    2. Route to appropriate detection engines
    3. Collect predictions from all engines
    4. Compute unified risk score
    5. Recommend action
    6. Execute action (warn, quarantine, etc.)
    """
    
    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        db_path: Optional[str] = None,
        quarantine_manager: Optional[Any] = None,
        notifier: Optional[Any] = None,
        xai: Optional[Any] = None,
        auto_quarantine: bool = False,
    ):
        """
        Initialize orchestrator.

        Args:
            event_bus: EventBus instance (creates new if None)
            db_path: Database path for storing results
            quarantine_manager: optional QuarantineManager; when set, HIGH/CRITICAL
                file verdicts are isolated automatically.
            notifier: optional DesktopNotifier for HIGH/CRITICAL file verdicts.
            xai: optional XAIExplainer (created if None).
        """
        self.event_bus = event_bus or get_event_bus()
        self.database = ThreatDatabase(db_path)
        self.risk_scorer = RiskScorer()
        self.xai = xai or XAIExplainer()
        self.quarantine_manager = quarantine_manager
        self.notifier = notifier
        self.auto_quarantine = auto_quarantine
        
        # Analysis engines (will be populated as components are integrated)
        self.malware_engines: Dict[str, Any] = {}
        self.phishing_engines: Dict[str, Any] = {}
        self.behavioral_engines: Dict[str, Any] = {}
        
        # Analysis queue
        self.analysis_queue: asyncio.Queue = asyncio.Queue()
        self.pending_analyses: Dict[str, AnalysisRequest] = {}
        
        # Active protection state
        self.protection_active = False
        
        # Subscribe to relevant events
        self._subscribe_to_events()
    
    def _subscribe_to_events(self) -> None:
        """Subscribe to relevant events."""
        self.event_bus.subscribe(EventType.FILE_CREATED, self._on_file_event)
        self.event_bus.subscribe(EventType.FILE_MODIFIED, self._on_file_event)
        self.event_bus.subscribe(EventType.FILE_DOWNLOADED, self._on_file_event)
        self.event_bus.subscribe(EventType.URL_VISITED, self._on_url_event)
        self.event_bus.subscribe(EventType.PROTECTION_STARTED, self._on_protection_started)
        self.event_bus.subscribe(EventType.PROTECTION_STOPPED, self._on_protection_stopped)
    
    def register_malware_engine(self, engine_name: str, engine: Any) -> None:
        """Register a malware detection engine."""
        self.malware_engines[engine_name] = engine
        logger.info(f"Registered malware engine: {engine_name}")
    
    def register_phishing_engine(self, engine_name: str, engine: Any) -> None:
        """Register a phishing detection engine."""
        self.phishing_engines[engine_name] = engine
        logger.info(f"Registered phishing engine: {engine_name}")
    
    def register_behavioral_engine(self, engine_name: str, engine: Any) -> None:
        """Register a behavioral analysis engine."""
        self.behavioral_engines[engine_name] = engine
        logger.info(f"Registered behavioral engine: {engine_name}")
    
    async def analyze_file(
        self,
        file_path: str,
        request_id: Optional[str] = None,
        enforce: Optional[bool] = None,
    ) -> AnalysisResult:
        """
        Analyze a file for malware threats.

        Args:
            file_path: Path to file to analyze
            request_id: Optional request ID (generated if not provided)
            enforce: override auto-quarantine for this call only (real-time
                protection passes True; a manual website scan passes False).

        Returns:
            AnalysisResult with risk assessment
        """
        start_time = time.time()
        enforce = self.auto_quarantine if enforce is None else enforce

        if request_id is None:
            import uuid
            request_id = str(uuid.uuid4())

        self.event_bus.publish(Event(
            event_type=EventType.ANALYSIS_STARTED,
            source="orchestrator",
            data={"file_path": file_path, "request_id": request_id},
        ))

        try:
            # Collect predictions from every registered malware engine/analyzer.
            # Detectors that cannot analyze the sample ABSTAIN (they carry an
            # analysis_status the RiskScorer excludes) - they are never turned
            # into a benign vote.
            predictions: List[ModelPrediction] = []
            for engine_name, engine in self.malware_engines.items():
                try:
                    if hasattr(engine, "analyze_all"):
                        predictions.extend(await engine.analyze_all(file_path))
                    else:
                        prediction = await engine.analyze(file_path)
                        if prediction:
                            predictions.append(prediction)
                except Exception as e:
                    logger.error("Error in malware engine %s: %s", engine_name, e)
                    predictions.append(ModelPrediction(
                        model_name=str(engine_name),
                        malicious_probability=0.0,
                        confidence=0.0,
                        reasoning=f"ANALYSIS FAILED - {e}",
                        evidence={"available": False, "analysis_status": "analysis_failed"},
                    ))

            if not predictions:
                predictions = [ModelPrediction(
                    model_name="orchestrator",
                    malicious_probability=0.0,
                    confidence=0.0,
                    reasoning="No malware analyzer produced a result.",
                    evidence={"available": False, "analysis_status": "analysis_incomplete"},
                )]

            risk_assessment = self.risk_scorer.score(predictions)
            analysis_time_ms = (time.time() - start_time) * 1000

            xai = self.xai.explain_prediction(predictions)
            outcome = self._build_outcome(
                "file", file_path, risk_assessment, predictions,
                analysis_time_ms, request_id, xai,
            )

            result = AnalysisResult(
                request_id=request_id,
                risk_assessment=risk_assessment,
                analysis_time_ms=analysis_time_ms,
                outcome=outcome.to_dict(),
                xai=xai,
            )

            self.event_bus.publish(Event(
                event_type=EventType.ANALYSIS_COMPLETED,
                source="orchestrator",
                data={
                    "request_id": request_id,
                    "file_path": file_path,
                    "risk_score": risk_assessment.risk_score,
                    "risk_level": risk_assessment.risk_level.value,
                    "classification": outcome.classification,
                    "analysis_status": risk_assessment.analysis_status,
                },
            ))

            if risk_assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                self._handle_file_threat(file_path, risk_assessment, outcome, result, enforce)

            return result

        except Exception as e:
            logger.error("File analysis failed for %s: %s", file_path, e)
            self.event_bus.publish(Event(
                event_type=EventType.ANALYSIS_FAILED,
                source="orchestrator",
                data={"request_id": request_id, "error": str(e)},
            ))
            raise

    # ------------------------------------------------------------------
    def _build_outcome(
        self,
        analysis_type: str,
        target: str,
        assessment: RiskAssessment,
        predictions: List[ModelPrediction],
        elapsed_ms: float,
        request_id: str,
        xai: Optional[Dict[str, Any]] = None,
    ) -> AnalysisOutcome:
        """Convert a RiskAssessment into the canonical shared result schema."""
        risk_percent = float(assessment.risk_score)
        risk_level_value = assessment.risk_level.value

        # Phishing corroboration guard (spec part 7 - do not block legit sites):
        # the lexical KNN is a weak URL-only signal. A BLOCK-level phishing verdict
        # needs a deterministic lookalike/homograph hit OR >= 2 phishing detectors
        # above 0.5. A lone KNN vote is downgraded to SUSPICIOUS.
        if analysis_type == "url" and risk_level_value in ("high", "critical"):
            strong = [p for p in predictions if p.malicious_probability >= 0.5
                      and p.model_name not in assessment.abstained_models]
            deterministic = any(
                isinstance(p.evidence, dict) and p.evidence.get("deterministic") is True
                for p in strong
            )
            only_knn = strong and all(p.model_name == "phishing_knn" for p in strong)
            if only_knn and not deterministic:
                # lone lexical KNN, no corroboration -> not actionable on its own
                risk_percent = min(risk_percent, 38.0)
                risk_level_value = "low"

        risk_01 = round(risk_percent / 100.0, 4)
        classification = classification_for(risk_level_value, analysis_type)
        enforcement_action = enforcement_for(
            classification, risk_level_value, analysis_type,
            assessment.analysis_status,
            quarantine_enabled=getattr(self, "quarantine_manager", None) is not None,
        )

        contributing_ids = set(assessment.contributing_models)
        evidence = []
        for pred in predictions:
            ev = pred.evidence if isinstance(pred.evidence, dict) else {}
            abstained = pred.model_name in assessment.abstained_models
            evidence.append({
                "detector": pred.model_name,
                "status": "abstained" if abstained else "contributed",
                "reason": str(ev.get("analysis_status", "analyzed")),
                "severity": round(float(pred.malicious_probability), 4),
                "weight": self.risk_scorer.get_model_weights().get(pred.model_name, 1.0),
                "summary": pred.reasoning,
                "data": ev,
            })

        sha256 = None
        if analysis_type == "file":
            for pred in predictions:
                if isinstance(pred.evidence, dict) and pred.evidence.get("sha256"):
                    sha256 = pred.evidence["sha256"]
                    break

        return AnalysisOutcome(
            classification=classification,
            risk_score=risk_01,
            risk_percent=round(risk_percent, 2),
            risk_level=risk_level_value,
            analysis_status=assessment.analysis_status,
            evidence=evidence,
            xai_explanation=(xai or {}).get("summary") or assessment.explanation,
            recommendation=assessment.recommendation,
            enforcement_action=enforcement_action,
            analysis_type=analysis_type,
            target=target,
            sha256=sha256,
            contributing_models=assessment.contributing_models,
            abstained_models=assessment.abstained_models,
            consensus_count=assessment.consensus_count,
            model_count=len(predictions),
            analysis_time_ms=elapsed_ms,
            request_id=request_id,
        )

    def _handle_file_threat(
        self,
        file_path: str,
        assessment: RiskAssessment,
        outcome: AnalysisOutcome,
        result: AnalysisResult,
        enforce: bool = False,
    ) -> None:
        """Emit THREAT_DETECTED and, when enforcing, quarantine + notify."""
        self.event_bus.publish(Event(
            event_type=EventType.THREAT_DETECTED,
            source="orchestrator",
            data={
                "file_path": file_path,
                "risk_score": assessment.risk_score,
                "risk_level": assessment.risk_level.value,
                "classification": outcome.classification,
                "recommendation": assessment.recommendation,
                "explanation": outcome.xai_explanation,
            },
        ))

        if enforce and self.quarantine_manager is not None:
            try:
                q = self.quarantine_manager.quarantine_file(
                    file_path=file_path,
                    threat_type="malware",
                    risk_score=float(assessment.risk_score),
                    explanation=outcome.xai_explanation,
                    detections={p.model_name: (p.evidence if isinstance(p.evidence, dict) else {})
                                for p in assessment.individual_predictions},
                    threat_name=outcome.classification,
                )
                result.quarantine = q
                self.event_bus.publish(Event(
                    event_type=EventType.THREAT_QUARANTINED,
                    source="orchestrator",
                    data={"file_path": file_path, "quarantine": q},
                ))
            except FileNotFoundError:
                logger.info("Quarantine skipped - file already gone: %s", file_path)
            except Exception as exc:
                logger.error("Quarantine failed for %s: %s", file_path, exc)

        if enforce and self.notifier is not None:
            try:
                from cybersentinel.notifications.desktop_notifications import NotificationPayload

                self.notifier.emit(NotificationPayload(
                    title="CyberSentinel - THREAT DETECTED",
                    message=f"{outcome.classification}: {file_path}",
                    file_path=file_path,
                    risk_level=assessment.risk_level.value.upper(),
                    reason=outcome.xai_explanation,
                    recommendation=assessment.recommendation.upper().replace("_", " "),
                    risk_percent=float(assessment.risk_score),
                ))
            except Exception as exc:
                logger.error("Notification failed: %s", exc)
    
    async def analyze_url(
        self,
        url: str,
        request_id: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze a URL for phishing threats.
        
        Args:
            url: URL to analyze
            request_id: Optional request ID (generated if not provided)
            
        Returns:
            AnalysisResult with risk assessment
        """
        start_time = time.time()

        if request_id is None:
            import uuid
            request_id = str(uuid.uuid4())

        self.event_bus.publish(Event(
            event_type=EventType.ANALYSIS_STARTED,
            source="orchestrator",
            data={"url": url, "request_id": request_id},
        ))

        try:
            predictions: List[ModelPrediction] = []
            for engine_name, engine in self.phishing_engines.items():
                try:
                    if hasattr(engine, "analyze_all"):
                        predictions.extend(await engine.analyze_all(url))
                    else:
                        prediction = await engine.analyze(url)
                        if prediction:
                            predictions.append(prediction)
                except Exception as e:
                    logger.error("Error in phishing engine %s: %s", engine_name, e)
                    predictions.append(ModelPrediction(
                        model_name=str(engine_name),
                        malicious_probability=0.0,
                        confidence=0.0,
                        reasoning=f"ANALYSIS FAILED - {e}",
                        evidence={"available": False, "analysis_status": "analysis_failed"},
                    ))

            if not predictions:
                predictions = [ModelPrediction(
                    model_name="orchestrator",
                    malicious_probability=0.0,
                    confidence=0.0,
                    reasoning="No phishing analyzer produced a result.",
                    evidence={"available": False, "analysis_status": "analysis_incomplete"},
                )]

            risk_assessment = self.risk_scorer.score(predictions)
            analysis_time_ms = (time.time() - start_time) * 1000
            xai = self.xai.explain_prediction(predictions)
            outcome = self._build_outcome(
                "url", url, risk_assessment, predictions,
                analysis_time_ms, request_id, xai,
            )

            result = AnalysisResult(
                request_id=request_id,
                risk_assessment=risk_assessment,
                analysis_time_ms=analysis_time_ms,
                outcome=outcome.to_dict(),
                xai=xai,
            )

            self.event_bus.publish(Event(
                event_type=EventType.ANALYSIS_COMPLETED,
                source="orchestrator",
                data={
                    "request_id": request_id,
                    "url": url,
                    "risk_score": risk_assessment.risk_score,
                    "risk_level": risk_assessment.risk_level.value,
                    "classification": outcome.classification,
                    "analysis_status": risk_assessment.analysis_status,
                },
            ))

            if risk_assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                self.event_bus.publish(Event(
                    event_type=EventType.THREAT_DETECTED,
                    source="orchestrator",
                    data={
                        "url": url,
                        "risk_score": risk_assessment.risk_score,
                        "classification": outcome.classification,
                        "recommendation": risk_assessment.recommendation,
                        "explanation": outcome.xai_explanation,
                    },
                ))

            return result

        except Exception as e:
            logger.error("URL analysis failed for %s: %s", url, e)
            self.event_bus.publish(Event(
                event_type=EventType.ANALYSIS_FAILED,
                source="orchestrator",
                data={"request_id": request_id, "error": str(e)},
            ))
            raise
    
    def start_protection(self) -> None:
        """Activate real-time threat protection."""
        self.protection_active = True
        event = Event(
            event_type=EventType.PROTECTION_STARTED,
            source="orchestrator"
        )
        self.event_bus.publish(event)
        logger.info("Protection started")
    
    def stop_protection(self) -> None:
        """Deactivate real-time threat protection."""
        self.protection_active = False
        event = Event(
            event_type=EventType.PROTECTION_STOPPED,
            source="orchestrator"
        )
        self.event_bus.publish(event)
        logger.info("Protection stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        return {
            "protection_active": self.protection_active,
            "malware_engines": list(self.malware_engines.keys()),
            "phishing_engines": list(self.phishing_engines.keys()),
            "behavioral_engines": list(self.behavioral_engines.keys()),
            "pending_analyses": len(self.pending_analyses),
            "database_stats": self.database.get_statistics(),
        }
    
    # Event handlers
    
    def _on_file_event(self, event: Event) -> None:
        """Handle file events (created, modified, downloaded)."""
        if not self.protection_active:
            return
        
        file_path = event.data.get("file_path")
        if file_path:
            # Would queue for analysis
            logger.debug(f"File event: {event.event_type.value} - {file_path}")
    
    def _on_url_event(self, event: Event) -> None:
        """Handle URL events (visited)."""
        if not self.protection_active:
            return
        
        url = event.data.get("url")
        if url:
            # Would queue for analysis
            logger.debug(f"URL event: {event.event_type.value} - {url}")
    
    def _on_protection_started(self, event: Event) -> None:
        """Handle protection started event."""
        logger.info("Protection started event received")
    
    def _on_protection_stopped(self, event: Event) -> None:
        """Handle protection stopped event."""
        logger.info("Protection stopped event received")
