"""
Database: Persistent storage for threat detection results and history.

Stores:
- Threat detections
- Quarantine records
- Model performance metrics
- User feedback
- Configuration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional, Any
import json
import hashlib
from pathlib import Path


@dataclass
class ThreatRecord:
    """Record of a detected threat."""
    
    record_id: str                    # Unique identifier
    detection_time: datetime          # When detected
    threat_type: str                  # "malware" or "phishing"
    file_path: Optional[str] = None   # For malware
    url: Optional[str] = None         # For phishing
    file_hash: Optional[str] = None   # SHA-256 hash
    risk_score: float = 0.0           # 0-100
    risk_level: str = "unknown"       # safe, low, medium, high, critical
    
    # Detection details
    detections: Dict[str, Any] = None  # Per-model detections
    explanation: str = ""              # Why was it flagged
    
    # Actions taken
    action_taken: str = "detected"     # detected, warned, quarantined, allowed
    quarantine_path: Optional[str] = None
    
    # User feedback (if applicable)
    user_feedback: Optional[str] = None  # "false_positive", "true_positive", None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "record_id": self.record_id,
            "detection_time": self.detection_time.isoformat(),
            "threat_type": self.threat_type,
            "file_path": self.file_path,
            "url": self.url,
            "file_hash": self.file_hash,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "detections": self.detections or {},
            "explanation": self.explanation,
            "action_taken": self.action_taken,
            "quarantine_path": self.quarantine_path,
            "user_feedback": self.user_feedback,
        }


@dataclass
class QuarantineRecord:
    """Record of a quarantined file."""
    
    quarantine_id: str
    original_path: str
    quarantine_path: str
    detection_time: datetime
    file_hash: str
    file_size: int
    
    # Analysis results
    threat_name: Optional[str] = None
    risk_score: float = 0.0
    
    # Analysis data
    analysis_json: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "quarantine_id": self.quarantine_id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "detection_time": self.detection_time.isoformat(),
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "threat_name": self.threat_name,
            "risk_score": self.risk_score,
            "analysis_json": self.analysis_json or {},
        }


class ThreatDatabase:
    """
    Database for storing threat detection results.
    
    Can use JSON files for development/offline, or SQL for production.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database.
        
        Args:
            db_path: Path to store database files (default: ./cybersentinel_db)
        """
        self.db_path = Path(db_path) if db_path else Path("./cybersentinel_db")
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # JSON storage paths
        self.threats_file = self.db_path / "threats.jsonl"
        self.quarantine_file = self.db_path / "quarantine.jsonl"
        self.feedback_file = self.db_path / "feedback.jsonl"
        self.config_file = self.db_path / "config.json"
        
        # In-memory cache
        self._threats: List[ThreatRecord] = []
        self._quarantine: List[QuarantineRecord] = []
        self._feedback: List[Dict[str, Any]] = []
        
        self._load_from_disk()
    
    def add_threat(self, record: ThreatRecord) -> None:
        """Add a threat detection record."""
        self._threats.append(record)
        self._save_threats()
    
    def add_quarantine(self, record: QuarantineRecord) -> None:
        """Add a quarantine record."""
        self._quarantine.append(record)
        self._save_quarantine()
    
    def add_feedback(
        self,
        threat_record_id: str,
        feedback: str,
        user_notes: Optional[str] = None
    ) -> None:
        """
        Add user feedback on a detection.
        
        Args:
            threat_record_id: ID of threat record
            feedback: "true_positive", "false_positive", "unknown"
            user_notes: Optional user notes
        """
        feedback_record = {
            "threat_record_id": threat_record_id,
            "feedback": feedback,
            "user_notes": user_notes,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._feedback.append(feedback_record)
        self._save_feedback()
    
    def get_threats(
        self,
        threat_type: Optional[str] = None,
        limit: int = 100
    ) -> List[ThreatRecord]:
        """Get threat history."""
        threats = self._threats
        if threat_type:
            threats = [t for t in threats if t.threat_type == threat_type]
        return threats[-limit:]
    
    def get_quarantine_files(self, limit: int = 100) -> List[QuarantineRecord]:
        """Get quarantined files."""
        return self._quarantine[-limit:]
    
    def get_threat_by_hash(self, file_hash: str) -> Optional[ThreatRecord]:
        """Retrieve threat record by file hash."""
        for threat in self._threats:
            if threat.file_hash == file_hash:
                return threat
        return None
    
    def get_quarantine_by_hash(self, file_hash: str) -> Optional[QuarantineRecord]:
        """Retrieve quarantine record by file hash."""
        for qr in self._quarantine:
            if qr.file_hash == file_hash:
                return qr
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        threats_by_type = {}
        threats_by_level = {}
        
        for threat in self._threats:
            threats_by_type[threat.threat_type] = threats_by_type.get(threat.threat_type, 0) + 1
            threats_by_level[threat.risk_level] = threats_by_level.get(threat.risk_level, 0) + 1
        
        feedback_counts = {}
        for fb in self._feedback:
            fb_type = fb.get("feedback", "unknown")
            feedback_counts[fb_type] = feedback_counts.get(fb_type, 0) + 1
        
        return {
            "total_threats": len(self._threats),
            "threats_by_type": threats_by_type,
            "threats_by_level": threats_by_level,
            "quarantined_files": len(self._quarantine),
            "user_feedback": feedback_counts,
        }
    
    def remove_quarantine(self, quarantine_id: str) -> bool:
        """Remove a quarantine record (after the payload was restored/deleted).

        Rewrites the JSONL file so a later process does not resurrect the row.
        Returns True if a record was removed.
        """
        before = len(self._quarantine)
        self._quarantine = [q for q in self._quarantine if q.quarantine_id != quarantine_id]
        removed = len(self._quarantine) != before
        if removed:
            self._rewrite_quarantine()
        return removed

    def mark_threat_action(self, record_id: str, action: str) -> None:
        """Update the action_taken field of a stored threat record."""
        changed = False
        for t in self._threats:
            if t.record_id == record_id:
                t.action_taken = action
                changed = True
        if changed:
            self._rewrite_threats()

    def _load_from_disk(self) -> None:
        """Reconstruct records from the JSONL files (survives process restarts)."""
        if self.threats_file.exists():
            for line in self.threats_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    self._threats.append(self._threat_from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        if self.quarantine_file.exists():
            for line in self.quarantine_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    self._quarantine.append(self._quarantine_from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        if self.feedback_file.exists():
            for line in self.feedback_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip():
                    try:
                        self._feedback.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    @staticmethod
    def _threat_from_dict(data: Dict[str, Any]) -> "ThreatRecord":
        return ThreatRecord(
            record_id=data["record_id"],
            detection_time=datetime.fromisoformat(data["detection_time"]),
            threat_type=data.get("threat_type", "unknown"),
            file_path=data.get("file_path"),
            url=data.get("url"),
            file_hash=data.get("file_hash"),
            risk_score=data.get("risk_score", 0.0),
            risk_level=data.get("risk_level", "unknown"),
            detections=data.get("detections") or {},
            explanation=data.get("explanation", ""),
            action_taken=data.get("action_taken", "detected"),
            quarantine_path=data.get("quarantine_path"),
            user_feedback=data.get("user_feedback"),
        )

    @staticmethod
    def _quarantine_from_dict(data: Dict[str, Any]) -> "QuarantineRecord":
        return QuarantineRecord(
            quarantine_id=data["quarantine_id"],
            original_path=data["original_path"],
            quarantine_path=data["quarantine_path"],
            detection_time=datetime.fromisoformat(data["detection_time"]),
            file_hash=data["file_hash"],
            file_size=data.get("file_size", 0),
            threat_name=data.get("threat_name"),
            risk_score=data.get("risk_score", 0.0),
            analysis_json=data.get("analysis_json") or {},
        )

    def _save_threats(self) -> None:
        """Append the most recent threat record to disk."""
        with open(self.threats_file, 'a', encoding="utf-8") as f:
            if self._threats:
                f.write(json.dumps(self._threats[-1].to_dict()) + '\n')

    def _save_quarantine(self) -> None:
        """Append the most recent quarantine record to disk."""
        with open(self.quarantine_file, 'a', encoding="utf-8") as f:
            if self._quarantine:
                f.write(json.dumps(self._quarantine[-1].to_dict()) + '\n')

    def _rewrite_threats(self) -> None:
        tmp = self.threats_file.with_suffix(".jsonl.tmp")
        tmp.write_text("".join(json.dumps(t.to_dict()) + "\n" for t in self._threats), encoding="utf-8")
        tmp.replace(self.threats_file)

    def _rewrite_quarantine(self) -> None:
        tmp = self.quarantine_file.with_suffix(".jsonl.tmp")
        tmp.write_text("".join(json.dumps(q.to_dict()) + "\n" for q in self._quarantine), encoding="utf-8")
        tmp.replace(self.quarantine_file)
    
    def _save_feedback(self) -> None:
        """Save feedback records to disk."""
        with open(self.feedback_file, 'a') as f:
            if self._feedback:
                latest = self._feedback[-1]
                f.write(json.dumps(latest) + '\n')


def compute_file_hash(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
