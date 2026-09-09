"""Safe quarantine manager for CyberSentinel.

When a file is classified as HIGH or CRITICAL, it is moved into a quarantine
folder with metadata preserved. The original file is not deleted; it is isolated
and tracked separately so the rest of the local detection pipeline remains intact.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any
import shutil
import uuid

from cybersentinel.common.database import ThreatDatabase, ThreatRecord, QuarantineRecord, compute_file_hash


class QuarantineManager:
    """Move suspicious files into a safe quarantine directory and store metadata."""

    def __init__(self, quarantine_root: Optional[str] = None, db: Optional[ThreatDatabase] = None):
        self.quarantine_root = Path(quarantine_root) if quarantine_root else Path("./cybersentinel_quarantine")
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        self.db = db or ThreatDatabase(db_path="./cybersentinel_db")

    def quarantine_file(
        self,
        file_path: str,
        threat_type: str,
        risk_score: float,
        explanation: str,
        detections: Optional[Dict[str, Any]] = None,
        threat_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Move the file into quarantine and persist metadata."""
        source = Path(file_path)
        if not source.exists():
            raise FileNotFoundError(file_path)

        file_hash = compute_file_hash(str(source))
        original_size = source.stat().st_size
        quarantine_id = str(uuid.uuid4())
        # Trailing ".quarantine" neutralises accidental double-click execution;
        # the real extension is preserved in metadata for restore.
        quarantine_path = (
            self.quarantine_root
            / f"{source.stem}_{quarantine_id[:8]}{source.suffix}.quarantine"
        )

        shutil.move(str(source), str(quarantine_path))
        try:
            import os
            import stat as _stat
            os.chmod(quarantine_path, _stat.S_IREAD)  # read-only in quarantine
        except OSError:
            pass

        threat_record = ThreatRecord(
            record_id=quarantine_id,
            detection_time=datetime.utcnow(),
            threat_type=threat_type,
            file_path=str(source),
            file_hash=file_hash,
            risk_score=risk_score,
            risk_level="critical" if risk_score >= 80 else "high",
            detections=detections or {},
            explanation=explanation,
            action_taken="quarantined",
            quarantine_path=str(quarantine_path),
        )
        self.db.add_threat(threat_record)

        qrecord = QuarantineRecord(
            quarantine_id=quarantine_id,
            original_path=str(source),
            quarantine_path=str(quarantine_path),
            detection_time=threat_record.detection_time,
            file_hash=file_hash,
            file_size=original_size,
            threat_name=threat_name or "unknown",
            risk_score=risk_score,
            analysis_json={
                "threat_type": threat_type,
                "detections": detections or {},
                "explanation": explanation,
                "original_suffix": source.suffix,
            },
        )
        self.db.add_quarantine(qrecord)

        return {
            "quarantine_id": quarantine_id,
            "original_path": str(source),
            "quarantine_path": str(quarantine_path),
            "file_hash": file_hash,
            "risk_score": risk_score,
        }

    def list_quarantine(self) -> list:
        """Return quarantine records (most recent first)."""
        records = [r.to_dict() for r in self.db.get_quarantine_files(limit=1000)]
        records.reverse()
        return records

    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> str:
        """Restore a quarantined file after an explicit user action.

        Args:
            quarantine_id: the id returned by ``quarantine_file`` (also accepts a
                file hash or the quarantine path for convenience).
            restore_path: optional override; defaults to the recorded original path.

        The stored SHA-256 is re-verified before the file is put back.
        """
        record = self.db.get_quarantine_by_hash(quarantine_id)
        if record is None:
            for r in self.db.get_quarantine_files(limit=1000):
                if r.quarantine_id == quarantine_id or r.quarantine_path == quarantine_id:
                    record = r
                    break
        if record is None:
            raise FileNotFoundError(f"No quarantine record for {quarantine_id!r}")

        qpath = Path(record.quarantine_path)
        if not qpath.exists():
            raise FileNotFoundError(f"Quarantined payload missing: {qpath}")

        try:
            import os
            import stat as _stat
            os.chmod(qpath, _stat.S_IWRITE | _stat.S_IREAD)
        except OSError:
            pass

        current_hash = compute_file_hash(str(qpath))
        if record.file_hash and current_hash != record.file_hash:
            raise ValueError("Quarantined file hash changed - refusing to restore")

        target = Path(restore_path) if restore_path else Path(record.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(qpath), str(target))
        return str(target)
