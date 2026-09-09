"""Safe quarantine manager for CyberSentinel.

When a file is classified as HIGH or CRITICAL, it is moved into a quarantine
folder with metadata preserved. The original file is not deleted; it is isolated
and tracked separately so the rest of the local detection pipeline remains intact.
"""

from __future__ import annotations

import logging
import os
import stat as _stat
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any
import shutil
import uuid

from cybersentinel.common.database import ThreatDatabase, ThreatRecord, QuarantineRecord, compute_file_hash

logger = logging.getLogger(__name__)


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

    # -- lookup / safety --------------------------------------------------
    def _find_record(self, quarantine_id: str) -> QuarantineRecord:
        """Resolve a record by quarantine_id (also accepts hash or quarantine path)."""
        record = self.db.get_quarantine_by_hash(quarantine_id)
        if record is None:
            for r in self.db.get_quarantine_files(limit=10000):
                if r.quarantine_id == quarantine_id or r.quarantine_path == quarantine_id:
                    record = r
                    break
        if record is None:
            raise FileNotFoundError(f"No quarantine record for {quarantine_id!r}")
        return record

    def _resolved_payload_path(self, record: QuarantineRecord) -> Path:
        """Return the quarantined payload path, proven to sit inside quarantine_root.

        Blocks path traversal / symlink escapes: the resolved path MUST be a
        descendant of the resolved quarantine directory.
        """
        root = self.quarantine_root.resolve()
        qpath = Path(record.quarantine_path).resolve()
        try:
            qpath.relative_to(root)
        except ValueError:
            raise ValueError(
                f"Refusing to act on a path outside the quarantine directory: {qpath}"
            )
        return qpath

    # -- delete ---------------------------------------------------------
    def delete_file(self, quarantine_id: str, confirm: bool = False) -> Dict[str, Any]:
        """Permanently delete a quarantined payload after explicit user confirmation.

        Safety (spec part 19): verify the record, resolve the path, ensure it is
        inside the quarantine directory, drop the read-only bit, unlink exactly
        that file, verify it is gone, then update the database/log. On failure
        the real OS error is returned - deletion is never faked. Never recurses
        into directories; never deletes a caller-supplied raw path.
        """
        if not confirm:
            raise ValueError("delete_file requires confirm=True (explicit user action)")

        record = self._find_record(quarantine_id)
        qpath = self._resolved_payload_path(record)

        if qpath.is_dir():
            raise ValueError("Quarantine payload resolved to a directory - refusing to delete")

        if not qpath.exists():
            # Payload already gone - tidy the record and report honestly.
            self.db.remove_quarantine(record.quarantine_id)
            self.db.mark_threat_action(record.quarantine_id, "deleted (payload already absent)")
            return {
                "deleted": True,
                "quarantine_id": record.quarantine_id,
                "note": "payload was already absent; record removed",
            }

        try:
            os.chmod(qpath, _stat.S_IWRITE | _stat.S_IREAD)
        except OSError:
            pass

        try:
            qpath.unlink()
        except OSError as exc:
            logger.error("Quarantine delete failed for %s: %s", qpath, exc)
            return {
                "deleted": False,
                "quarantine_id": record.quarantine_id,
                "error": f"{exc.__class__.__name__}: {exc}",
                "errno": getattr(exc, "errno", None),
                "path": str(qpath),
            }

        if qpath.exists():  # verify
            return {
                "deleted": False,
                "quarantine_id": record.quarantine_id,
                "error": "unlink returned without error but the file still exists",
                "path": str(qpath),
            }

        self.db.remove_quarantine(record.quarantine_id)
        self.db.mark_threat_action(record.quarantine_id, "deleted")
        logger.warning("Quarantined payload permanently deleted: %s (%s)",
                       record.original_path, record.file_hash)
        return {
            "deleted": True,
            "quarantine_id": record.quarantine_id,
            "sha256": record.file_hash,
            "original_path": record.original_path,
        }

    # -- restore -------------------------------------------------------
    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> str:
        """Restore a quarantined file after an explicit user action.

        The stored SHA-256 is re-verified before the file is put back, and the
        payload must resolve to a location inside the quarantine directory.
        """
        record = self._find_record(quarantine_id)
        qpath = self._resolved_payload_path(record)
        if not qpath.exists():
            raise FileNotFoundError(f"Quarantined payload missing: {qpath}")

        try:
            os.chmod(qpath, _stat.S_IWRITE | _stat.S_IREAD)
        except OSError:
            pass

        current_hash = compute_file_hash(str(qpath))
        if record.file_hash and current_hash != record.file_hash:
            raise ValueError("Quarantined file hash changed - refusing to restore")

        target = Path(restore_path) if restore_path else Path(record.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(qpath), str(target))
        self.db.remove_quarantine(record.quarantine_id)
        self.db.mark_threat_action(record.quarantine_id, "restored")
        return str(target)
