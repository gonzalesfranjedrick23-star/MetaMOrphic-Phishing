"""Structured logging + Flask-independent status surface for the agent.

Part 23 - every real-time scan is logged with:
    timestamp, file, sha256, detected format, classification, risk, analysis
    status, evidence count, duration.
Never logs file contents, passwords, tokens, cookies or unrelated data.

Part 22 - a status snapshot the website (or any tool) can read from disk while
the background agent runs, without the website itself being open.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_MAX_LOG_BYTES = 5 * 1024 * 1024  # rotate at ~5 MB


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanLog:
    """Append-only JSONL scan log with size-based rotation."""

    def __init__(self, log_dir: str | Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / "agent_scans.jsonl"
        self._lock = threading.Lock()

    def record_file_scan(
        self,
        file_path: str,
        outcome: Dict[str, Any],
        duration_ms: float,
        action: str = "none",
    ) -> Dict[str, Any]:
        ev = outcome.get("evidence") or []
        fmt = "unknown"
        for item in ev:
            data = item.get("data") if isinstance(item, dict) else None
            if isinstance(data, dict) and data.get("magic"):
                fmt = data["magic"]
                break
        entry = {
            "ts": _now(),
            "kind": "file",
            "file": file_path,
            "sha256": outcome.get("sha256"),
            "format": fmt,
            "classification": outcome.get("classification"),
            "risk_percent": outcome.get("risk_percent"),
            "risk_level": outcome.get("risk_level"),
            "analysis_status": outcome.get("analysis_status"),
            "evidence_count": len(ev),
            "contributing": outcome.get("contributing_models"),
            "abstained": outcome.get("abstained_models"),
            "duration_ms": round(float(duration_ms), 1),
            "action": action,
        }
        self._append(entry)
        return entry

    def record_url_scan(self, url: str, outcome: Dict[str, Any], duration_ms: float) -> Dict[str, Any]:
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname or ""
        except Exception:
            domain = ""
        ev = outcome.get("evidence") or []
        entry = {
            "ts": _now(),
            "kind": "url",
            "url": url,
            "domain": domain,
            "classification": outcome.get("classification"),
            "risk_percent": outcome.get("risk_percent"),
            "risk_level": outcome.get("risk_level"),
            "analysis_status": outcome.get("analysis_status"),
            "evidence_count": len(ev),
            "duration_ms": round(float(duration_ms), 1),
        }
        self._append(entry)
        return entry

    def _append(self, entry: Dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size > _MAX_LOG_BYTES:
                    self.path.replace(self.path.with_suffix(".jsonl.1"))
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError as exc:
                logger.error("Could not write scan log: %s", exc)

    def tail(self, limit: int = 100) -> list:
        try:
            lines = self.path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


class StatusFile:
    """A small JSON snapshot the website reads without needing to be running."""

    def __init__(self, log_dir: str | Path):
        self.path = Path(log_dir) / "agent_status.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._counters = {"files_analyzed": 0, "threats_detected": 0, "quarantined": 0}
        self._last: Optional[Dict[str, Any]] = None

    def note_scan(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._counters["files_analyzed"] += 1
            if entry.get("classification") in ("MALICIOUS", "HIGH RISK", "PHISHING"):
                self._counters["threats_detected"] += 1
            if entry.get("action", "").startswith("quarantine"):
                self._counters["quarantined"] += 1
            self._last = entry

    def write(self, runtime_status: Dict[str, Any]) -> None:
        with self._lock:
            snapshot = {
                "ts": _now(),
                "malware_protection": "ACTIVE" if runtime_status.get("running") else "STOPPED",
                "file_monitor": runtime_status.get("watcher", "unknown"),
                "monitored_paths": runtime_status.get("paths", []),
                "files_analyzed": self._counters["files_analyzed"],
                "threats_detected": self._counters["threats_detected"],
                "quarantined": self._counters["quarantined"],
                "last_scan": self._last,
                "queue_depth": runtime_status.get("queue_depth", 0),
                "runtime": runtime_status,
            }
        try:
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            logger.error("Could not write status file: %s", exc)

    @staticmethod
    def read(log_dir: str | Path) -> Optional[Dict[str, Any]]:
        path = Path(log_dir) / "agent_status.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
