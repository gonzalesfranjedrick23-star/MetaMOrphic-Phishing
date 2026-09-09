"""Runtime for the standalone CyberSentinel background agent.

This module deliberately does not import Flask. The foreground CLI and the
Windows Service host both use this exact runtime, so real-time protection keeps
working when the dashboard, an IDE, or a browser is closed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cybersentinel.common.event_bus import Event, EventBus, EventType
from cybersentinel.malware_engine.analyzer import MalwareEngine
from cybersentinel.monitoring.monitor import FileMonitor
from cybersentinel.notifications.desktop_notifications import DesktopNotifier
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.quarantine.manager import QuarantineManager
from cybersentinel.service.scan_log import ScanLog, StatusFile

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 100 * 1024 * 1024
QUEUE_LIMIT = 64


def project_root() -> Path:
    """Return the repository root, independent of the process working directory."""
    return Path(__file__).resolve().parents[2]


def configured_paths(value: Optional[str] = None) -> List[Path]:
    """Read local monitored paths from the explicit agent environment setting.

    ``CYBERSENTINEL_MONITORED_PATHS`` uses the platform path separator (``;``
    on Windows). This lets a Windows Service use administrator-configured paths
    rather than silently scanning arbitrary locations.
    """
    raw = value if value is not None else os.getenv("CYBERSENTINEL_MONITORED_PATHS", "")
    if raw.strip():
        paths = [Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip()]
    else:
        # Default user-approved locations (Part 3). Only folders that exist are
        # watched - no arbitrary system paths.
        home = Path.home()
        candidates = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            project_root() / "monitored",
        ]
        paths = [p for p in candidates if p == project_root() / "monitored" or p.exists()]

    # Preserve order but remove duplicate resolved locations.
    unique: List[Path] = []
    seen = set()
    for path in paths:
        normalized = str(path.resolve())
        if normalized not in seen:
            unique.append(path)
            seen.add(normalized)
    return unique


class AgentRuntime:
    """A queue-backed real-time scanner shared by CLI and Windows Service hosts."""

    def __init__(
        self,
        paths: Optional[Iterable[str | Path]] = None,
        *,
        poll_interval: float = 0.25,
        stability_checks: int = 2,
        max_file_size: int = MAX_FILE_SIZE,
    ):
        self.project_root = project_root()
        self.paths = [Path(path).expanduser() for path in paths] if paths is not None else configured_paths()
        self.poll_interval = poll_interval
        self.stability_checks = stability_checks
        self.max_file_size = max_file_size

        self.event_bus = EventBus()
        self.analysis_queue: queue.Queue[Optional[str]] = queue.Queue(maxsize=QUEUE_LIMIT)
        self.stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._in_progress: set[str] = set()
        self.metrics: Dict[str, Any] = {
            "completed": 0,
            "failed": 0,
            "dropped": 0,
            "last_successful_analysis": None,
        }

        self.orchestrator: Optional[ThreatOrchestrator] = None
        self.file_monitor: Optional[FileMonitor] = None
        self.quarantine_manager: Optional[QuarantineManager] = None
        self.notifier: Optional[DesktopNotifier] = None
        self._started = False

        self.log_dir = self.project_root / "logs"
        self.scan_log = ScanLog(self.log_dir)
        self.status_file = StatusFile(self.log_dir)

    def start(self) -> None:
        """Create the local detection stack and begin protected monitoring."""
        with self._lock:
            if self._started:
                return
            os.chdir(self.project_root)
            for path in self.paths:
                path.mkdir(parents=True, exist_ok=True)
            (self.project_root / "quarantine").mkdir(parents=True, exist_ok=True)

            self.quarantine_manager = QuarantineManager(
                quarantine_root=str(self.project_root / "quarantine")
            )
            self.notifier = DesktopNotifier()
            self.orchestrator = ThreatOrchestrator(
                event_bus=self.event_bus,
                quarantine_manager=self.quarantine_manager,
                notifier=self.notifier,
                auto_quarantine=True,
            )
            malware_engine = MalwareEngine()
            for index, analyzer in enumerate(malware_engine.analyzers, start=1):
                self.orchestrator.register_malware_engine(f"malware_layer_{index}", analyzer)

            self.file_monitor = FileMonitor(
                paths=[str(path) for path in self.paths],
                event_bus=self.event_bus,
                poll_interval=self.poll_interval,
                stability_checks=self.stability_checks,
            )
            for event_type in (EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DOWNLOADED):
                self.event_bus.subscribe(event_type, self._enqueue_file_event)

            self.stop_event.clear()
            self._worker = threading.Thread(
                target=self._analysis_worker,
                name="cybersentinel-agent-analysis",
                daemon=True,
            )
            self._worker.start()
            self.orchestrator.start_protection()
            self.file_monitor.start()
            self._started = True
            self.status_file.write(self.get_status())
            logger.info("CyberSentinel agent started; monitoring: %s", self.paths)

    def stop(self) -> None:
        """Stop monitoring and queue processing without deleting any file or data."""
        with self._lock:
            if not self._started:
                return
            self.stop_event.set()
            if self.file_monitor is not None:
                self.file_monitor.stop()
            if self.orchestrator is not None:
                self.orchestrator.stop_protection()
            try:
                self.analysis_queue.put_nowait(None)
            except queue.Full:
                # The worker wakes promptly from its timeout even if a sentinel
                # cannot be added behind a full queue.
                pass
            worker = self._worker
            self._started = False

        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=5.0)
        try:
            self.status_file.write(self.get_status())
        except Exception:  # never fail shutdown on a status write
            pass
        logger.info("CyberSentinel agent stopped")

    def run_until_stopped(self, external_stop: Optional[threading.Event] = None) -> None:
        """Run until a CLI interrupt or service-control event requests shutdown."""
        self.start()
        stop = external_stop or self.stop_event
        try:
            while not stop.wait(0.5):
                pass
        finally:
            self.stop()

    def get_status(self) -> Dict[str, Any]:
        """Return local process status without contacting a remote service."""
        with self._lock:
            return {
                "running": self._started,
                "paths": [str(path) for path in self.paths],
                "watcher": (
                    "watchdog" if self.file_monitor is not None and self.file_monitor.using_watchdog
                    else "polling"
                ),
                "queue_depth": self.analysis_queue.qsize(),
                "queue_limit": self.analysis_queue.maxsize,
                "items_in_progress": len(self._in_progress),
                **self.metrics,
            }

    def _enqueue_file_event(self, event: Event) -> None:
        """Validate and de-duplicate stable monitor events before analysis."""
        raw_path = (event.data or {}).get("file_path")
        if not raw_path:
            return
        try:
            path = Path(raw_path).resolve()
            if not self._is_in_monitored_paths(path) or not path.is_file():
                return
            if path.stat().st_size > self.max_file_size:
                logger.warning("Skipping oversized monitored file: %s", path)
                return
        except OSError:
            return

        key = str(path)
        with self._lock:
            if key in self._in_progress:
                return
            self._in_progress.add(key)
        try:
            self.analysis_queue.put_nowait(key)
        except queue.Full:
            with self._lock:
                self._in_progress.discard(key)
                self.metrics["dropped"] += 1
            logger.warning("Agent analysis queue is full; deferred file: %s", path)

    def _analysis_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                file_path = self.analysis_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                if file_path is None:
                    return
                if self.orchestrator is None:
                    raise RuntimeError("Agent orchestrator was not initialized")
                started = time.monotonic()
                result = asyncio.run(self.orchestrator.analyze_file(file_path, enforce=True))
                duration_ms = (time.monotonic() - started) * 1000.0
                with self._lock:
                    self.metrics["completed"] += 1
                    self.metrics["last_successful_analysis"] = datetime.now(timezone.utc).isoformat()
                self._record_scan(file_path, result, duration_ms)
            except Exception as exc:
                with self._lock:
                    self.metrics["failed"] += 1
                logger.exception("Background analysis failed for %s: %s", file_path, exc)
            finally:
                if file_path is not None:
                    with self._lock:
                        self._in_progress.discard(file_path)
                self.analysis_queue.task_done()

    def _record_scan(self, file_path: str, result: Any, duration_ms: float) -> None:
        """Write the structured scan-log line + refresh the status snapshot."""
        try:
            outcome = getattr(result, "outcome", None) or {}
            action = "quarantine" if getattr(result, "quarantine", None) else "none"
            entry = self.scan_log.record_file_scan(file_path, outcome, duration_ms, action)
            self.status_file.note_scan(entry)
            self.status_file.write(self.get_status())
        except Exception as exc:  # logging must never break protection
            logger.error("Scan-log write failed for %s: %s", file_path, exc)

    def _is_in_monitored_paths(self, path: Path) -> bool:
        for root in self.paths:
            try:
                path.relative_to(root.resolve())
                return True
            except ValueError:
                continue
        return False
