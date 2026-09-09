"""Stable, local file monitoring for CyberSentinel.

The monitor does not submit a file at the moment a browser or another process
creates it. Instead it waits until the file has remained unchanged for a
configurable number of checks. This prevents partial downloads and temporary
browser files from reaching the malware engine as completed user files.

``watchdog`` is used when available for efficient OS file events. A small
polling fallback preserves the same event contract on systems where watchdog
is not installed or cannot watch a requested directory.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event as StopEvent
from threading import Thread
from typing import Dict, Iterable, List, Optional, Tuple

from cybersentinel.common.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)

try:  # Optional at import time so the polling fallback remains usable.
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on dependency-free installs
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment,misc]
    WATCHDOG_AVAILABLE = False


@dataclass
class _PendingFile:
    """A file waiting for write/download stability before it is emitted."""

    event_type: EventType
    fingerprint: Optional[Tuple[int, int]] = None
    stable_checks: int = 0


class _WatchdogHandler(FileSystemEventHandler):
    """Translate watchdog callbacks into stable-monitor candidates."""

    def __init__(self, monitor: "FileMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event) -> None:  # type: ignore[no-untyped-def]
        if not event.is_directory:
            self.monitor._queue_candidate(Path(event.src_path), EventType.FILE_CREATED)

    def on_modified(self, event) -> None:  # type: ignore[no-untyped-def]
        if not event.is_directory:
            self.monitor._queue_candidate(Path(event.src_path), EventType.FILE_MODIFIED)

    def on_moved(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.is_directory:
            return
        source = Path(event.src_path)
        target = Path(event.dest_path)
        # A browser normally downloads to *.crdownload / *.part then renames
        # the completed payload. Mark that final transition explicitly.
        event_type = (
            EventType.FILE_DOWNLOADED
            if self.monitor.is_temporary_file(source)
            else EventType.FILE_CREATED
        )
        self.monitor._queue_candidate(target, event_type)


class FileMonitor:
    """Watch directory trees and emit only stable, completed file events.

    ``FILE_CREATED`` and ``FILE_MODIFIED`` are preserved for compatibility.
    A temporary-download rename emits ``FILE_DOWNLOADED``. Consumers should
    subscribe to all three events when they want real-time protection.
    """

    TEMPORARY_SUFFIXES = {
        ".crdownload", ".download", ".part", ".partial", ".tmp",
        ".opdownload", ".dmgpart",
    }
    TEMPORARY_PREFIXES = ("~$", ".~lock.")

    def __init__(
        self,
        paths: Optional[List[str]] = None,
        event_bus: Optional[EventBus] = None,
        poll_interval: float = 0.25,
        stability_checks: int = 2,
        debounce_seconds: float = 0.75,
        use_watchdog: bool = True,
    ):
        self.paths = [Path(p).expanduser() for p in (paths or ["."])]
        self.event_bus = event_bus or EventBus()
        self.poll_interval = max(0.02, float(poll_interval))
        self.stability_checks = max(1, int(stability_checks))
        self.debounce_seconds = max(0.0, float(debounce_seconds))
        self.use_watchdog = bool(use_watchdog)

        self._stop_event = StopEvent()
        self._thread: Optional[Thread] = None
        self._observer = None
        self._known_files: Dict[str, Tuple[int, int]] = {}
        self._pending: Dict[str, _PendingFile] = {}
        self._recently_emitted: Dict[str, Tuple[Tuple[int, int], float]] = {}
        self._lock = threading.RLock()
        self._using_watchdog = False

    @property
    def using_watchdog(self) -> bool:
        """Whether the active monitor uses watchdog rather than polling."""
        return self._using_watchdog

    def start(self) -> None:
        """Start the stable-event monitor exactly once."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._pending.clear()
        self._recently_emitted.clear()
        self._known_files = self._snapshot_files()
        self._using_watchdog = self._start_watchdog()
        self._thread = Thread(target=self._run, name="cybersentinel-file-monitor", daemon=True)
        self._thread.start()
        mode = "watchdog" if self._using_watchdog else "polling fallback"
        logger.info("File monitor started (%s): %s", mode, self.paths)

    def stop(self) -> None:
        """Stop all watcher threads without leaving a running observer behind."""
        self._stop_event.set()
        observer = self._observer
        self._observer = None
        self._using_watchdog = False
        if observer is not None:
            observer.stop()
            observer.join(timeout=2.0)
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._thread = None

    def is_temporary_file(self, path: Path | str) -> bool:
        """Return True for browser/editor temporary files that must not scan yet."""
        candidate = Path(path)
        name = candidate.name.lower()
        return (
            name.startswith(self.TEMPORARY_PREFIXES)
            or any(name.endswith(suffix) for suffix in self.TEMPORARY_SUFFIXES)
        )

    def _start_watchdog(self) -> bool:
        if not self.use_watchdog or not WATCHDOG_AVAILABLE:
            return False
        observer = Observer()
        handler = _WatchdogHandler(self)
        scheduled = False
        try:
            for base in self.paths:
                if base.exists() and base.is_dir():
                    observer.schedule(handler, str(base), recursive=True)
                    scheduled = True
            if not scheduled:
                return False
            observer.start()
            self._observer = observer
            return True
        except Exception as exc:  # a network/removable drive can reject watching
            logger.warning("Watchdog could not monitor requested paths; using polling: %s", exc)
            observer.stop()
            observer.join(timeout=1.0)
            return False

    def _run(self) -> None:
        while not self._stop_event.is_set():
            if not self._using_watchdog:
                self._poll_for_changes()
            self._flush_stable_candidates()
            self._stop_event.wait(self.poll_interval)

    def _poll_for_changes(self) -> None:
        current = self._snapshot_files()
        for path, fingerprint in current.items():
            previous = self._known_files.get(path)
            if previous is None:
                self._queue_candidate(Path(path), EventType.FILE_CREATED)
            elif previous != fingerprint:
                self._queue_candidate(Path(path), EventType.FILE_MODIFIED)
        self._known_files = current

    def _queue_candidate(self, path: Path, event_type: EventType) -> None:
        """Record an OS/poll event; publish only after stabilization."""
        if self.is_temporary_file(path):
            return
        try:
            if not path.is_file():
                return
            stat = path.stat()
            fingerprint = (stat.st_size, stat.st_mtime_ns)
        except OSError:
            return

        key = str(path.resolve())
        now = time.monotonic()
        with self._lock:
            recent = self._recently_emitted.get(key)
            if recent and recent[0] == fingerprint and now - recent[1] < self.debounce_seconds:
                return

            existing = self._pending.get(key)
            if existing is None:
                self._pending[key] = _PendingFile(event_type=event_type)
                return

            # Preserve the more informative event during a normal write:
            # creation and final download must not be downgraded to "modified".
            if existing.event_type == EventType.FILE_MODIFIED:
                existing.event_type = event_type
            elif event_type == EventType.FILE_DOWNLOADED:
                existing.event_type = event_type

    def _flush_stable_candidates(self) -> None:
        """Publish candidates that have stopped changing for enough checks."""
        ready: List[Tuple[str, EventType, Tuple[int, int]]] = []
        with self._lock:
            for key, pending in list(self._pending.items()):
                path = Path(key)
                try:
                    if self.is_temporary_file(path) or not path.is_file():
                        self._pending.pop(key, None)
                        continue
                    stat = path.stat()
                    fingerprint = (stat.st_size, stat.st_mtime_ns)
                except OSError:
                    self._pending.pop(key, None)
                    continue

                if fingerprint == pending.fingerprint:
                    pending.stable_checks += 1
                else:
                    pending.fingerprint = fingerprint
                    pending.stable_checks = 1

                if pending.stable_checks >= self.stability_checks:
                    ready.append((key, pending.event_type, fingerprint))
                    self._pending.pop(key, None)
                    self._recently_emitted[key] = (fingerprint, time.monotonic())

            cutoff = time.monotonic() - max(self.debounce_seconds * 2, 5.0)
            self._recently_emitted = {
                path: value for path, value in self._recently_emitted.items()
                if value[1] >= cutoff
            }

        for key, event_type, fingerprint in ready:
            self.event_bus.publish(Event(
                event_type=event_type,
                source="file_monitor",
                data={
                    "file_path": key,
                    "size": fingerprint[0],
                    "mtime_ns": fingerprint[1],
                    "stable": True,
                },
            ))

    def _snapshot_files(self) -> Dict[str, Tuple[int, int]]:
        files: Dict[str, Tuple[int, int]] = {}
        for base in self.paths:
            if not base.exists() or not base.is_dir():
                continue
            try:
                candidates: Iterable[Path] = base.rglob("*")
                for path in candidates:
                    if self.is_temporary_file(path) or not path.is_file():
                        continue
                    try:
                        stat = path.stat()
                        files[str(path.resolve())] = (stat.st_size, stat.st_mtime_ns)
                    except OSError:
                        continue
            except OSError:
                continue
        return files
