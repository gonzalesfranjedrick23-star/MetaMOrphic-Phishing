"""CyberSentinel local background service controller.

Provides a lightweight, documented protection facade around the current
local FileMonitor + ThreatOrchestrator stack. It does not attempt to install
or hide a persistent system service in this repository. It represents the
local protection toggle and status model requested by the user while keeping
all normal system operations explicit and user-authored.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentStatus:
    """Simple local status model for protection-state inspection."""
    enabled: bool = False
    service_status: str = "stopped"
    monitor_status: str = "idle"
    queue_size: int = 0
    items_in_progress: int = 0
    completed: int = 0
    failed: int = 0
    dropped: int = 0
    recent_detections: int = 0
    last_successful_analysis: Optional[str] = None


class BackgroundAgent:
    """Local background protection façade for the current Flask event bus."""

    def __init__(self, orchestrator: Any, file_monitor: Any, analysis_queue: Any, metrics: Dict[str, int],
                 monitored_paths: Optional[List[str]] = None):
        self.orchestrator = orchestrator
        self.file_monitor = file_monitor
        self.analysis_queue = analysis_queue
        self.metrics = metrics
        self.monitored_paths = monitored_paths or ["./monitored"]
        self.lock = Lock()
        self._enabled = False
        self.status = AgentStatus()

    def enable(self) -> Dict[str, Any]:
        """Enable protection by starting the existing analysis and monitor flow."""
        with self.lock:
            self._enabled = True
            self.status.enabled = True
            self.status.service_status = "running"
            self.status.monitor_status = "running"
            if hasattr(self.orchestrator, "start_protection"):
                self.orchestrator.start_protection()
            if hasattr(self.file_monitor, "start"):
                self.file_monitor.start()
            logger.info("CyberSentinel protection enabled")
            return {"status": "enabled", "protection_active": True}

    def disable(self) -> Dict[str, Any]:
        """Disable protection cleanly without destructive behavior."""
        with self.lock:
            self._enabled = False
            self.status.enabled = False
            self.status.service_status = "stopped"
            self.status.monitor_status = "stopped"
            if hasattr(self.orchestrator, "stop_protection"):
                self.orchestrator.stop_protection()
            if hasattr(self.file_monitor, "stop"):
                self.file_monitor.stop()
            logger.info("CyberSentinel protection disabled")
            return {"status": "disabled", "protection_active": False}

    def replace_monitor(self, file_monitor: Any, monitored_paths: Optional[List[str]] = None) -> None:
        """Keep this facade aligned when the API replaces its monitor instance."""
        with self.lock:
            self.file_monitor = file_monitor
            if monitored_paths is not None:
                self.monitored_paths = monitored_paths

    def get_status(self) -> Dict[str, Any]:
        """Return a safe, human-readable, local status surface."""
        queue_size = self.analysis_queue.qsize() if hasattr(self.analysis_queue, "qsize") else 0
        with self.lock:
            self.status.queue_size = queue_size
            self.status.items_in_progress = len(getattr(self, "_in_progress", set()))
            self.status.completed = self.metrics.get("completed", 0)
            self.status.failed = self.metrics.get("failed", 0)
            self.status.dropped = self.metrics.get("dropped", 0)
            self.status.enabled = self.orchestrator.protection_active if hasattr(self.orchestrator, "protection_active") else self._enabled
            self.status.service_status = "running" if self.status.enabled else "stopped"
            self.status.monitor_status = "running" if self.status.enabled else "idle"
            return {
                "enabled": self.status.enabled,
                "service_status": self.status.service_status,
                "monitor_status": self.status.monitor_status,
                "queue_size": self.status.queue_size,
                "items_in_progress": self.status.items_in_progress,
                "completed": self.status.completed,
                "failed": self.status.failed,
                "dropped": self.status.dropped,
                "recent_detections": self.status.recent_detections,
                "last_successful_analysis": self.status.last_successful_analysis,
            }
