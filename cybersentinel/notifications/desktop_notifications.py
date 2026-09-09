"""Desktop notification helper for CyberSentinel.

Local-only. Emits a real OS notification for high-risk detections so the
background agent can warn the user without any window being open. Falls back to
a structured log record when no notification backend is available.

Backends tried in order:
    1. plyer.notification            (cross-platform)
    2. PowerShell toast / balloon    (Windows, no extra deps)
    3. structured log record         (always works)
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NotificationPayload:
    """Safe local notification payload for a detection."""

    title: str = "CyberSentinel"
    message: str = "Threat detected"
    file_path: Optional[str] = None
    risk_level: str = "HIGH"
    reason: str = "Multiple detection layers identified suspicious characteristics."
    recommendation: str = "QUARANTINE"
    risk_percent: Optional[float] = None

    def to_dict(self) -> Dict[str, str]:
        return {
            "title": self.title,
            "message": self.message,
            "file_path": self.file_path or "",
            "risk_level": self.risk_level,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "risk_percent": "" if self.risk_percent is None else f"{self.risk_percent:.0f}",
        }

    def body_text(self) -> str:
        parts = []
        if self.file_path:
            parts.append(f"File: {self.file_path}")
        parts.append(f"Risk: {self.risk_level}")
        if self.risk_percent is not None:
            parts.append(f"Score: {self.risk_percent:.0f}%")
        if self.reason:
            parts.append(f"Why: {self.reason}")
        parts.append(f"Recommendation: {self.recommendation}")
        return "\n".join(parts)


class DesktopNotifier:
    """Local-only notifier. Never contacts a remote service."""

    def __init__(self, app_name: str = "CyberSentinel", enabled: bool = True):
        self.app_name = app_name
        self.enabled = enabled
        self.history: List[Dict[str, str]] = []
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        try:
            import plyer  # noqa: F401
            return "plyer"
        except Exception:
            pass
        if shutil.which("powershell"):
            return "powershell"
        return "log"

    def emit(self, payload: NotificationPayload) -> Dict[str, str]:
        record = payload.to_dict()
        record["backend"] = self._backend
        self.history.append(record)
        self.history[:] = self.history[-200:]

        if not self.enabled:
            record["delivered"] = "suppressed"
            return record

        body = payload.body_text()
        try:
            if self._backend == "plyer":
                from plyer import notification
                notification.notify(
                    title=payload.title,
                    message=body[:250],
                    app_name=self.app_name,
                    timeout=10,
                )
                record["delivered"] = "plyer"
            elif self._backend == "powershell":
                self._powershell_toast(payload.title, body)
                record["delivered"] = "powershell"
            else:
                logger.warning("CyberSentinel notification: %s | %s", payload.title, body)
                record["delivered"] = "log"
        except Exception as exc:  # never let a notification failure crash a scan
            logger.error("Notification delivery failed (%s): %s", self._backend, exc)
            logger.warning("CyberSentinel notification: %s | %s", payload.title, body)
            record["delivered"] = f"log (fallback: {exc})"
        return record

    def _powershell_toast(self, title: str, body: str) -> None:
        safe_title = title.replace("'", "''")
        safe_body = body.replace("'", "''")
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
            "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            f"$t.GetElementsByTagName('text')[0].AppendChild($t.CreateTextNode('{safe_title}')) > $null;"
            f"$t.GetElementsByTagName('text')[1].AppendChild($t.CreateTextNode('{safe_body}')) > $null;"
            "$n = [Windows.UI.Notifications.ToastNotification]::new($t);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('CyberSentinel').Show($n);"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=15, check=False,
        )
