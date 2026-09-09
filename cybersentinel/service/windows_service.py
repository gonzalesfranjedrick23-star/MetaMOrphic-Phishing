"""Windows Service host for the standalone CyberSentinel background agent.

The module is intentionally safe to import: it never installs, starts, stops,
or removes a Windows Service as an import side effect. Those privileged actions
only occur through an explicit ``cybersentinel agent <action>`` command.
"""

from __future__ import annotations

import logging
import signal
import site
import sys
import threading
from pathlib import Path
from typing import Any, Dict

from cybersentinel.service.agent_runtime import AgentRuntime, project_root

logger = logging.getLogger(__name__)

SERVICE_NAME = "CyberSentinelAgent"
SERVICE_DISPLAY_NAME = "CyberSentinel Background Protection"
SERVICE_DESCRIPTION = (
    "Local CyberSentinel real-time malware protection for configured folders."
)

try:  # Keep non-Windows development/test imports safe.
    import servicemanager
    import win32service
    import win32serviceutil

    PYWIN32_AVAILABLE = True
except ImportError:  # pragma: no cover - Windows production dependency
    servicemanager = None  # type: ignore[assignment]
    win32service = None  # type: ignore[assignment]
    win32serviceutil = None  # type: ignore[assignment]
    PYWIN32_AVAILABLE = False


def _require_pywin32() -> None:
    if not PYWIN32_AVAILABLE:
        raise RuntimeError(
            "Windows Service support requires pywin32 and a Windows Python interpreter."
        )


if PYWIN32_AVAILABLE:

    class CyberSentinelWindowsService(win32serviceutil.ServiceFramework):
        """SCM host which owns the same AgentRuntime used by ``agent run``."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):  # type: ignore[no-untyped-def]
            super().__init__(args)
            self._stop_requested = threading.Event()
            self._runtime: AgentRuntime | None = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_requested.set()

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("CyberSentinel Windows Service starting")
            self._runtime = AgentRuntime()
            try:
                self._runtime.run_until_stopped(self._stop_requested)
            except Exception as exc:
                logger.exception("CyberSentinel Windows Service failed: %s", exc)
                servicemanager.LogErrorMsg(f"CyberSentinel Windows Service failed: {exc}")
                raise
            finally:
                servicemanager.LogInfoMsg("CyberSentinel Windows Service stopped")

else:

    class CyberSentinelWindowsService:  # pragma: no cover - import fallback only
        """Placeholder which gives a clear error on non-Windows installations."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME

        def __init__(self, *_args: Any, **_kwargs: Any):
            _require_pywin32()


def _ensure_project_import_path() -> Path:
    """Make the repository importable to the isolated ``pythonservice.exe`` host.

    pywin32 services start outside the repository directory. During explicit
    installation we place a one-line ``.pth`` file into *this interpreter's*
    site-packages, so the service uses the exact project the user installed.
    """
    root = project_root()
    candidates = [Path(path) for path in site.getsitepackages()]
    user_site = site.getusersitepackages()
    if user_site:
        candidates.append(Path(user_site))

    for directory in candidates:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            pth_file = directory / "cybersentinel_project.pth"
            pth_file.write_text(f"{root}\n", encoding="utf-8")
            return pth_file
        except OSError:
            continue
    raise RuntimeError("Unable to create the CyberSentinel service import-path file.")


def install_service() -> Dict[str, str]:
    """Install an auto-start service. Must be explicitly run as Administrator."""
    _require_pywin32()
    pth_file = _ensure_project_import_path()
    win32serviceutil.InstallService(
        f"{__name__}.CyberSentinelWindowsService",
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        startType=win32service.SERVICE_AUTO_START,
        description=SERVICE_DESCRIPTION,
        delayedstart=True,
    )
    return {
        "action": "installed",
        "service": SERVICE_NAME,
        "import_path": str(pth_file),
    }


def uninstall_service() -> Dict[str, str]:
    """Remove the service registration; it does not delete scans or quarantine."""
    _require_pywin32()
    win32serviceutil.RemoveService(SERVICE_NAME)
    return {"action": "uninstalled", "service": SERVICE_NAME}


def start_service() -> Dict[str, str]:
    """Ask the Windows Service Control Manager to start CyberSentinel."""
    _require_pywin32()
    win32serviceutil.StartService(SERVICE_NAME)
    return {"action": "start_requested", "service": SERVICE_NAME}


def stop_service() -> Dict[str, str]:
    """Ask the Windows Service Control Manager to stop CyberSentinel."""
    _require_pywin32()
    win32serviceutil.StopService(SERVICE_NAME)
    return {"action": "stop_requested", "service": SERVICE_NAME}


def get_service_status() -> Dict[str, Any]:
    """Read the SCM status without changing the system state."""
    _require_pywin32()
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
    except win32service.error as exc:
        # ERROR_SERVICE_DOES_NOT_EXIST is an ordinary pre-install state, not a
        # CLI failure. Keep other SCM failures (for example access denied)
        # visible to the caller.
        if getattr(exc, "winerror", None) == 1060 or (exc.args and exc.args[0] == 1060):
            return {"service": SERVICE_NAME, "state": "not_installed"}
        raise
    state = status[1]
    names = {
        win32service.SERVICE_STOPPED: "stopped",
        win32service.SERVICE_START_PENDING: "start_pending",
        win32service.SERVICE_STOP_PENDING: "stop_pending",
        win32service.SERVICE_RUNNING: "running",
        win32service.SERVICE_CONTINUE_PENDING: "continue_pending",
        win32service.SERVICE_PAUSE_PENDING: "pause_pending",
        win32service.SERVICE_PAUSED: "paused",
    }
    return {
        "service": SERVICE_NAME,
        "state": names.get(state, f"unknown({state})"),
        "win32_exit_code": status[3],
        "service_exit_code": status[4],
        "checkpoint": status[5],
        "wait_hint_ms": status[6],
    }


def run_foreground() -> int:
    """Run the agent in the current console until Ctrl+C, without SCM changes."""
    stop_requested = threading.Event()

    def request_stop(_signum, _frame) -> None:  # type: ignore[no-untyped-def]
        stop_requested.set()

    previous = signal.signal(signal.SIGINT, request_stop)
    try:
        AgentRuntime().run_until_stopped(stop_requested)
    except KeyboardInterrupt:
        stop_requested.set()
    finally:
        signal.signal(signal.SIGINT, previous)
    return 0


if __name__ == "__main__":  # Allows standard pywin32 debugging commands too.
    _require_pywin32()
    win32serviceutil.HandleCommandLine(CyberSentinelWindowsService)
