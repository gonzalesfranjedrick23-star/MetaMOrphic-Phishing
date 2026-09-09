"""Phase 2 regression coverage for the standalone protection agent."""

import os
import tempfile
from pathlib import Path

from cybersentinel.common.event_bus import EventBus, EventType
from cybersentinel.monitoring.monitor import FileMonitor
from cybersentinel.service.agent_cli import run_agent_command
from cybersentinel.service.agent_runtime import AgentRuntime, configured_paths
from cybersentinel.service.windows_service import (
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    CyberSentinelWindowsService,
)


def test_monitor_waits_for_stability_and_debounces_duplicate_events():
    bus = EventBus()
    seen = []
    bus.subscribe(EventType.FILE_CREATED, lambda event: seen.append(event))

    with tempfile.TemporaryDirectory() as directory:
        file_path = Path(directory) / "download.exe"
        file_path.write_bytes(b"completed payload")
        monitor = FileMonitor(
            paths=[directory],
            event_bus=bus,
            stability_checks=2,
            debounce_seconds=5.0,
            use_watchdog=False,
        )

        monitor._queue_candidate(file_path, EventType.FILE_CREATED)
        monitor._flush_stable_candidates()
        assert seen == []  # One unchanged observation is not enough.

        monitor._flush_stable_candidates()
        assert len(seen) == 1
        assert seen[0].data["stable"] is True
        assert seen[0].data["file_path"] == str(file_path.resolve())

        monitor._queue_candidate(file_path, EventType.FILE_MODIFIED)
        monitor._flush_stable_candidates()
        assert len(seen) == 1  # Same fingerprint inside debounce window.


def test_temporary_download_is_ignored_until_final_payload_is_stable():
    bus = EventBus()
    seen = []
    bus.subscribe(EventType.FILE_DOWNLOADED, lambda event: seen.append(event))

    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory) / "installer.exe.crdownload"
        final = Path(directory) / "installer.exe"
        temporary.write_bytes(b"partial")
        monitor = FileMonitor(
            paths=[directory], event_bus=bus, stability_checks=2, use_watchdog=False
        )

        monitor._queue_candidate(temporary, EventType.FILE_CREATED)
        monitor._flush_stable_candidates()
        monitor._flush_stable_candidates()
        assert seen == []

        temporary.rename(final)
        monitor._queue_candidate(final, EventType.FILE_DOWNLOADED)
        monitor._flush_stable_candidates()
        assert seen == []
        monitor._flush_stable_candidates()

        assert len(seen) == 1
        assert seen[0].data["file_path"] == str(final.resolve())


def test_agent_runtime_restricts_queue_inputs_to_monitored_paths():
    with tempfile.TemporaryDirectory() as monitored, tempfile.TemporaryDirectory() as outside:
        runtime = AgentRuntime(paths=[monitored])
        assert runtime._is_in_monitored_paths(Path(monitored) / "file.bin")
        assert not runtime._is_in_monitored_paths(Path(outside) / "file.bin")
        assert runtime.get_status()["running"] is False


def test_configured_paths_uses_explicit_path_separator(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_MONITORED_PATHS", os.pathsep.join(["C:/one", "C:/two", "C:/one"]))
    paths = configured_paths()
    assert [str(path) for path in paths] == [str(Path("C:/one")), str(Path("C:/two"))]


def test_windows_service_and_cli_surface_are_available_without_side_effects():
    assert SERVICE_NAME == "CyberSentinelAgent"
    assert "CyberSentinel" in SERVICE_DISPLAY_NAME
    assert CyberSentinelWindowsService._svc_name_ == SERVICE_NAME
    assert run_agent_command("not-an-action") == 2
