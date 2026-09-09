"""Explicit command dispatcher for the CyberSentinel background agent."""

from __future__ import annotations

import json
import sys
from typing import Callable, Dict


def run_agent_command(action: str) -> int:
    """Run a requested agent command and print a machine-readable result.

    Service-management actions are intentionally not implied by ``agent run``;
    install/start/stop/uninstall must each be requested by name.
    """
    from cybersentinel.service import windows_service

    commands: Dict[str, Callable[[], object]] = {
        "run": windows_service.run_foreground,
        "install": windows_service.install_service,
        "uninstall": windows_service.uninstall_service,
        "start": windows_service.start_service,
        "stop": windows_service.stop_service,
        "status": windows_service.get_service_status,
    }
    command = commands.get(action)
    if command is None:
        print(f"Unsupported agent action: {action}", file=sys.stderr)
        return 2
    try:
        result = command()
    except Exception as exc:
        print(f"CyberSentinel agent {action} failed: {exc}", file=sys.stderr)
        if action in {"install", "uninstall", "start", "stop"}:
            print("Run this command from an elevated Administrator terminal.", file=sys.stderr)
        return 1

    if isinstance(result, dict):
        print(json.dumps(result, indent=2, sort_keys=True))
    return int(result) if isinstance(result, int) else 0
