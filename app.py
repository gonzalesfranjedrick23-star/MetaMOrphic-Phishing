"""Production-friendly local entry point for the CyberSentinel website."""

from __future__ import annotations

import argparse
import atexit
import logging
import os
import signal
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cybersentinel.web.api import (  # noqa: E402
    _start_analysis_workers,
    _stop_analysis_workers,
    app,
    file_monitor,
    orchestrator,
    malware_engine,
    phishing_engine,
    background_agent,
    notifier,
    quarantine_manager,
)


logger = logging.getLogger("cybersentinel.app")
_started = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start the CyberSentinel website and API")
    parser.add_argument("command", nargs="?", choices=["doctor"], help="Optional diagnostic command.")
    parser.add_argument("--host", default=os.getenv("CYBERSENTINEL_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CYBERSENTINEL_PORT", "5000")))
    parser.add_argument("--eicar", action="store_true", help="Trace the EICAR signature path in doctor mode.")
    parser.add_argument("--realtime", action="store_true", help="doctor: check the real-time surface.")
    parser.add_argument("--file", dest="file_path", help="doctor: trace a real file.")
    parser.add_argument("--url", dest="url", help="doctor: trace a URL.")
    return parser.parse_args()


def start_services() -> None:
    """Start realtime analysis exactly once for this process."""
    global _started
    if _started:
        return

    for directory in (ROOT / "uploads" / "temp", ROOT / "quarantine", ROOT / "monitored"):
        directory.mkdir(parents=True, exist_ok=True)

    _start_analysis_workers()
    orchestrator.start_protection()
    file_monitor.start()
    _started = True
    logger.info("Realtime protection started; monitored paths: %s", file_monitor.paths)


def stop_services() -> None:
    """Stop monitoring and background workers without raising during shutdown."""
    global _started
    if not _started:
        return
    file_monitor.stop()
    _stop_analysis_workers()
    orchestrator.stop_protection()
    _started = False


def _handle_shutdown(signum, _frame) -> None:
    logger.info("Shutdown signal received: %s", signum)
    stop_services()
    raise SystemExit(0)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args()
    if args.command == "doctor":
        from cybersentinel.doctor import run_doctor
        run_doctor(eicar=args.eicar, realtime=args.realtime,
                   file_path=args.file_path, url=args.url)
        return

    signal.signal(signal.SIGINT, _handle_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_shutdown)
    atexit.register(stop_services)
    start_services()
    logger.info("Website available at http://127.0.0.1:%s/", args.port)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
