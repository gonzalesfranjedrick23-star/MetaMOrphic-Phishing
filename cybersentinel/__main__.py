"""Project-local CLI entry point for CyberSentinel.

    python -m cybersentinel doctor
    python -m cybersentinel doctor --realtime
    python -m cybersentinel doctor --eicar
    python -m cybersentinel doctor --file <path>
    python -m cybersentinel doctor --url <url>
    python -m cybersentinel agent  run | install | uninstall | start | stop | status
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberSentinel command-line tools")
    sub = parser.add_subparsers(dest="command")

    doc = sub.add_parser("doctor", help="Detection-engine health check")
    doc.add_argument("--realtime", action="store_true", help="Check the real-time protection surface")
    doc.add_argument("--eicar", action="store_true", help="Trace an EICAR scan end to end")
    doc.add_argument("--malware", action="store_true", help="(compat) core malware engine check")
    doc.add_argument("--file", dest="file_path", help="Trace a real file through the engine")
    doc.add_argument("--url", dest="url", help="Trace a URL through the phishing engine")

    ag = sub.add_parser("agent", help="Background malware-protection agent")
    ag.add_argument("action", nargs="?", default="run",
                    choices=["run", "install", "uninstall", "start", "stop", "status"])

    args = parser.parse_args(argv)

    if args.command == "doctor":
        from cybersentinel.doctor import run_doctor
        run_doctor(eicar=args.eicar, realtime=args.realtime or args.malware,
                   file_path=args.file_path, url=args.url)
        return 0

    if args.command == "agent":
        try:
            from cybersentinel.service.agent_cli import run_agent_command
        except ImportError:
            print("The background agent CLI is not available in this build yet.",
                  file=sys.stderr)
            return 2
        return run_agent_command(args.action)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
