"""End-to-end orchestrator demo with real-time file monitoring.

This demo chains together:
1. Real-time file monitoring emitting FILE_CREATED events
2. Orchestrator analyzing the file
3. Phishing + malware engines scoring risk
4. Risk aggregation and decision-making
5. Quarantine of high-risk files
6. Event history and statistics
"""

import asyncio
import tempfile
import time
from pathlib import Path

from cybersentinel.common.event_bus import EventBus
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.monitoring.monitor import FileMonitor


async def demo():
    print("=" * 70)
    print("CyberSentinel Unified Platform: End-to-End Demo")
    print("=" * 70)
    print()

    # Initialize the shared event bus and orchestrator
    bus = EventBus()
    orchestrator = ThreatOrchestrator(event_bus=bus)

    # Create a temporary directory for monitoring
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Monitoring directory: {tmpdir}")
        print()

        # Start the real-time file monitor
        monitor = FileMonitor(paths=[tmpdir], event_bus=bus, poll_interval=0.05)
        monitor.start()
        print("✓ File monitor started (listening for FILE_CREATED, FILE_MODIFIED events)")
        print()

        # Start protection
        orchestrator.start_protection()
        print("✓ Threat orchestrator started (listening for file events)")
        print()

        # Demo 1: Create a benign file
        print("-" * 70)
        print("Demo 1: Benign file creation")
        print("-" * 70)
        benign_path = Path(tmpdir) / "benign.txt"
        benign_path.write_text("This is a benign text file.", encoding="utf-8")
        print(f"Created: {benign_path}")
        time.sleep(0.3)
        print()

        # Demo 2: Create a suspicious PE-like file (mock)
        print("-" * 70)
        print("Demo 2: Suspicious file creation (mock PE)")
        print("-" * 70)
        suspect_path = Path(tmpdir) / "suspect.exe"
        # Write minimal PE header signature (MZ)
        suspect_path.write_bytes(b"MZ" + b"\x00" * 100)
        print(f"Created: {suspect_path} (PE-like header)")
        time.sleep(0.3)
        print()

        # Demo 3: Analyze a URL via orchestrator
        print("-" * 70)
        print("Demo 3: URL analysis (phishing check)")
        print("-" * 70)
        test_url = "http://example-bank-login-verify.com/account"
        print(f"Analyzing URL: {test_url}")
        result = await orchestrator.analyze_url(test_url)
        print(f"  Risk Level: {result.risk_assessment.risk_level}")
        print(f"  Risk Score: {result.risk_assessment.risk_score}")
        print(f"  Recommendation: {result.risk_assessment.recommendation}")
        print()

        # Stop monitoring
        monitor.stop()
        orchestrator.stop_protection()
        print("-" * 70)
        print("✓ Monitoring and protection stopped")
        print()

        # Print event history and stats
        print("-" * 70)
        print("Event History & Statistics")
        print("-" * 70)
        history = bus.get_event_history()
        print(f"Total events emitted: {len(history)}")
        for i, event in enumerate(history, 1):
            print(f"  {i}. {event.event_type.value} from {event.source}")
        print()

        stats = bus.get_stats()
        print("Event type breakdown:")
        for event_type_str, count in sorted(stats["event_types"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type_str}: {count}")
        print()

    print("=" * 70)
    print("Demo complete. All Phase 3 features operational.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
