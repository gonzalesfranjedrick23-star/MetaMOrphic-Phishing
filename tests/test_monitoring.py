import tempfile
import time
from pathlib import Path

from cybersentinel.common.event_bus import EventBus, EventType
from cybersentinel.monitoring.monitor import FileMonitor


def test_file_monitor_emits_file_created_events():
    bus = EventBus()
    seen = []

    def on_event(event):
        seen.append(event.data.get("file_path"))

    bus.subscribe(EventType.FILE_CREATED, on_event)

    with tempfile.TemporaryDirectory() as d:
        monitor = FileMonitor(paths=[d], event_bus=bus, poll_interval=0.05)
        monitor.start()

        file_path = Path(d) / "demo.txt"
        file_path.write_text("hello", encoding="utf-8")

        time.sleep(0.25)
        monitor.stop()

        assert str(file_path) in seen
