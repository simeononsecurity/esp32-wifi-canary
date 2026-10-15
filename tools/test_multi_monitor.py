import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from multi_monitor import Collector, PortReader


def event(device, score):
    health = {"aps": 1, "probes": 0, "channel": 1, "deauth_queue_drops": 0, "pwnagotchi_queue_drops": 0}
    return json.dumps({"schema": 1, "device_id": device, "firmware": "1", "board": "test", "uptime_ms": 1, "event": "status", "detector": None, "score_delta": 0, "score": score, "state": "normal", "reason": "ok", "ssid": None, "bssid": None, "channel": 1, "rssi": -40, "health": health}).encode() + b"\n"


class MultiMonitorTests(unittest.TestCase):
    def test_two_simultaneous_streams_and_filters(self):
        collector, stop = Collector(), threading.Event()
        pairs = [os.openpty(), os.openpty()]
        readers = [PortReader(os.ttyname(slave), collector, stop, 0.02) for _, slave in pairs]
        for reader in readers:
            reader.start()
        time.sleep(0.05)
        os.write(pairs[0][0], event("unit-a", 1))
        os.write(pairs[1][0], event("unit-b", 2))
        deadline = time.time() + 2
        while len(collector.snapshot()) < 2 and time.time() < deadline:
            time.sleep(0.02)
        stop.set()
        for reader in readers:
            reader.join(1)
        self.assertEqual(2, len(collector.snapshot()))
        self.assertEqual(1, len(collector.snapshot("unit-a")))
        for master, slave in pairs:
            os.close(master); os.close(slave)

    def test_bounded_storage_and_exports(self):
        collector = Collector(2)
        for score in range(3):
            collector.ingest("test", event("unit", score).decode())
        self.assertEqual([1, 2], [item["score"] for item in collector.snapshot()])
        with tempfile.TemporaryDirectory() as directory:
            json_path, csv_path = Path(directory) / "events.json", Path(directory) / "events.csv"
            collector.export_json(json_path); collector.export_csv(csv_path)
            self.assertEqual(2, len(json.loads(json_path.read_text())))
            self.assertIn("device_id", csv_path.read_text())


if __name__ == "__main__":
    unittest.main()
