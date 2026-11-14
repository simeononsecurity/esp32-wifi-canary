#!/usr/bin/env python3
"""Local, reconnecting multi-port collector for WiFi Canary JSON Lines."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import select
import threading
import time
from collections import deque
from pathlib import Path

try:
    from canary_events import parse_event_line
except ImportError:
    from tools.canary_events import parse_event_line


def discover_ports() -> list[str]:
    patterns = ("/dev/tty.usbserial-*", "/dev/tty.usbmodem*", "/dev/ttyACM*", "/dev/ttyUSB*")
    return sorted({port for pattern in patterns for port in glob.glob(pattern)})


class Collector:
    def __init__(self, limit: int = 10000):
        self.events = deque(maxlen=limit)
        self.lock = threading.Lock()

    def ingest(self, port: str, line: str):
        parsed = parse_event_line(line)
        if parsed is None:
            return None
        item = dict(parsed.raw)
        item["port"] = port
        item["received_at"] = time.time()
        with self.lock:
            self.events.append(item)
        return item

    def snapshot(self, device_id: str | None = None) -> list[dict]:
        with self.lock:
            values = list(self.events)
        return values if device_id is None else [e for e in values if e["device_id"] == device_id]

    def export_json(self, path: Path):
        path.write_text(json.dumps(self.snapshot(), indent=2) + "\n", encoding="utf-8")

    def export_csv(self, path: Path):
        rows = self.snapshot()
        fields = ["received_at", "port", "device_id", "firmware", "board", "uptime_ms", "event", "detector", "score", "state", "reason", "ssid", "bssid", "channel", "rssi"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)


class PortReader(threading.Thread):
    def __init__(self, port: str, collector: Collector, stop: threading.Event, retry: float = 0.25):
        super().__init__(daemon=True, name=f"canary:{port}")
        self.port, self.collector, self.stop, self.retry = port, collector, stop, retry

    def run(self):
        pending = b""
        while not self.stop.is_set():
            try:
                descriptor = os.open(self.port, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
                try:
                    while not self.stop.is_set():
                        ready, _, _ = select.select([descriptor], [], [], 0.1)
                        if not ready:
                            continue
                        chunk = os.read(descriptor, 4096)
                        if not chunk:
                            break
                        pending += chunk
                        lines = pending.split(b"\n")
                        pending = lines.pop()
                        for line in lines:
                            try:
                                item = self.collector.ingest(self.port, line.decode("utf-8", "replace"))
                                if item:
                                    print(f"{item['device_id']} {item['state']} {item['score']} {item.get('reason') or ''}", flush=True)
                            except ValueError as error:
                                print(f"{self.port}: {error}", flush=True)
                finally:
                    os.close(descriptor)
            except OSError:
                pass
            self.stop.wait(self.retry)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ports", nargs="*")
    parser.add_argument("--seconds", type=float, default=0, help="stop after N seconds")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--limit", type=int, default=10000)
    args = parser.parse_args()
    ports = args.ports or discover_ports()
    if not ports:
        parser.error("no serial ports found")
    collector, stop = Collector(args.limit), threading.Event()
    readers = [PortReader(port, collector, stop) for port in ports]
    for reader in readers:
        reader.start()
    try:
        stop.wait(args.seconds if args.seconds > 0 else None)
    except KeyboardInterrupt:
        pass
    stop.set()
    for reader in readers:
        reader.join(2)
    if args.json:
        collector.export_json(args.json)
    if args.csv:
        collector.export_csv(args.csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
