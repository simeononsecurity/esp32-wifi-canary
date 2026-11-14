#!/usr/bin/env python3
"""Flash one or more WiFi Canary units and verify each boot banner."""

from __future__ import annotations

import argparse
import glob
import re
import select
import subprocess
import os
import time

BOARDS = ("atom-lite", "esp32dev", "atom-echo", "atom-voice", "m5stack-basic", "m5stack-core2-aws", "m5stickc-plus-se", "lilygo-t-dongle-c5")
MAC_PATTERN = re.compile(r"MAC:\s*([0-9a-f:]{17})", re.I)


def ports() -> list[str]:
    patterns = ("/dev/tty.usbserial-*", "/dev/tty.usbmodem*", "/dev/ttyACM*", "/dev/ttyUSB*")
    return sorted({value for pattern in patterns for value in glob.glob(pattern)})


def read_mac(port: str) -> str:
    result = subprocess.run(["pio", "pkg", "exec", "--", "esptool.py", "--port", port, "read_mac"], text=True, capture_output=True, check=True)
    match = MAC_PATTERN.search(result.stdout + result.stderr)
    if not match:
        raise RuntimeError(f"no MAC returned for {port}")
    return match.group(1).lower()


def verify_boot(port: str, timeout: float = 12) -> bool:
    descriptor = os.open(port, os.O_RDONLY | os.O_NONBLOCK)
    try:
        deadline, data = time.time() + timeout, b""
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                data += os.read(descriptor, 4096)
                if b"[canary] event schema=" in data and b'"event":"boot"' in data:
                    return True
        return False
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--board", choices=BOARDS, required=True)
    parser.add_argument("--port", action="append", dest="selected_ports")
    parser.add_argument("--repeat", action="store_true", help="refresh port list after each unit")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    queue, seen = list(args.selected_ports or ports()), set()
    if not queue:
        parser.error("no serial ports found")
    while queue:
        port = queue.pop(0)
        mac = read_mac(port)
        if mac in seen:
            raise RuntimeError(f"duplicate device {mac} on {port}")
        seen.add(mac)
        if not args.yes and input(f"Flash {args.board} to {port}, MAC {mac}? [y/N] ").lower() != "y":
            continue
        subprocess.run(["pio", "run", "-e", args.board, "--target", "upload", "--upload-port", port], check=True)
        if not verify_boot(port):
            raise RuntimeError(f"boot verification failed on {port}")
        print(f"verified {mac} on {port}")
        if args.repeat and not queue:
            print("disconnect the verified unit and connect the next unit")
            while port in ports():
                time.sleep(0.5)
            while not queue:
                queue = ports()
                if not queue:
                    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
