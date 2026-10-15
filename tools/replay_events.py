#!/usr/bin/env python3
"""Replay stored WiFi Canary JSON Lines through the production parser."""

import argparse
import json
import time
from pathlib import Path

from canary_events import parse_event_line


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--delay", type=float, default=0)
    args = parser.parse_args()
    for line in args.path.read_text(encoding="utf-8").splitlines():
        event = parse_event_line(line)
        if event is not None:
            print(json.dumps(event.raw, separators=(",", ":")), flush=True)
            if args.delay:
                time.sleep(args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
