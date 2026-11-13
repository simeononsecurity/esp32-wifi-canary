"""Validate built images and assemble a local browser release directory."""

import hashlib
import json
import argparse
import re
import shutil
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release"
STAGING = ROOT / "release-input"
BOARDS = (
    "atom-lite", "esp32dev", "atom-echo", "atom-voice", "m5stack-basic",
    "m5stack-core2-aws", "m5stickc-plus-se", "lilygo-t-dongle-c5",
)
CONFIG_OFFSET = 0x290000
OFFSETS = (0x8000, 0x10000, CONFIG_OFFSET)
NAMES = ("bootloader.bin", "partitions.bin", "firmware.bin")
PARTITIONS = {
    "app0": (0x10000, 0x280000),
    "canarycfg": (CONFIG_OFFSET, 0x1000),
    "canarylog": (0x291000, 0x5F000),
}


def validate_partition_table(path):
    data = path.read_bytes()
    entries = {}
    for position in range(0, len(data) - 31, 32):
        magic, _type, _subtype, offset, size, label, _flags = struct.unpack_from(
            "<HBBII16sI", data, position
        )
        if magic != 0x50AA:
            break
        entries[label.split(b"\0", 1)[0].decode("ascii")] = (offset, size)
    for name, expected in PARTITIONS.items():
        if entries.get(name) != expected:
            raise ValueError(f"{path}: {name} partition does not match {expected}")


def validate_board(board, directory):
    manifest = json.loads((ROOT / "web" / "manifests" / f"{board}.json").read_text())
    firmware_version = re.search(r'kFirmwareVersion\s*=\s*"([^"]+)"',
                                 (ROOT / "canary_event.h").read_text())
    if not firmware_version or manifest.get("version") != firmware_version.group(1):
        raise ValueError(f"{board}: manifest version differs from firmware")
    if len(manifest.get("builds", [])) != 1:
        raise ValueError(f"{board}: expected one build")
    build = manifest["builds"][0]
    c5 = board == "lilygo-t-dongle-c5"
    if build.get("chipFamily") != ("ESP32-C5" if c5 else "ESP32"):
        raise ValueError(f"{board}: wrong chip family")
    parts = build.get("parts", [])
    if len(parts) != 3:
        raise ValueError(f"{board}: expected three firmware parts")
    boot_offset = 0x2000 if c5 else 0x1000
    results = []
    for index, name in enumerate(NAMES):
        part = parts[index]
        expected_path = f"../firmware/{board}/{name}"
        offset = (boot_offset, *OFFSETS[:2])[index]
        if part != {"path": expected_path, "offset": offset}:
            raise ValueError(f"{board}: wrong {name} manifest entry")
        source = directory / board / name
        if not source.is_file():
            raise FileNotFoundError(source)
        size = source.stat().st_size
        if size == 0 or size > OFFSETS[index] - offset:
            raise ValueError(f"{board}: {name} size {size} crosses next partition")
        results.append((source, name, hashlib.sha256(source.read_bytes()).hexdigest()))
        if name == "partitions.bin":
            validate_partition_table(source)
    return results


def stage_board(board):
    if board not in BOARDS:
        raise ValueError(f"unknown board: {board}")
    images = validate_board(board, ROOT / ".pio" / "build")
    destination = STAGING / board
    destination.mkdir(parents=True, exist_ok=True)
    for source, name, _ in images:
        shutil.copy2(source, destination / name)
    print(f"{board}: validated and staged input")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=BOARDS)
    args = parser.parse_args()
    if args.stage:
        stage_board(args.stage)
        return
    validated = {board: validate_board(board, STAGING) for board in BOARDS}
    if RELEASE.exists():
        shutil.rmtree(RELEASE)
    shutil.copytree(ROOT / "web", RELEASE / "web", ignore=shutil.ignore_patterns("firmware"))
    checksums = []
    for board, images in validated.items():
        for source, name, digest in images:
            for destination in (RELEASE / "firmware" / board / name,
                                RELEASE / "web" / "firmware" / board / name):
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                checksums.append(f"{digest}  {destination.relative_to(RELEASE)}")
    (RELEASE / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    for board in BOARDS:
        print(f"{board}: validated and staged")
    print(f"release: {RELEASE}")


if __name__ == "__main__":
    main()
