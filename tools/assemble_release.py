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
    "nvs": (1, 2, 0x9000, 0x5000),
    "otadata": (1, 0, 0xE000, 0x2000),
    "app0": (0, 0, 0x10000, 0x280000),
    "canarycfg": (1, 0x40, CONFIG_OFFSET, 0x1000),
    "canarylog": (1, 0x41, 0x291000, 0x5F000),
    "coredump": (1, 3, 0x2F0000, 0x10000),
    "spiffs": (1, 0x82, 0x300000, 0x100000),
}


def validate_partition_table(path):
    data = path.read_bytes()
    entries = {}
    for position in range(0, len(data) - 31, 32):
        magic, partition_type, subtype, offset, size, label, _flags = struct.unpack_from(
            "<HBBII16sI", data, position
        )
        if magic != 0x50AA:
            break
        name = label.split(b"\0", 1)[0].decode("ascii")
        if name in entries:
            raise ValueError(f"{path}: duplicate partition {name}")
        entries[name] = (partition_type, subtype, offset, size)
    if len(entries) != len(PARTITIONS):
        raise ValueError(f"{path}: unexpected partition count")
    for name, expected in PARTITIONS.items():
        if entries.get(name) != expected:
            raise ValueError(f"{path}: {name} partition does not match {expected}")


def validate_image_target(path, expected_chip):
    image = path.read_bytes()
    if len(image) < 24 or image[0] != 0xE9:
        raise ValueError(f"{path}: invalid Espressif image header")
    chip_id = struct.unpack_from("<H", image, 12)[0]
    if chip_id != expected_chip:
        raise ValueError(f"{path}: image chip ID {chip_id} differs from {expected_chip}")


def firmware_sources():
    return sorted((ROOT / "boards").glob("*.json")) + sorted(ROOT.glob("canary_*.h")) + [
        ROOT / "main.cpp", ROOT / "platformio.ini", ROOT / "partitions_4mb.csv"
    ]


def source_digest():
    digest = hashlib.sha256()
    for path in firmware_sources():
        digest.update(str(path.relative_to(ROOT)).encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


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
        if name in ("bootloader.bin", "firmware.bin"):
            validate_image_target(source, 23 if c5 else 0)
        if name == "partitions.bin":
            validate_partition_table(source)
    return results


def stage_board(board):
    if board not in BOARDS:
        raise ValueError(f"unknown board: {board}")
    images = validate_board(board, ROOT / ".pio" / "build")
    newest_source = max(path.stat().st_mtime_ns for path in firmware_sources())
    firmware = ROOT / ".pio" / "build" / board / "firmware.bin"
    if firmware.stat().st_mtime_ns < newest_source:
        raise ValueError(f"{board}: firmware image predates current source")
    destination = STAGING / board
    destination.mkdir(parents=True, exist_ok=True)
    for source, name, _ in images:
        shutil.copy2(source, destination / name)
    (destination / "source.json").write_text(json.dumps({
        "source_sha256": source_digest(),
        "images": {name: digest for _, name, digest in images},
    }, sort_keys=True) + "\n")
    print(f"{board}: validated and staged input")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=BOARDS)
    args = parser.parse_args()
    if args.stage:
        stage_board(args.stage)
        return
    validated = {}
    current_source = source_digest()
    for board in BOARDS:
        images = validate_board(board, STAGING)
        metadata = json.loads((STAGING / board / "source.json").read_text())
        if metadata.get("source_sha256") != current_source or metadata.get("images") != {
            name: digest for _, name, digest in images
        }:
            raise ValueError(f"{board}: staged image does not match current source")
        validated[board] = images
    if RELEASE.exists():
        shutil.rmtree(RELEASE)
    shutil.copytree(ROOT / "web", RELEASE / "web", ignore=shutil.ignore_patterns("firmware"))
    for board, images in validated.items():
        for source, name, digest in images:
            for destination in (RELEASE / "firmware" / board / name,
                                RELEASE / "web" / "firmware" / board / name):
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
    checksums = []
    for path in sorted(RELEASE.rglob("*")):
        if path.is_file():
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(RELEASE)}")
    (RELEASE / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    for board in BOARDS:
        print(f"{board}: validated and staged")
    print(f"release: {RELEASE}")
    print(f"checksums: {len(checksums)} files")


if __name__ == "__main__":
    main()
