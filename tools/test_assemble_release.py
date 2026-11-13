import struct
import tempfile
import unittest
from pathlib import Path

from assemble_release import PARTITIONS, validate_image_target, validate_partition_table


class ReleaseValidationTests(unittest.TestCase):
    def test_wrong_chip_rejected_for_bootloader_and_application(self):
        for board, expected in (("atom-lite", 0), ("lilygo-t-dongle-c5", 23)):
            for name in ("bootloader.bin", "firmware.bin"):
                with self.subTest(board=board, name=name), tempfile.TemporaryDirectory() as directory:
                    image = bytearray(24)
                    image[0] = 0xE9
                    struct.pack_into("<H", image, 12, expected)
                    path = Path(directory) / name
                    path.write_bytes(image)
                    validate_image_target(path, expected)
                    struct.pack_into("<H", image, 12, 23 if expected == 0 else 0)
                    path.write_bytes(image)
                    with self.assertRaisesRegex(ValueError, "image chip ID"):
                        validate_image_target(path, expected)

    def test_wrong_custom_partition_subtypes_rejected(self):
        fixture = bytearray()
        for name, (partition_type, subtype, offset, size) in PARTITIONS.items():
            fixture.extend(struct.pack("<HBBII16sI", 0x50AA, partition_type, subtype,
                                       offset, size, name.encode("ascii"), 0))
        for label in (b"canarycfg", b"canarylog"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                table = bytearray(fixture)
                path = Path(directory) / "partitions.bin"
                path.write_bytes(table)
                validate_partition_table(path)
                for position in range(0, len(table) - 31, 32):
                    if table[position + 12:position + 12 + len(label)] == label:
                        table[position + 3] = 0x42
                        break
                else:
                    self.fail(f"partition {label!r} missing from fixture")
                path.write_bytes(table)
                with self.assertRaisesRegex(ValueError, label.decode()):
                    validate_partition_table(path)


if __name__ == "__main__":
    unittest.main()
