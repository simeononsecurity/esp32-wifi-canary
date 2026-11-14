import unittest
from provision import BOARDS, MAC_PATTERN


class ProvisionTests(unittest.TestCase):
    def test_mac_parser(self):
        self.assertEqual("aa:bb:cc:dd:ee:ff", MAC_PATTERN.search("MAC: aa:bb:cc:dd:ee:ff").group(1))

    def test_required_boards_are_available(self):
        self.assertIn("atom-lite", BOARDS)
        self.assertIn("lilygo-t-dongle-c5", BOARDS)


if __name__ == "__main__":
    unittest.main()
