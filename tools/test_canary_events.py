import json
import unittest
from pathlib import Path

from canary_events import (
    InvalidEventError,
    UnsupportedSchemaError,
    parse_event_line,
)


FIXTURE = Path(__file__).resolve().parents[1] / "test" / "fixtures" / "events.jsonl"


class EventParserTests(unittest.TestCase):
    def load_events(self):
        return [
            parse_event_line(line)
            for line in FIXTURE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_fixture_events_parse(self):
        events = self.load_events()
        self.assertEqual(3, len(events))
        self.assertEqual(["boot", "detection", "status"], [e.event_type for e in events])
        self.assertEqual({"aabbccddeeff"}, {e.device_id for e in events})

    def test_human_line_is_ignored(self):
        self.assertIsNone(parse_event_line("[canary] score +4 -> 4"))

    def test_newer_schema_fails_loudly(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])
        payload["schema"] = 2
        with self.assertRaises(UnsupportedSchemaError):
            parse_event_line(json.dumps(payload))

    def test_missing_field_fails_loudly(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])
        del payload["device_id"]
        with self.assertRaisesRegex(InvalidEventError, "device_id"):
            parse_event_line(json.dumps(payload))

    def test_invalid_json_fails_loudly(self):
        with self.assertRaises(InvalidEventError):
            parse_event_line('{"schema":1')


if __name__ == "__main__":
    unittest.main()
