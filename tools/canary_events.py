"""Parser for Travel WiFi Canary schema-versioned JSON Lines events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


EVENT_SCHEMA = 1
REQUIRED_FIELDS = {
    "schema",
    "device_id",
    "firmware",
    "board",
    "uptime_ms",
    "event",
    "detector",
    "score_delta",
    "score",
    "state",
    "reason",
    "ssid",
    "bssid",
    "channel",
    "rssi",
    "health",
}
REQUIRED_HEALTH_FIELDS = {
    "aps",
    "probes",
    "channel",
    "deauth_queue_drops",
    "pwnagotchi_queue_drops",
}


class EventError(ValueError):
    """Base class for event contract failures."""


class UnsupportedSchemaError(EventError):
    """Raised when firmware emits a newer schema than this parser understands."""


class InvalidEventError(EventError):
    """Raised when a JSON object does not satisfy the current event contract."""


@dataclass(frozen=True)
class ParsedEvent:
    raw: dict[str, Any]

    @property
    def device_id(self) -> str:
        return self.raw["device_id"]

    @property
    def event_type(self) -> str:
        return self.raw["event"]


def parse_event_line(line: str) -> ParsedEvent | None:
    """Parse one serial line.

    Human-readable firmware lines return None. JSON-looking lines must satisfy
    the schema or raise a contract error so consumers never drop events silently.
    """

    stripped = line.strip()
    if not stripped.startswith("{"):
        return None

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise InvalidEventError(f"invalid JSON event: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise InvalidEventError("event must be a JSON object")

    schema = payload.get("schema")
    if not isinstance(schema, int):
        raise InvalidEventError("event schema must be an integer")
    if schema > EVENT_SCHEMA:
        raise UnsupportedSchemaError(
            f"device event schema {schema} is newer than supported schema {EVENT_SCHEMA}"
        )
    if schema < 1:
        raise InvalidEventError(f"unsupported historical schema {schema}")

    missing = sorted(REQUIRED_FIELDS - payload.keys())
    if missing:
        raise InvalidEventError(f"missing required fields: {', '.join(missing)}")

    health = payload["health"]
    if not isinstance(health, dict):
        raise InvalidEventError("health must be a JSON object")
    missing_health = sorted(REQUIRED_HEALTH_FIELDS - health.keys())
    if missing_health:
        raise InvalidEventError(
            f"missing required health fields: {', '.join(missing_health)}"
        )

    if not isinstance(payload["device_id"], str) or not payload["device_id"]:
        raise InvalidEventError("device_id must be a non-empty string")
    if not isinstance(payload["event"], str) or not payload["event"]:
        raise InvalidEventError("event must be a non-empty string")
    if payload["state"] not in {"startup", "normal", "caution", "alert"}:
        raise InvalidEventError(f"invalid state: {payload['state']!r}")

    return ParsedEvent(payload)
