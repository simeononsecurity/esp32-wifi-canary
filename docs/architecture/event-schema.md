# Serial event schema

WiFi Canary emits readable `[canary]` lines and one-line JSON event objects on the same 115200-baud serial stream. Consumers ignore non-JSON lines and validate every JSON object.

Schema 1 fields are:

| Field | Meaning |
| --- | --- |
| `schema` | Integer event contract version |
| `device_id` | Stable ESP32 eFuse MAC rendered as 12 hexadecimal characters |
| `firmware` | Firmware release identifier |
| `board` | PlatformIO hardware profile identifier |
| `uptime_ms` | Device uptime at event emission |
| `event` | `boot`, `detection`, `state`, `status`, `decay`, or `reset` |
| `detector` | Stable detector identifier, or null for non-detection events |
| `score_delta` | Signed score change caused by this event |
| `score` | Total score after the event |
| `state` | `startup`, `normal`, `caution`, or `alert` |
| `reason` | Human-readable event reason |
| `ssid` | Related SSID, or null |
| `bssid` | Related BSSID or source MAC, or null |
| `channel` | Related radio channel, or null |
| `rssi` | Related signal strength, or null |
| `health` | AP count, probes, channel, queue drops, scan duration, capture gaps, parser rejects, log losses, heap, reset reason, and current-channel frame count |

Boot and scored detection events also enter the CRC-protected `canarylog` flash ring. The `dumplog` command replays the same JSON objects through this contract.

Health includes `baseline_done`, `baseline_target`, and `baseline_learned`. The firmware emits a `baseline` event after each passive baseline scan. The log record is 1,024 bytes, with room for a complete JSON event and a CRC. Oversized records are rejected instead of truncated.

Adding an optional field does not require a schema increase. Renaming, removing, retyping, or changing the meaning of an existing field requires a schema increase and parser compatibility work. A consumer must reject newer schemas with a visible error instead of dropping records.

`tools/canary_events.py` is the reference host parser. `test/fixtures/events.jsonl` holds compatibility fixtures used in CI.
