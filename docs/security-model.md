# Security model

Production firmware observes nearby WiFi management activity. It does not join an access point. It does not send telemetry. It does not include raw-frame transmission, deauthentication, beacon injection, or probe injection.

The browser dashboard uses Web Serial. Event data stays in browser memory until the user exports a file. Text enters the page through `textContent`, not HTML parsing. The page rejects unknown event schema versions.

The config and event-log partitions validate fixed layouts and CRC values. Invalid config data loads defaults. Invalid log records do not replay.

The detector exposes SSIDs, BSSIDs, signal strength, and observed attack context over USB serial. Treat exported data as sensitive local telemetry.

This repository has no selected software license. A maintainer decision is still required before redistribution terms are clear.
