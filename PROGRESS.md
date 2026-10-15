# Productization progress

## 2026-10-14

Phases 0 through 3 are implemented on branch `codex/wifi-canary-productization` from commit `2d7a5bb`.

Evidence gathered:

- The starting worktree was clean.
- PlatformIO 6.1.19 and Node.js 26.10.0 are available.
- The pinned Arduino ESP32 API defines `scanNetworks(async, show_hidden, passive, max_ms_per_chan, channel)`. The existing two-argument call selects active scanning.
- `docs/architecture/current-behavior.md` records detection thresholds, timing, memory limits, partitions, build targets, and the pre-versioned serial surface.
- `canary_core.h` and native Unity tests begin behavior capture before firmware refactoring.
- Production AP scans now set the Arduino ESP32 `passive` argument to true.
- The firmware uses the host-tested core for frame parsing, bounded SSID extraction, queue math, thresholds, Pwnagotchi metadata, AP comparison, and state selection.
- Schema 1 JSON Lines events retain readable serial logs and add stable device identity, firmware, board, detector ID, score, state, radio context, and queue-drop health.
- `tools/canary_events.py` rejects invalid or newer events instead of dropping them silently.
- CI runs host parser tests, native firmware tests, both current board builds, and gated release-artifact assembly.
- Verification passed with 13 native Unity tests, 5 Python parser tests, `atom-lite`, and `esp32dev` builds.

Phases 4 through 10 are implemented in source and host tests.

- Eight capability profiles isolate light, display, audio, haptic, and button behavior.
- Every profile has compiled. The C5 profile uses a pinned pioarduino toolchain and stays experimental.
- A fixed 34-byte configuration record rejects blank, corrupt, truncated, newer, and invalid data.
- The static browser tool provides board manifests, install flow, config generation, Web Serial monitoring, and JSON or CSV export.
- A CRC-protected flash ring stores boot and scored detection events. `dumplog` and `clearlog` manage local history.
- Diagnostics report reset cause, heap, scan gaps, queue drops, parser rejects, log losses, and channel frame count.
- Host tooling covers two concurrent pseudo-terminal streams, bounded storage, filtering, reconnect loops, replay, and provisioning flow helpers.
- User, maintainer, security, schema, hardware, release, and troubleshooting docs now match build-tested behavior.

Remaining evidence limits:

- No physical board was attached. Every hardware profile is build verified only.
- The browser page still needs a rendered install-flow check with staged release binaries.
- ESP32-C5 5 GHz behavior is unverified and disabled by the current 2.4 GHz channel list.
- A software license still needs a maintainer decision.

Final verification on 2026-10-14:

- 18 native Unity cases passed.
- 9 Python parser, multi-unit, and provisioning cases passed.
- Browser parser and config-generation tests passed.
- Atom Lite, ESP32 DevKit, Atom Echo, Atom Voice, M5Stack Basic, Core2 for AWS, M5StickC Plus SE, and LILYGO T-Dongle C5 builds passed.
- The C5 build produced a 1,080,441-byte image with Arduino ESP32 3.3.11. CI isolates its PlatformIO package cache from classic ESP32 builds.
- Rendered browser checks passed at 473 and 1280 pixels with no horizontal overflow.
- Board selection changed the installer manifest. Config download produced the expected image.
- Workflow YAML, board JSON, manifest JSON, and `git diff --check` passed.
- Source scan found no access-point join call, AP mode, frame-transmit API, BLE engine, or unrelated detector implementation.
