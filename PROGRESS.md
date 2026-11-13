# Productization progress

## 2026-11-12, local implementation loop

- Compared `codex/wifi-canary-productization` with `main` and copied main's `AGENTS.md` into this worktree, updating its board flag to match the current profile.
- The selected board's browser manifest now includes a validated 34-byte configuration image at `0x290000`. Firmware paths resolve against the source manifest before the browser creates a Blob manifest. A standard install writes standard settings, so an earlier custom setting does not survive a reinstall.
- The browser blocks installation for missing or mismatched manifests and invalid settings. It keeps Atom Echo and Atom Voice as separate manifest choices.
- Focused checks: `node web/test.mjs` passed, including all eight manifest and config offset cases. PlatformIO native tests passed, 18 of 18. `atom-lite` and `esp32dev` builds passed using PlatformIO 6.2.0 in a temporary Python 3.14 environment. No device was flashed or checked physically.
- The installed Homebrew PlatformIO uses unsupported Python 3.15 and lacked `intelhex`; verification used `/private/tmp/canary-pio-venv` with Python 3.14 and `intelhex`.

Review findings for commit `5cb6e4d` are in the task report, keyed to its parent `64c2d5c`. The next change addresses the original Atom Lite LED pulse regression, C5 band scope, board-specific controls, firmware preflight, bounded Web Serial input, local installer packaging, release integrity, and console detail.

Verification for the review fix on 2026-11-13:

- `node web/test.mjs` passed, including eight board manifests, invalid configuration values, bounded serial lines, schema validation, and CSV formula escaping.
- `python3.14 -m unittest discover -s tools -p 'test_*.py'` passed, 9 of 9. The multi-port test needed `O_NOCTTY` to avoid a PTY hangup signal.
- `pio test -e native` passed, 18 of 18, in the temporary Python 3.14 PlatformIO environment.
- Seven classic ESP32 profiles built successfully. The experimental C5 profile built successfully with an isolated PlatformIO core. These are compile results, not physical-device results.
- Release assembly validated all eight manifest versions, chip families, image paths and offsets, generated partition entries, and image boundaries. All 48 staged firmware checksums passed `shasum -a 256 -c SHA256SUMS`.
- A rendered localhost check of the assembled page showed separate Echo and Voice choices, matching ready states, installer manifest refresh after setting changes, invalid-value install blocking, and no horizontal overflow at 473 pixels. The final console health panel rendered with no browser errors.
- No physical device was attached, flashed, booted, or used to confirm radio, LED, audio, display, haptic, button, or Web Serial behavior. C5 stays experimental. A WiFi Canary software license still needs the owner’s decision.

Review findings for commit `1152ee6` are in the task report, keyed to parent `5cb6e4d`. The follow-up fix separates saved and live boot events, keeps active flash Blob URLs alive, corrects negative numeric CSV export, checks stage freshness against current firmware source, and covers all release files with checksums. It also prevents repeated C5 scan-error output when the 2.4 GHz band lock fails.

Follow-up verification on 2026-11-13:

- `node web/test.mjs` passed. Python parser and monitor tests passed, 9 of 9. Native Unity tests passed, 18 of 18.
- A deliberate staging attempt with an older Atom Lite image failed with `firmware image predates current source`.
- Atom Lite, ESP32 DevKit, Atom Echo, Atom Voice, M5Stack Basic, Core2 for AWS, and M5StickC Plus SE builds passed. The isolated C5 build passed as experimental.
- Release assembly validated all eight source fingerprints and image layouts. `shasum -a 256 -c SHA256SUMS` passed for 92 files, including the browser page, manifests, bundled installer, and firmware images.
- Live boot confirmation still needs a device reset observed over USB. Saved boot records are labeled as history. No physical check occurred.


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
