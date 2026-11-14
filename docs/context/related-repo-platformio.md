# PlatformIO and library context

This document compares source configuration, not measured device behavior. The source snapshots are WiFi Canary `f6c437a`, Eye Spy `f5c2c7b`, and Flock You ESP32 `ea5dc188`. Recheck each repository before copying a setting.

The 2026-11-13 implementation adds configuration to the selected flash manifest, bundles ESP Web Tools 10.5.2, bounds serial lines, and validates staged images. The gap descriptions below remain the historical review baseline.

## WiFi Canary build baseline

| Item | Original `main` | Productization worktree |
| --- | --- | --- |
| Source | `esp32-wifi-canary/platformio.ini` | `platformio.ini` in this worktree |
| Framework | Arduino | Arduino for firmware, native Unity for core tests |
| Classic platform | `espressif32@^6.3.0` | `espressif32@^6.3.0` |
| Firmware environments | `atom-lite`, `esp32dev` | Original two plus `atom-echo`, `atom-voice`, `m5stack-basic`, `m5stack-core2-aws`, `m5stickc-plus-se`, experimental `lilygo-t-dongle-c5` |
| C5 platform | None | pioarduino release `55.03.311`, Arduino ESP32 `3.3.11` packages |
| Board definitions | Registry boards | Registry boards plus `boards/m5stickc-plus-se.json` and `boards/lilygo-t-dongle-c5.json` |
| Partitions | `partitions_4mb.csv` | `partitions_4mb.csv` with separate configuration and event-log regions |
| Direct libraries | Adafruit NeoPixel for Atom Lite | NeoPixel, M5Unified, or Adafruit ST7735/GFX by board |

The original source and requirements are in `esp32-wifi-canary/AGENTS.md:1-22` and `esp32-wifi-canary/platformio.ini:1-41`. The expanded environments are in this worktree's `platformio.ini:1-140`. PlatformIO documents one `[env:NAME]` per target, `lib_deps` per environment, custom `boards_dir`, and `board_build.partitions` for an ESP32 CSV table: https://github.com/platformio/platformio-docs/blob/develop/projectconf/sections/env/index.rst and https://github.com/platformio/platformio-docs/blob/develop/platforms/espressif32_extra.rst.

## Relevant patterns from Eye Spy and Flock You

| Pattern | Eye Spy source | Flock You source | WiFi Canary decision |
| --- | --- | --- | --- |
| Native tests beside board builds | `eye-spy/platformio.ini:18-32` | `flock-you-esp32/platformio.ini:22-33` | Keep the worktree's `native` environment and test pure detector logic. |
| Separate board environments | `eye-spy/platformio.ini:34-214` | `flock-you-esp32/platformio.ini:5-20,63-164,523-589` | Keep one firmware environment per hardware profile. Do not add BLE variants. |
| Shared board definitions | `eye-spy/boards/` | `flock-you-esp32/boards/` | Use custom JSON only when the PlatformIO registry lacks the exact board. |
| C5 toolchain | `eye-spy/platformio.ini:192-214` | `flock-you-esp32/platformio.ini:523-559` | Isolate C5 from classic ESP32 packages. Keep C5 experimental until radio and display checks pass on hardware. |
| Display libraries | `eye-spy/platformio.ini:6-16` | `flock-you-esp32/platformio.ini:544-547` | Load only libraries used by each Canary profile. |
| Firmware plus config flash parts | `eye-spy/docs/adr/0001-config-partition-and-flasher-configurator.md:22-27,37-60` | Flock You's browser installer in `flock-you-esp32/docs/index.html` | Add the Canary config image to the chosen manifest during install, after offset and erase behavior are checked. |

Eye Spy pins exact versions for its broader library set: NeoPixel `1.15.5`, M5Unified `0.2.19`, M5GFX `0.2.33`, ST7735/ST7789 `1.11.0`, GFX `1.12.6`, and BusIO `1.17.4` (`eye-spy/platformio.ini:6-16`). WiFi Canary currently uses NeoPixel `^1.15.1`, M5Unified `^0.2.2`, ST7735/ST7789 `^1.10.4`, and GFX `^1.11.9` (`platformio.ini:25-26,72-75,100-101,132-135`). Treat sibling versions as reviewed references, not automatic upgrades. Rebuild every Canary environment after any dependency change.

NimBLE appears in Eye Spy and Flock You for BLE detection. WiFi Canary has no BLE detector or BLE build variant. Do not copy NimBLE, BLE coexistence flags, signature tables, GPS dependencies, or active test-emitter firmware into its production environments.

## Flash layout and release inputs

WiFi Canary's productization table places the factory app at `0x10000`, configuration at `0x290000`, event log at `0x291000`, coredump at `0x2F0000`, and SPIFFS at `0x300000` (`partitions_4mb.csv:1-8`). The static installer manifests pair bootloader, partition table, and application binaries with board-specific offsets (`web/manifests/atom-lite.json`, `web/manifests/lilygo-t-dongle-c5.json`). CI copies binaries into `web/firmware/<environment>/` for a release artifact (`.github/workflows/build-firmware.yml:55-87`).

The browser now adds its 34-byte config image to the selected board's install manifest at `0x290000` (`web/app.js`, `web/install-manifest.js`). Eye Spy's configurator supplied the earlier reference for a client-side manifest with an additional config part (`eye-spy/docs/index.html:725-755`). Default settings are included when no custom values are selected.

The page now loads pinned ESP Web Tools files from `web/vendor/` for offline use (`web/index.html`). The Web Serial reader bounds each pending line and reports oversized input through `parser-error` (`web/serial-lines.js`, `web/app.js`).

The C5 custom board JSON declares 16 MB flash, while Canary currently selects `partitions_4mb.csv` (`boards/lilygo-t-dongle-c5.json`, `platformio.ini:124-140`). Eye Spy and Flock You also use C5-specific toolchains, but their partition choices and dual-band claims differ. Do not infer 5 GHz support or full-flash use from a successful build.
