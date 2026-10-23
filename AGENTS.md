# Agent Instructions: Travel WiFi Canary

A passive 2.4 GHz WiFi awareness sensor for the M5Stack Atom Lite (ESP32-PICO). The whole firmware is one Arduino file, `main.cpp` (~1,070 lines), built with PlatformIO (`src_dir = .`).

## Build and verify
```bash
pio run -e atom-lite -e esp32dev     # build BOTH envs; report the real compiler output
pio run -e atom-lite -t upload       # only when a device is attached and the task says to flash
pio device monitor -b 115200
```
- `atom-lite` drives the SK6812 RGB LED on GPIO27 (Adafruit NeoPixel) and the button on GPIO39. `esp32dev` sets `-DDEVKIT_LED`, so the GPIO2 LED is on/off only and has no colour.
- The partition table is `partitions_4mb.csv`. Compiling is not the same as working: say whether a change was hardware-tested or only built.

## Detection engines (keep the README in sync with any change)
Pwnagotchi beacon, WiFi Pineapple OUI, probe-request flood, deauth/disassoc burst, open clone of a known encrypted SSID, original AP missing with the open clone present, security downgrade, duplicate SSID from an unexpected vendor, beacon/SSID flood. Each feeds confidence scoring, and the score drives the LED colour.
- **Passive only:** promiscuous receive. Never add transmit, deauth, or injection code.
- Tune thresholds with evidence (a serial log capture), and state the false-positive trade-off.
- No captured MACs, SSIDs or location data in commits.

## Related repos
`eye-spy` and `flock-you-esp32` share the same hardware and patterns, and their `.clinerules/` and `.agents/skills/` are the fuller reference for detection and firmware conventions.

## Git
Commit locally with conventional commits. Never push without the owner's approval.
