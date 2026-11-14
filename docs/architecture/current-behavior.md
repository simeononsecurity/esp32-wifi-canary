# Current behavior baseline

This document freezes the v1.1 behavior before the product-delivery roadmap refactors firmware code.

## Product boundary

WiFi Canary is an offline 2.4 GHz WiFi threat-awareness sensor. Production firmware does not join an access point, host a network service, inspect credentials, decrypt traffic, or inject 802.11 frames. Flock, ALPR, camera, BLE tracker, drone, and skimmer detection remain outside scope.

The v1.1 scan call used `WiFi.scanNetworks(false, true)`. Arduino ESP32 defines the third argument as `passive`, with a default of `false`. The v1.1 call therefore requested active scanning and conflicted with the no-transmission statement. The roadmap changes this call to explicit passive scanning and keeps promiscuous collection receive-only.

## Detection engines and scores

| Engine | Caution evidence | Alert evidence |
| --- | --- | --- |
| Deauthentication or disassociation burst | 8 frames from one source in 5 seconds, +2 | 20 frames from one source in 5 seconds, +4 |
| Broadcast deauthentication | 5 frames in the source window, +1 | Combined evidence drives final state |
| Probe-request flood | 40 frames in 10 seconds, +1 | 80 frames in 10 seconds, +3 |
| Pwnagotchi | Passive policy, +2 | Deauthentication policy enabled, +4 |
| WiFi Pineapple BSSID pattern | None | Bytes 1 and 2 equal `13:37`, +4 |
| Open clone | Known encrypted SSID appears open, +3 | New BSSID adds +1, signal over 10 dB stronger adds +1 |
| Missing original with open clone | None | Missing encrypted baseline BSSID plus open SSID clone, +3 |
| Security downgrade | One rank, +1 | Two or more ranks, +3 |
| Duplicate SSID from another vendor | Different OUI, +1 | Signal over 10 dB stronger adds +1 |
| Beacon or SSID flood | 15 new SSIDs in 30 seconds, +2 | 30 new SSIDs in 30 seconds, +3 |

Score state thresholds are 0 through 2 normal, 3 through 5 caution, and 6 or higher alert. The score clamps at 20 and loses one point after each 60-second decay interval.

## Timing and radio behavior

The baseline uses three scans, scheduled eight seconds apart. Normal scans run every 20 seconds. Promiscuous collection hops channels 1, 6, and 11 every 300 milliseconds. Active scanning pauses promiscuous collection in v1.1. The roadmap replaces the scan with explicit passive scanning, though promiscuous collection still pauses while the scan API owns the radio.

Deauthentication source windows last five seconds. Probe windows last ten seconds. New-SSID windows last 30 seconds. Pwnagotchi state expires after 60 quiet seconds. Heartbeats print every 30 seconds.

## Fixed memory limits

The AP table holds 96 records. The deauthentication frame queue holds 64 entries with one slot reserved by ring-buffer full detection. Source aggregation tracks 24 transmitters. The Pwnagotchi queue holds four entries with one reserved slot. Its SSID snapshot holds 95 bytes plus a terminator. New-SSID tracking holds 64 names. SSIDs hold 32 bytes plus a terminator.

## Flash layout

| Partition | Offset | Size |
| --- | --- | --- |
| NVS | `0x9000` | `0x5000` |
| OTA data | `0xE000` | `0x2000` |
| Application | `0x10000` | `0x2E0000` |
| SPIFFS | `0x2F0000` | `0x100000` |

No persistent application data exists in v1.1.

## Build targets

`atom-lite` targets M5Stack Atom Lite with one SK6812 RGB LED on GPIO 27 and a button on GPIO 39. `esp32dev` targets a generic ESP32 DevKit with a binary LED on GPIO 2. Both use Arduino ESP32 through PlatformIO `espressif32@^6.3.0`.

## Serial contract before versioning

The serial stream uses the `[canary]` prefix. Lines report score changes, decay, state changes, scan results, individual detector evidence, a 30-second heartbeat, AP-table dumps, and button resets. No schema version, stable device ID, structured event envelope, or compatibility negotiation exists in v1.1.
