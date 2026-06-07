# Travel WiFi Canary

A compact, passive 2.4 GHz WiFi awareness sensor for the **M5Stack Atom Lite** (ESP32).

Plug it in. It learns your environment. It watches quietly. The RGB LED tells you what it sees.

---

## What It Does

Monitors the 2.4 GHz WiFi environment and lights the RGB LED when it observes patterns
associated with common wireless threats: evil-twin access points, deauthentication attacks,
Pwnagotchi wardrivers, WiFi Pineapple hardware, security downgrades, and beacon floods.

It **does not**:
- Connect to any network
- Capture or store credentials
- Transmit any frames
- Perform deauthentication
- Decrypt or inspect traffic

It **does**:
- Passively scan nearby APs and build a local baseline
- Monitor 802.11 management frames for deauth/disassoc/probe/beacon activity
- Compare new scans against baseline to detect attack-tool signatures and evil-twin patterns
- Score detected signals with a confidence model to reduce false positives
- Express results on a single RGB LED

---

## LED Colors

| Color | Meaning |
|-------|---------|
| 🔵 Blue (slow pulse) | Startup — building baseline reference table |
| 🟢 Green (solid) | Normal — no high-confidence issues detected |
| 🟡 Yellow (solid) | Caution — suspicious pattern observed |
| 🔴 Red (fast pulse) | Alert — higher-confidence threat pattern detected |

Baseline learning takes ~24 seconds (3 scans × 8 s) before leaving the blue startup state.

---

## Detection Engines

### 1. Pwnagotchi Detector
Pwnagotchi wardriving devices broadcast 802.11 beacon frames from the hardcoded MAC
`de:ad:be:ef:de:ad`. The SSID carries a JSON payload with device name, version, networks
captured, and active attack policy. Parsed with a lightweight byte-search — no JSON library.

| Condition | Score |
|-----------|-------|
| Pwnagotchi detected, passive (deauth=false) | +2 → caution |
| Pwnagotchi detected, **deauth policy ON** | +4 → alert |

When `deauth=true`, the pwnagotchi is actively flooding deauthentication frames to disconnect
nearby clients and force handshake captures.

```
[canary] PWNAGOTCHI: name='pwn0' deauth=YES rssi=-62
[canary] PWNAGOTCHI ALERT: 'pwn0' is attacking (deauth=true) rssi=-62
```

---

### 2. WiFi Pineapple OUI Detector
Hak5 WiFi Pineapple devices use BSSIDs where bytes `[1]` and `[2]` are `0x13` and `0x37`
(the "1337" pattern). Checked against every AP found in each scan.

| Condition | Score |
|-----------|-------|
| Pineapple BSSID pattern detected | +4 → alert |

The 1337 OUI is not assigned to any legitimate device manufacturer.

```
[canary] PINEAPPLE ALERT: SSID='FreeAirport_WiFi' bssid=aa:13:37:xx:xx:xx rssi=-55
```

---

### 3. Probe Request Flood
Counts 802.11 probe request frames (management subtype 4) in promiscuous mode in a
10-second rolling window. A high-rate flood correlates with:
- Post-deauth client thrashing (clients frantically probing after being disconnected)
- Aggressive scanning tools (Pineapple, aircrack-ng, etc.)

| Condition | Score |
|-----------|-------|
| ≥ 40 probes / 10 s | +1 → caution |
| ≥ 80 probes / 10 s | +3 → alert |

Intentionally lower-scored because busy venues (airports, conferences) generate legitimate
probe noise. Most meaningful when combined with other signals.

---

### 4. Deauthentication / Disassociation Burst
Counts 802.11 deauth (subtype 12) and disassoc (subtype 10) frames per source in a 5-second
rolling window.

| Condition | Score |
|-----------|-------|
| ≥ 8 frames/window from same source | +2 → caution |
| ≥ 20 frames/window from same source | +4 → alert |
| ≥ 5 broadcast deauth frames | +1 |

A handful of deauth frames around a normal roam event will not trigger. Sustained bursts
from a single source — the signature of a deauth attack tool — will.

---

### 5. Open Clone of Known Encrypted Network
After baseline learning, if a previously WPA/WPA2/WPA3-only SSID appears as an open
(unencrypted) network — a classic evil-twin pattern.

| Condition | Score |
|-----------|-------|
| Same SSID, now OPEN, baseline was encrypted | +3 |
| BSSID not in baseline | +1 |
| Clone signal ≥ 10 dB stronger than known AP | +1 |

Max +5 on a fully loaded evil-twin → immediate red alert.

---

### 6. Original AP Missing + Open Clone Present
If a baseline encrypted AP disappears **and** a matching open AP appears in its place,
the real AP may have been pushed off-air by a stronger attacker clone.

| Condition | Score |
|-----------|-------|
| Original gone, open version present | +3 → alert |

---

### 7. Security Downgrade
Same SSID as a baseline AP but with weaker encryption observed.

| Condition | Score |
|-----------|-------|
| WPA3 → WPA2 or similar 1-rank drop | +1 |
| 2+ rank drop (e.g. WPA2 → WEP) | +3 |

Open downgrades are scored by detection engine 5 instead.

---

### 8. Duplicate SSID from Unexpected Vendor
Same SSID and same security as a baseline AP, but from a BSSID with a different vendor OUI
(first 3 bytes). Common in enterprise/mesh — intentionally scored low; useful as a
corroborating signal.

| Condition | Score |
|-----------|-------|
| Different vendor OUI | +1 |
| Also ≥ 10 dB stronger than known AP | +2 total |

---

### 9. Beacon / SSID Flood
Counts new SSIDs (not in baseline) within a 30-second rolling window.

| Condition | Score |
|-----------|-------|
| ≥ 15 new SSIDs / 30 s | +2 → caution |
| ≥ 30 new SSIDs / 30 s | +3 → alert |

---

## Confidence Scoring

All nine engines feed a single integer score. The LED state is driven by thresholds:

| Score | LED State |
|-------|-----------|
| 0–2 | Green (normal) |
| 3–5 | Yellow (caution) |
| 6+ | Red (alert) |

The score **decays by 1 point every 60 seconds** of quiet — the device self-resets if the
threat disappears without needing a reboot.

---

## Hardware

**Target:** M5Stack Atom Lite

| Component | Detail |
|-----------|--------|
| MCU | ESP32-PICO-D4 |
| LED | Single SK6812 RGB NeoPixel (GPIO 27) |
| Button | GPIO 39, active-low |
| USB | CP2104 → `/dev/tty.usbserial-*` on macOS |
| Power | USB-C, ~80–120 mA scanning |

No external components required.

---

## Building and Flashing

```bash
cd wifi-canary

# Flash to Atom Lite
pio run -e atom-lite --target upload

# Open serial monitor (115200 baud)
pio device monitor -b 115200
```

### Generic ESP32 DevKit (bench testing)

```bash
pio run -e esp32dev --target upload
```

DevKit build uses GPIO 2 (onboard LED, binary on/off). All detection logic is identical.

---

## Serial Output

```
================================
 Travel WiFi Canary v1.1
 Passive 2.4 GHz awareness
================================
[canary] setup done — starting baseline learning
[canary] baseline scan (aps=0 score=0)
[canary] scan found 18 APs
[canary] baseline scan 1/3
[canary] baseline scan (aps=18 score=0)
[canary] scan found 18 APs
[canary] baseline scan 2/3
[canary] baseline scan (aps=18 score=0)
[canary] scan found 19 APs
[canary] baseline complete: 19 APs
  [00] CoffeeShop_WiFi             aa:bb:cc:dd:ee:ff ch06 WPA2     -52 dBm
  [01] XFINITY                     11:22:33:44:55:66 ch01 WPA2     -71 dBm
  ...
[canary] STARTUP → NORMAL  (score=0  "")

[canary] normal scan (aps=19 score=0)
[canary] OPEN CLONE: SSID='CoffeeShop_WiFi' baseline=WPA2 clone=OPEN bssid=de:ad:be:ef:00:01 rssi=-48/-52
[canary] score +4 → 4  "open clone of encrypted SSID 'CoffeeShop_WiFi'"
[canary] NORMAL → CAUTION  (score=4  "open clone of encrypted SSID 'CoffeeShop_WiFi'")
```

---

## Button

Press the button (GPIO 39) to:
1. **Dump the full AP table** to serial
2. **Reset the threat score to 0** — useful for observing a fresh scan cycle

---

## Limitations

- **False positives possible.** Enterprise networks, mesh systems, and busy venues can
  partially match threat patterns. Confidence scoring reduces but does not eliminate this.
- **False negatives possible.** An attacker spoofing the exact known BSSID and matching
  signal strength may not score above threshold.
- **Deauth detection requires passive range.** Frames from a distant attacker may not reach
  the device.
- **2.4 GHz only.** 5 GHz and 6 GHz are not covered.
- **Scan gap.** The ESP32 radio switches between promiscuous and scan mode; deauth events
  during the ~3 s scan window will not be captured.

---

## Project Structure

```
wifi-canary/
├── main.cpp              # All firmware logic
├── platformio.ini        # Build environments (atom-lite, esp32dev)
├── partitions_4mb.csv    # 4MB flash partition table
└── README.md             # This file
```
