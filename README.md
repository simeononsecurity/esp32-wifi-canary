# Travel WiFi Canary

A compact, passive 2.4 GHz WiFi awareness sensor for the **M5Stack Atom Lite** (ESP32).

Plug it in. It learns your environment. It watches quietly. The RGB LED tells you what it sees.

---

## What It Does

The Travel WiFi Canary monitors the 2.4 GHz WiFi environment around you and lights up when it observes patterns associated with common wireless threats — evil-twin access points, deauthentication attacks, security downgrades, and beacon floods.

It **does not**:
- Connect to any network
- Capture or store credentials
- Transmit any frames
- Perform deauthentication
- Decrypt or inspect traffic

It **does**:
- Passively scan nearby access points and build a local baseline
- Monitor 802.11 management frames for deauth/disassoc activity
- Compare new scans against baseline to detect evil-twin and cloning patterns
- Score detected signals with a confidence model to reduce false positives
- Display results on a single RGB LED

---

## LED Colors

| Color | Meaning |
|-------|---------|
| 🔵 Blue (slow pulse) | Startup — building baseline reference table |
| 🟢 Green (solid) | Normal — no high-confidence issues detected |
| 🟡 Yellow (solid) | Caution — suspicious WiFi pattern observed |
| 🔴 Red (fast pulse) | Alert — higher-confidence threat pattern detected |

The device spends ~24 seconds learning your environment (3 scans × 8 seconds) before it can transition out of the blue startup state.

---

## What It Detects

### Deauthentication / Disassociation Bursts
Monitors 802.11 management frame subtypes 10 (disassoc) and 12 (deauth) in promiscuous mode. Counts frames per source within a 5-second rolling window.

- ≥ 8 frames/window → **Caution** (+2 points)
- ≥ 20 frames/window → **Alert** (+4 points)
- ≥ 5 broadcast deauth frames → +1 point

A single deauth or a handful around a normal roam event will not trigger anything. Sustained bursts from a single source — the signature of a deauth attack tool — trigger the scoring.

### Open Clone of Known Encrypted Network (Evil Twin)
After baseline learning, if a previously WPA/WPA2/WPA3-only SSID suddenly appears as an open network:

- Same SSID, but `OPEN` where baseline was encrypted → **+3 points**
- BSSID not seen in baseline → **+1 point**
- Clone signal ≥ 10 dB stronger than known AP → **+1 point**

This is the highest-confidence detection. An open clone of a hotel or coffee shop SSID that is also stronger than the real AP is a textbook evil-twin setup.

### Original Encrypted AP Missing + Open Clone Present
If a baseline encrypted AP disappears from the scan and a matching open network appears in its place:

- **+3 points**

This covers scenarios where an attacker's stronger open clone causes clients to connect to it while the real AP is deauthed off the air.

### Security Downgrade
Same SSID as a baseline AP but observed with weaker encryption:

- WPA3 → WPA2: **+1 point**
- WPA2 → WPA: **+1 point**
- Any jump of 2+ strength ranks: **+3 points**

Open downgrades are handled separately as the "open clone" detection above.

### Duplicate SSID from Unexpected Vendor
Same SSID and same security type as a baseline AP, but from a BSSID with a different vendor OUI (first 3 bytes of MAC):

- Different OUI → **+1 point**
- Clone also ≥ 10 dB stronger → **+2 points**

This is intentionally low-scored because enterprise and mesh networks legitimately have multiple BSSIDs for the same SSID. It combines with other signals to push a score up.

### Beacon / SSID Flood
Counts new SSIDs (not seen in baseline) within a 30-second rolling window:

- ≥ 15 new SSIDs in 30 s → **Caution** (+2 points)
- ≥ 30 new SSIDs in 30 s → **Alert** (+3 points)

---

## Confidence Scoring

All detected signals feed into a single integer score. The LED state is driven by this score:

| Score | State |
|-------|-------|
| 0–2 | Normal (green) |
| 3–5 | Caution (yellow) |
| 6+ | Alert (red) |

The score **decays by 1 point every 60 seconds** without new events. This means:

- A brief deauth burst will trigger caution, then automatically return to green if the attack stops
- A sustained attack that continues to generate scoring events will hold the alert state
- The device self-resets without needing a reboot

---

## Hardware

**Primary target:** M5Stack Atom Lite

| Component | Detail |
|-----------|--------|
| MCU | ESP32-PICO-D4 |
| LED | Single SK6812 RGB NeoPixel (GPIO 27) |
| Button | GPIO 39, active-low |
| USB | CP2104 (appears as `/dev/tty.usbserial-*` on macOS) |
| Power | USB-C, ~80–120 mA scanning |

No external components required. The Atom Lite ships with everything needed.

---

## Building and Flashing

### Requirements

- [PlatformIO](https://platformio.org/) (CLI or VS Code extension)
- M5Stack Atom Lite connected via USB-C

### Build and flash

```bash
cd wifi-canary

# Flash to Atom Lite
pio run -e atom-lite --target upload

# Open serial monitor (115200 baud)
pio device monitor -b 115200
```

### Generic ESP32 DevKit (for testing)

```bash
pio run -e esp32dev --target upload
```

The DevKit build uses GPIO 2 (onboard LED) and outputs the full serial log. No NeoPixel is driven. All detection logic is identical.

---

## Serial Output

The device logs everything at 115200 baud. Example output:

```
==============================================
 Travel WiFi Canary v1.0
 Passive 2.4 GHz awareness sensor
==============================================
[canary] setup done — starting baseline learning
[canary] baseline scan start (aps=0 score=0)
[canary] scan found 18 APs
[canary] baseline scan 1/3
[canary] baseline scan start (aps=18 score=0)
[canary] scan found 18 APs
[canary] baseline scan 2/3
[canary] baseline scan start (aps=18 score=0)
[canary] scan found 19 APs
[canary] baseline complete: 19 APs learned
  [00] MyHomeWifi                    aa:bb:cc:dd:ee:ff ch06 WPA2     -52 dBm
  [01] XFINITY                       11:22:33:44:55:66 ch01 WPA2     -71 dBm
  ...
[canary] STARTUP → NORMAL  (score=0  "")

[canary] normal scan start (aps=19 score=0)
[canary] scan found 21 APs
[canary] OPEN CLONE: SSID='MyHomeWifi' baseline=WPA2 clone=OPEN bssid=de:ad:be:ef:00:01 rssi=-48/-52
[canary] score +4 → 4  "open clone of encrypted SSID 'MyHomeWifi'"
[canary] NORMAL → CAUTION  (score=4  "open clone of encrypted SSID 'MyHomeWifi'")
```

---

## Button

Press the button on the Atom Lite (GPIO 39) to:

1. **Dump the full AP table** to serial — useful for auditing what the device sees
2. **Reset the threat score to 0** — forces return to normal/green state so you can observe a fresh scan cycle

---

## Detection Notes and Limitations

The Travel WiFi Canary is an **awareness device**, not a forensic tool.

- **False positives are possible.** Enterprise networks, large venue deployments, Airbnb routers with multiple BSSIDs, and neighbor networks all generate conditions that partially match threat patterns. The confidence scoring reduces but does not eliminate false positives.
- **False negatives are possible.** A well-crafted attack that spoofs the exact known BSSID, matches security settings, and operates at identical signal strength may not score above threshold.
- **Deauth detection only works in passive range.** The device must be within receive range of the deauth frames. A distant or directional attacker may not be detected.
- **2.4 GHz only.** 5 GHz and 6 GHz networks are not scanned or monitored.
- **No ongoing promiscuous monitoring during scans.** The ESP32 WiFi radio switches between promiscuous mode (deauth monitoring) and scan mode (AP enumeration). Deauth events that occur during the ~3 second scan window will not be captured.

---

## Project Structure

```
wifi-canary/
├── main.cpp              # All firmware logic
├── platformio.ini        # Build environments (atom-lite, esp32dev)
├── partitions_4mb.csv    # 4MB flash partition table
└── README.md             # This file
```

---

## License

Passive awareness only. Not for offensive use.
