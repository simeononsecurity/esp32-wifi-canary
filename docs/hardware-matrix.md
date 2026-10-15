# Hardware matrix

No listed board has a recorded live-device check in this branch. Each status below means source compilation only.

| PlatformIO environment | Chip | Light | Display | Audio | Haptic | Button | Status |
|---|---|---:|---:|---:|---:|---:|---|
| atom-lite | ESP32 | RGB | No | No | No | Yes | Build verified |
| esp32dev | ESP32 | GPIO 2 | No | No | No | No | Build verified |
| atom-echo | ESP32 | RGB | No | No | No | Yes | Build verified |
| atom-voice | ESP32 | RGB | No | Speaker | No | Yes | Build verified |
| m5stack-basic | ESP32 | No | Yes | Speaker | No | Yes | Build verified |
| m5stack-core2-aws | ESP32 | No | Yes | Speaker | Yes | Yes | Build verified |
| m5stickc-plus-se | ESP32 | No | Yes | Buzzer | No | Yes | Build verified |
| lilygo-t-dongle-c5 | ESP32-C5 | RGB | Yes | No | No | Yes | Experimental build verified |

The ESP32-C5 target does not have verified 5 GHz channel hopping or capture support. Current production channel selection stays on 1, 6, and 11.
