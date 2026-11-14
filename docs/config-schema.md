# Configuration schema 1

The `canarycfg` partition starts at `0x290000`. The packed record is 34 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic `CANY` in little-endian storage |
| 4 | 2 | Version, 1 |
| 6 | 2 | Record size, 34 |
| 8 | 2 | Nine-engine enable mask |
| 10 | 1 | Sensitivity, low 0, standard 1, high 2 |
| 11 | 1 | Baseline scan count, 1 through 12 |
| 12 | 1 | LED brightness, 0 through 255 |
| 13 | 1 | Alert hold seconds, 3 through 120 |
| 14 | 1 | Output flags for light, display, audio, and haptic |
| 15 | 15 | Reserved, set to zero |
| 30 | 4 | IEEE CRC-32 over bytes 0 through 29 |

Validation failure loads compiled defaults and never blocks boot.
