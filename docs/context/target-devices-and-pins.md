# Target devices, pins, and capabilities

The product remains an offline, passive 2.4 GHz WiFi awareness sensor. The eight current PlatformIO profiles are build targets, not eight hardware-verified products. The worktree hardware matrix records no live-device checks (`docs/hardware-matrix.md:1-16`). Keep the original Atom Lite experience as the reference behavior.

## Target order

| Priority | Product / environment | Reason | Release evidence needed |
| --- | --- | --- | --- |
| P0 | M5Stack Atom Lite / `atom-lite` | Original device with RGB LED and button | Build, boot, baseline, all LED states, button, passive radio capture, browser flash |
| P0 | Generic ESP32 DevKit / `esp32dev` | Original low-cost development target with GPIO LED | Build, boot, binary LED, serial events, passive radio capture, browser flash |
| P1 | M5Stack Atom Voice / `atom-voice` | Compact RGB, button, and onboard speaker | Build, board identity, LED, button, speaker, serial and flash |
| P1 | M5Stack Atom Echo / `atom-echo` | Separate product target with an existing light-only Canary profile | Build, board identity, LED, button, serial and flash |
| P1 | M5Stack Basic / `m5stack-basic` | Screen, speaker, and buttons for a self-contained view | Build, display, speaker, button, serial and flash |
| P1 | M5Stack Core2 for AWS / `m5stack-core2-aws` | Screen, speaker, touch button, and vibration | Build, display, sound, touch, haptic, serial and flash |
| P1 | M5StickC Plus SE / `m5stickc-plus-se` | Small screen, buzzer, and buttons | Build, display, buzzer, button, serial and flash |
| P2 experimental | LILYGO T-Dongle C5 / `lilygo-t-dongle-c5` | Small screen and RGB in a USB-C form factor | Build plus actual display, LED, button, flash, and 2.4 GHz passive capture checks |

The owner identifies Atom Echo and Atom Voice as separate products. Both accept compatible firmware. Keep separate product entries, board selections, support instructions, and validation results in WiFi Canary. Canary currently has separate `atom-echo` and `atom-voice` environments. The Echo profile enables RGB and button, while the Voice profile also enables onboard audio (`canary_board_profile.h:33-36`). Validate a shared binary on both devices before assigning one artifact to both flasher selections. Flock You's naming note in `flock-you-esp32/platformio.ini:63-75` does not define WiFi Canary's product catalog.

## Pin and output reference

| Profile | Light | Input | Display | Audio / haptic | Canary source |
| --- | --- | --- | --- | --- | --- |
| Atom Lite | SK6812 RGB, GPIO27 | Button, GPIO39 | None | None | `platformio.ini:14-34`, `canary_board.h:54-60,141-146` |
| ESP32 DevKit | GPIO2 binary LED | No configured button | None | None | `platformio.ini:36-52`, `canary_board.h:87-112,193-195` |
| Atom Echo | RGB, GPIO27 | Button, GPIO39 | None | No audio in this profile | `canary_board_profile.h:33-36`, `canary_board.h:54-60,141-146` |
| Atom Voice | RGB, GPIO27 | Button, GPIO39 | None | M5Unified onboard speaker | `canary_board.h:17-20,119-122,158-161` |
| M5Stack Basic | No separate RGB output | M5Unified BtnA | M5Unified display | M5Unified speaker | `canary_board.h:113-126,175-179,198-223` |
| Core2 for AWS | No separate RGB output | M5Unified BtnA / touch interface | M5Unified display | M5Unified speaker and Power vibration | `canary_board.h:119-125,158-170,175-179` |
| M5StickC Plus SE | No separate RGB output | M5Unified BtnA | M5Unified display | Buzzer, GPIO2 | `canary_board.h:113-132,162-165,175-179` |
| LILYGO T-Dongle C5 | WS2812B RGB, GPIO11 | BOOT button, GPIO9 | ST7735S: CS4, DC2, MOSI6, SCLK5, RST3, backlight1 | None | `canary_board.h:54-65,134-146,180-185` |

The ST7735 five-argument constructor order is `cs, dc, mosi, sclk, rst`. Canary's `Adafruit_ST7735(4, 2, 6, 5, 3)` therefore matches the named C5 pins in `eye-spy/src/c5_display.h:17-29` and `flock-you-esp32/c5_display.h:1-28`. The constructor signature is in the installed Adafruit library's `Adafruit_ST7735.h:54`. The pin assignment still needs a live C5 check.

Eye Spy records M5StickC Plus SE buttons A=GPIO37, B=GPIO39, buzzer GPIO2, and a separate active-low red LED on GPIO10 (`eye-spy/src/m5stickc_display.h:4-7,196-209`). Canary currently uses BtnA and the buzzer, but not the separate red LED. Eye Spy records M5Stack Basic buttons GPIO39/38/37 and speaker GPIO25 (`eye-spy/src/m5basic_display.h:4-8`). Canary delegates these outputs to M5Unified. Do not duplicate library-managed pin setup without checking the exact board revision.

## Library map

| Capability | Current direct library | Target profiles |
| --- | --- | --- |
| RGB pixel | `adafruit/Adafruit NeoPixel@^1.15.1` | Atom Lite, Atom Echo, Atom Voice, C5 |
| M5 display, speaker, button, power | `m5stack/M5Unified@^0.2.2` | Atom Voice, Basic, Core2 for AWS, M5StickC Plus SE |
| C5 TFT | `adafruit/Adafruit ST7735 and ST7789 Library@^1.10.4` and `adafruit/Adafruit GFX Library@^1.11.9` | C5 only |
| Core logic tests | PlatformIO native Unity environment | Host tests only |

Library declarations come from this worktree's `platformio.ini:5-140`. Framework-provided Arduino and ESP WiFi APIs are not extra `lib_deps`. M5Unified and Adafruit packages bring their own transitive dependencies. Do not add Eye Spy's NimBLE or its companion-server packages to WiFi Canary.

## Capability and validation rules

Show only supported controls in the browser. A DevKit has a binary LED, so brightness and color previews must not promise RGB behavior. Screen and sound controls belong only to matching boards. Retain the original Atom Lite LED and button behavior with standard settings. Keep any C5 5 GHz option absent until the receive path is demonstrated on a device. A compiled board profile only proves source compatibility.
