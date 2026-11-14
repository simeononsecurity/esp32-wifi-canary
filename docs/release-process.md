# Release process

1. Run Python, browser, and native firmware tests.
2. Build every board environment.
3. Treat the ESP32-C5 target as experimental until live radio checks exist.
4. Stage each build with `python tools/assemble_release.py --stage <environment>` before building the next target. Use `PLATFORMIO_CORE_DIR=/tmp/wifi-canary-pio-c5 pio run -e lilygo-t-dongle-c5` for the C5 and stage it before switching toolchains. Run `python tools/assemble_release.py` after all eight. It rejects staged images from older source, then checks manifest version, chip family, binary paths, offsets, binary partition entries, and sizes. Verify every file in `release/SHA256SUMS` with `shasum -a 256 -c SHA256SUMS` from `release/`.
5. Serve `release/web/` locally and perform a rendered install-flow check. Confirm exact board selection, optional settings, firmware readiness, generated configuration, serial boot identity, and event display.
6. Flash available boards and record fresh boot, status, button, alert-output, `dumplog`, and `clearlog` evidence.
7. Confirm production source contains no frame-injection calls or unrelated detector engines.
8. Update the changelog and hardware matrix.
9. Create release artifacts only after required CI jobs pass.

Publishing, deployment, pushing, and choosing a software license need direct maintainer approval.
