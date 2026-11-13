# Quick start

## Browser install

1. Build each environment and run `python tools/assemble_release.py --stage <environment>` immediately after its build. Build the C5 separately with `PLATFORMIO_CORE_DIR=/tmp/wifi-canary-pio-c5 pio run -e lilygo-t-dongle-c5`, then stage it. After all eight, run `python tools/assemble_release.py`. Serve `release/web/` from localhost or HTTPS.
2. Open the page in a Chromium browser.
3. Select the exact board.
4. Set sensitivity and baseline scans. RGB boards also show brightness. Basic, Core2, and StickC show a display alert timer. Standard values match the original behavior.
5. Wait for the ready message, then connect the board over USB and start Install. The page checks the selected board's three firmware files and includes its 34-byte configuration in the flash.
6. Connect serial at 115200 baud. The console requests saved events, then asks you to press the device reset button. Confirm a new live boot event reports the selected board. Inspect state, score, baseline progress, detector meaning, and health. Export JSON or CSV locally. A readable `[canary] config=stored` line appears after reset.

The page works offline when served from the assembled release. Use a Chromium browser with Web Serial support. Browser flashing and physical boot still require checks on each device.

## Local build

```sh
pio test -e native
python -m unittest discover -s tools -p 'test_*.py'
node web/test.mjs
pio run -e atom-lite
```

Use the environment from `docs/hardware-matrix.md` for another board.

## Stored history

Send `dumplog` followed by Enter to replay boot and scored detection records. Send `clearlog` to erase history.
