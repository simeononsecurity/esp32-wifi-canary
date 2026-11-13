# Quick start

## Browser install

1. Serve `web/` from HTTPS or localhost.
2. Open the page in a Chromium browser.
3. Select the exact board.
4. Set optional sensitivity, baseline, brightness, and alert hold values. Standard values match the original behavior.
5. Wait for the ready message, then connect the board over USB and start Install. The selected board's firmware and 34-byte configuration flash together.
6. Connect serial at 115200 baud. Confirm the boot event shows the selected board and the readable `[canary] config=stored` line appears. View local events in the dashboard.

The install button needs release binaries under `web/firmware/<board>/`. CI assembles this directory in the release artifact.

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
