# Quick start

## Browser install

1. Serve `web/` from HTTPS or localhost.
2. Open the page in a Chromium browser.
3. Select the exact board.
4. Connect the board over USB.
5. Start Install.
6. Open the local dashboard at 115200 baud.

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
