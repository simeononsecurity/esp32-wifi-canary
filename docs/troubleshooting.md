# Troubleshooting

## No serial port

Use a USB data cable. Check `/dev/tty.usbserial-*`, `/dev/tty.usbmodem*`, `/dev/ttyACM*`, or `/dev/ttyUSB*`.

## Baseline never finishes

Check JSON status events. A scan error appears in readable serial output. Stored configuration permits 1 through 12 baseline scans.

## Repeated alerts

Export JSON from the dashboard. Compare detector IDs, channels, RSSI, and queue drops. Select Low sensitivity only after reviewing the cause.

## Configuration ignored

The config image belongs at flash offset `0x290000`. Firmware rejects blank, truncated, corrupt, out-of-range, and newer-version blobs, then loads defaults.

## Dashboard does not connect

Use Chromium. Serve the page from HTTPS or localhost. Close other serial monitors first.

## Recovery erase

An erase removes saved configuration and event history. Reflash firmware after erasing.
