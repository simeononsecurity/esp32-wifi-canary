const SIZE = 34;
const MAGIC = 0x594e4143;

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (~crc) >>> 0;
}

export function buildConfig(values = {}) {
  const fields = {
    engineMask: [0, 0x1ff, 0x1ff],
    sensitivity: [0, 2, 1],
    baselineScans: [1, 12, 3],
    ledBrightness: [0, 255, 120],
    alertHoldSeconds: [3, 120, 15],
    outputFlags: [0, 15, 15]
  };
  for (const [name, [min, max]] of Object.entries(fields)) {
    const value = values[name] ?? fields[name][2];
    if (!Number.isInteger(value) || value < min || value > max)
      throw new RangeError(`Invalid ${name}`);
  }
  const bytes = new Uint8Array(SIZE);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, MAGIC, true);
  view.setUint16(4, 1, true);
  view.setUint16(6, SIZE, true);
  view.setUint16(8, values.engineMask ?? 0x1ff, true);
  view.setUint8(10, values.sensitivity ?? 1);
  view.setUint8(11, values.baselineScans ?? 3);
  view.setUint8(12, values.ledBrightness ?? 120);
  view.setUint8(13, values.alertHoldSeconds ?? 15);
  view.setUint8(14, values.outputFlags ?? 15);
  view.setUint32(30, crc32(bytes.subarray(0, 30)), true);
  return bytes;
}
