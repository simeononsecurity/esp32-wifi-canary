import assert from "node:assert/strict";
import { parseCanaryLine, eventsToCsv } from "./event-parser.js";
import { buildConfig, crc32 } from "./config.js";
import { buildInstallManifest, CONFIG_OFFSET } from "./install-manifest.js";
import { readFileSync } from "node:fs";

const valid = JSON.stringify({schema:1,device_id:"abc",firmware:"1",board:"atom-lite",uptime_ms:4,event:"status",score:0,state:"normal",health:{}});
assert.equal(parseCanaryLine("plain log"), null);
assert.equal(parseCanaryLine(valid).device_id, "abc");
assert.throws(() => parseCanaryLine(valid.replace('"schema":1', '"schema":2')), /Unsupported/);
assert.throws(() => parseCanaryLine('{"schema":1}'), /Missing/);
assert.match(eventsToCsv([parseCanaryLine(valid)]), /device_id/);
const config = buildConfig();
assert.equal(config.length, 34);
assert.equal(new DataView(config.buffer).getUint32(30, true), crc32(config.subarray(0, 30)));
for (const values of [{baselineScans:0}, {baselineScans:13}, {ledBrightness:256}, {sensitivity:3}, {alertHoldSeconds:2}, {alertHoldSeconds:121}, {baselineScans:NaN}, {baselineScans:1.5}])
  assert.throws(() => buildConfig(values), RangeError);
for (const board of ["atom-lite", "esp32dev", "atom-echo", "atom-voice", "m5stack-basic", "m5stack-core2-aws", "m5stickc-plus-se", "lilygo-t-dongle-c5"]) {
  const base = JSON.parse(readFileSync(new URL(`./manifests/${board}.json`, import.meta.url)));
  const manifest = buildInstallManifest(base, `https://canary.example/web/manifests/${board}.json`, board, "blob:https://canary.example/config");
  assert.deepEqual(manifest.builds[0].parts.map(part => part.offset), [board === "lilygo-t-dongle-c5" ? 0x2000 : 0x1000, 0x8000, 0x10000, CONFIG_OFFSET]);
  assert.equal(manifest.builds[0].parts[2].path, `https://canary.example/web/firmware/${board}/firmware.bin`);
  assert.equal(manifest.builds[0].parts[3].path, "blob:https://canary.example/config");
  assert.throws(() => buildInstallManifest(base, `https://canary.example/web/manifests/${board}.json`, "other-board", "blob:https://canary.example/config"));
}
console.log("web parser and config tests passed");
