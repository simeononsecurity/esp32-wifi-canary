import assert from "node:assert/strict";
import { parseCanaryLine, eventsToCsv } from "./event-parser.js";
import { buildConfig, crc32 } from "./config.js";

const valid = JSON.stringify({schema:1,device_id:"abc",firmware:"1",board:"atom-lite",uptime_ms:4,event:"status",score:0,state:"normal",health:{}});
assert.equal(parseCanaryLine("plain log"), null);
assert.equal(parseCanaryLine(valid).device_id, "abc");
assert.throws(() => parseCanaryLine(valid.replace('"schema":1', '"schema":2')), /Unsupported/);
assert.throws(() => parseCanaryLine('{"schema":1}'), /Missing/);
assert.match(eventsToCsv([parseCanaryLine(valid)]), /device_id/);
const config = buildConfig();
assert.equal(config.length, 34);
assert.equal(new DataView(config.buffer).getUint32(30, true), crc32(config.subarray(0, 30)));
console.log("web parser and config tests passed");
