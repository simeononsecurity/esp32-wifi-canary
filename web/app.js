import { parseCanaryLine, eventsToCsv, safeText } from "./event-parser.js";
import { buildConfig } from "./config.js";
import { buildInstallManifest } from "./install-manifest.js";
import { createSerialLines } from "./serial-lines.js";
import { explainDetector } from "./detectors.js";
import { createBootState } from "./boot-state.js";

const events = [];
const bootState = createBootState();
const byId = id => document.getElementById(id);
let port;
let reader;
let installUrls = [];
let installRevision = 0;
const MAX_INSTALL_MANIFESTS = 128;

function configValues() {
  const fields = ["baseline-scans", "brightness", "alert-hold"];
  for (const id of fields) {
    if (!byId(id).checkValidity() || byId(id).value.trim() === "")
      throw new RangeError(`Invalid ${id}`);
  }
  return {
    sensitivity: Number(byId("sensitivity").value),
    baselineScans: Number(byId("baseline-scans").value),
    ledBrightness: Number(byId("brightness").value),
    alertHoldSeconds: Number(byId("alert-hold").value)
  };
}

function updateBoardControls() {
  const board = byId("board-select").value;
  byId("brightness-field").hidden = !["atom-lite", "atom-echo", "atom-voice", "lilygo-t-dongle-c5"].includes(board);
  byId("alert-hold-field").hidden = !["m5stack-basic", "m5stack-core2-aws", "m5stickc-plus-se"].includes(board);
}

async function refreshInstall() {
  const revision = ++installRevision;
  const installer = byId("installer");
  installer.hidden = true;
  installer.removeAttribute("manifest");
  updateBoardControls();
  safeText(byId("install-status"), "Preparing firmware and settings");
  if (installUrls.length >= MAX_INSTALL_MANIFESTS * 2) {
    safeText(byId("install-status"), "Too many setting changes. Reload this page to prepare another install.");
    return;
  }
  let urls = [];
  try {
    const board = byId("board-select").value;
    const config = buildConfig(configValues());
    const manifestUrl = new URL(`./manifests/${board}.json`, location.href);
    const response = await fetch(manifestUrl);
    if (!response.ok) throw new Error(`Manifest unavailable: ${response.status}`);
    const base = await response.json();
    if (revision !== installRevision) return;
    const configUrl = URL.createObjectURL(new Blob([config], { type: "application/octet-stream" }));
    urls.push(configUrl);
    const manifest = buildInstallManifest(base, manifestUrl.href, board, configUrl);
    for (let index = 0; index < 3; index++) {
      const part = manifest.builds[0].parts[index];
      const result = await fetch(part.path);
      if (!result.ok) throw new Error(`Firmware unavailable: ${part.path.split("/").pop()} (${result.status})`);
      const bytes = await result.arrayBuffer();
      const nextOffset = manifest.builds[0].parts[index + 1].offset;
      if (!bytes.byteLength || bytes.byteLength > nextOffset - part.offset)
        throw new Error(`Firmware size is invalid: ${part.path.split("/").pop()}`);
      if (revision !== installRevision) return;
    }
    const manifestObjectUrl = URL.createObjectURL(new Blob([JSON.stringify(manifest)], { type: "application/json" }));
    urls.push(manifestObjectUrl);
    installer.setAttribute("manifest", manifestObjectUrl);
    installer.hidden = false;
    safeText(byId("install-status"), `Ready: ${byId("board-select").selectedOptions[0].text}. Firmware and settings flash together.`);
    installUrls.push(...urls);
    urls = [];
  } catch (error) {
    if (revision === installRevision) safeText(byId("install-status"), error.message);
  } finally {
    for (const url of urls) URL.revokeObjectURL(url);
  }
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function render(event) {
  events.push(event);
  if (events.length > 1000) events.shift();
  for (const field of ["device_id", "board", "state", "score", "reason", "ssid", "bssid", "channel", "rssi"])
    safeText(byId(field), event[field]);
  safeText(byId("drops"), (event.health.deauth_queue_drops || 0) + (event.health.pwnagotchi_queue_drops || 0));
  safeText(byId("detector-name"), event.detector || "None");
  safeText(byId("detector-explanation"), explainDetector(event.detector));
  const health = event.health;
  safeText(byId("baseline-progress"), health.baseline_target == null ? "Unknown" :
    health.baseline_learned ? `Complete (${health.baseline_done}/${health.baseline_target})` :
    `${health.baseline_done}/${health.baseline_target} scans`);
  for (const [id, key] of [["aps", "aps"], ["probes", "probes"],
    ["scan-duration", "scan_duration_ms"], ["capture-gap", "capture_gap_ms"],
    ["parser-rejects", "parser_rejects"], ["log-losses", "log_losses"],
    ["free-heap", "free_heap"], ["min-free-heap", "min_free_heap"],
    ["reset-reason", "reset_reason"], ["channel-frames", "channel_frames"]])
    safeText(byId(id), health[key]);
  const row = document.createElement("tr");
  for (const field of ["uptime_ms", "device_id", "event", "detector", "score", "reason"] ) {
    const cell = document.createElement("td");
    safeText(cell, event[field]);
    row.append(cell);
  }
  byId("events").prepend(row);
  while (byId("events").children.length > 200) byId("events").lastChild.remove();
}

async function connect() {
  if (!("serial" in navigator)) throw new Error("Web Serial needs Chromium on HTTPS or localhost");
  if (port) return;
  port = await navigator.serial.requestPort();
  try {
    await port.open({ baudRate: 115200 });
    byId("connect").disabled = true;
    byId("disconnect").disabled = false;
    safeText(byId("connection"), "Connected. Reading saved events.");
    safeText(byId("boot-status"), bootState.connect(byId("board-select").value));
    const serialLines = createSerialLines(line => {
      if (line === "[canary] replay complete") {
        safeText(byId("boot-status"), bootState.replayComplete());
        return;
      }
      try {
        const event = parseCanaryLine(line);
        if (event) {
          render(event);
          const bootStatus = bootState.event(event);
          if (bootStatus) safeText(byId("boot-status"), bootStatus);
        }
      } catch (error) { safeText(byId("parser-error"), error.message); }
    }, message => safeText(byId("parser-error"), message));
    reader = port.readable.getReader();
    const writer = port.writable.getWriter();
    try { await writer.write(new TextEncoder().encode("dumplog\n")); }
    finally { writer.releaseLock(); }
    const decoder = new TextDecoder();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      serialLines.push(decoder.decode(value, { stream: true }));
    }
  } finally {
    if (reader) { reader.releaseLock(); reader = undefined; }
    if (port) { try { await port.close(); } catch {} port = undefined; }
    byId("connect").disabled = false;
    byId("disconnect").disabled = true;
    safeText(byId("connection"), "Disconnected");
    safeText(byId("boot-status"), bootState.disconnect());
  }
}

async function disconnect() {
  if (reader) await reader.cancel();
}

byId("board-select").addEventListener("change", () => {
  safeText(byId("boot-status"), bootState.boardChanged(byId("board-select").value));
  refreshInstall();
});
for (const id of ["sensitivity", "baseline-scans", "brightness", "alert-hold"])
  byId(id).addEventListener("input", refreshInstall);
byId("connect").addEventListener("click", () => connect().catch(error => safeText(byId("connection"), error.message)));
byId("disconnect").addEventListener("click", () => disconnect().catch(error => safeText(byId("connection"), error.message)));
byId("json-export").addEventListener("click", () => download("wifi-canary-events.json", JSON.stringify(events, null, 2), "application/json"));
byId("csv-export").addEventListener("click", () => download("wifi-canary-events.csv", eventsToCsv(events), "text/csv"));
byId("config-export").addEventListener("click", () => {
  try {
    download("canary-config.bin", buildConfig(configValues()), "application/octet-stream");
  } catch (error) { safeText(byId("install-status"), error.message); }
});
window.addEventListener("pagehide", () => {
  for (const url of installUrls) URL.revokeObjectURL(url);
  installUrls = [];
});
refreshInstall();
