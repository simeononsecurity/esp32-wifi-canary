import { parseCanaryLine, eventsToCsv, safeText } from "./event-parser.js";
import { buildConfig } from "./config.js";
import { buildInstallManifest } from "./install-manifest.js";

const events = [];
const byId = id => document.getElementById(id);
let port;
let installUrls = [];
let installRevision = 0;

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

async function refreshInstall() {
  const revision = ++installRevision;
  const installer = byId("installer");
  installer.hidden = true;
  installer.removeAttribute("manifest");
  safeText(byId("install-status"), "Preparing firmware and settings");
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
    const manifestObjectUrl = URL.createObjectURL(new Blob([JSON.stringify(manifest)], { type: "application/json" }));
    urls.push(manifestObjectUrl);
    installer.setAttribute("manifest", manifestObjectUrl);
    installer.hidden = false;
    safeText(byId("install-status"), `Ready: ${byId("board-select").selectedOptions[0].text}. Firmware and settings flash together.`);
    for (const url of installUrls) URL.revokeObjectURL(url);
    installUrls = urls;
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
  port = await navigator.serial.requestPort();
  await port.open({ baudRate: 115200 });
  safeText(byId("connection"), "Connected");
  const decoder = new TextDecoderStream();
  port.readable.pipeTo(decoder.writable).catch(() => {});
  const reader = decoder.readable.getReader();
  let pending = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    pending += value;
    const lines = pending.split(/\r?\n/);
    pending = lines.pop();
    for (const line of lines) {
      try {
        const event = parseCanaryLine(line);
        if (event) render(event);
      } catch (error) { safeText(byId("parser-error"), error.message); }
    }
  }
}

byId("board-select").addEventListener("change", refreshInstall);
for (const id of ["sensitivity", "baseline-scans", "brightness", "alert-hold"])
  byId(id).addEventListener("change", refreshInstall);
byId("connect").addEventListener("click", () => connect().catch(error => safeText(byId("connection"), error.message)));
byId("json-export").addEventListener("click", () => download("wifi-canary-events.json", JSON.stringify(events, null, 2), "application/json"));
byId("csv-export").addEventListener("click", () => download("wifi-canary-events.csv", eventsToCsv(events), "text/csv"));
byId("config-export").addEventListener("click", () => {
  try {
    download("canary-config.bin", buildConfig(configValues()), "application/octet-stream");
  } catch (error) { safeText(byId("install-status"), error.message); }
});
refreshInstall();
