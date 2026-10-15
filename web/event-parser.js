export const SUPPORTED_SCHEMA = 1;

export function parseCanaryLine(line) {
  const text = String(line || "").trim();
  if (!text.startsWith("{")) return null;
  let value;
  try { value = JSON.parse(text); } catch { return null; }
  if (value.schema !== SUPPORTED_SCHEMA) throw new Error(`Unsupported schema ${value.schema}`);
  for (const key of ["device_id", "firmware", "board", "uptime_ms", "event", "score", "state", "health"])
    if (!(key in value)) throw new Error(`Missing field ${key}`);
  return value;
}

export function eventsToCsv(events) {
  const fields = ["device_id", "firmware", "board", "uptime_ms", "event", "detector", "score_delta", "score", "state", "reason", "ssid", "bssid", "channel", "rssi"];
  const quote = value => `"${String(value ?? "").replaceAll('"', '""')}"`;
  return [fields.join(","), ...events.map(event => fields.map(field => quote(event[field])).join(","))].join("\n");
}

export function safeText(element, value) {
  element.textContent = value == null ? "" : String(value);
}
