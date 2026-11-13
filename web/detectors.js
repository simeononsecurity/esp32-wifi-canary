export const detectorExplanations = Object.freeze({
  pwnagotchi: "Pwnagotchi beacon metadata",
  pineapple_oui: "WiFi Pineapple BSSID pattern",
  wifi_pineapple: "WiFi Pineapple BSSID pattern",
  probe_flood: "Probe requests exceeded the rate threshold",
  deauth_burst: "Deauthentication or disassociation burst",
  broadcast_deauth: "Broadcast deauthentication burst",
  open_clone: "Known encrypted SSID also appeared open",
  missing_original_open_clone: "Encrypted baseline AP disappeared while an open clone remained",
  security_downgrade: "Known SSID appeared with weaker security",
  duplicate_ssid_vendor: "Known SSID appeared from another vendor",
  beacon_flood: "New SSIDs exceeded the rate threshold",
  score_decay: "Confidence score decayed over time"
});

export function explainDetector(id) {
  return detectorExplanations[id] || (id ? `Unknown detector: ${id}` : "No detector for this event");
}
