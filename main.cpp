/*
 * Travel WiFi Canary
 * Target:  M5Stack Atom Lite  (ESP32, single SK6812 RGB LED on GPIO27)
 * Purpose: Passive 2.4 GHz WiFi awareness sensor.
 *
 * Detection engines:
 *   1. Deauth/disassoc burst  — 802.11 mgmt subtype 10/12 rate analysis
 *   2. Probe request flood    — subtype 4 rate analysis
 *   3. Pwnagotchi detector    — beacon from de:ad:be:ef:de:ad + deauth policy
 *   4. WiFi Pineapple OUI     — BSSID bytes [1:2] == 13:37
 *   5. Open clone / evil twin — same SSID appears as OPEN after encrypted baseline
 *   6. Original AP absent + open clone present
 *   7. Security downgrade     — same SSID with weaker encryption
 *   8. Duplicate SSID diff vendor (OUI mismatch)
 *   9. Beacon / SSID flood    — new SSIDs per 30 s window
 *
 * LED legend:
 *   Blue  (pulse)  — startup / baseline learning
 *   Green (solid)  — environment looks normal
 *   Yellow (solid) — caution: suspicious pattern
 *   Red   (pulse)  — alert: higher-confidence threat
 */

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "canary_core.h"
#include "canary_event.h"
#include "canary_config.h"
#include "canary_storage.h"
#include "canary_event_log.h"
#include "canary_board.h"

using namespace canary;

// ============================================================
// CONFIGURATION
// ============================================================

// Baseline learning
#define BASELINE_SCAN_INTERVAL_MS  8000

// Normal operation
#define SCAN_INTERVAL_MS          20000

// Channel hop (promiscuous mode)
static const uint8_t HOP_CHANNELS[]    = {1, 6, 11};
static const size_t  HOP_CHANNEL_COUNT = 3;
#define CHANNEL_DWELL_MS           300

// ── Deauth / disassoc burst ───────────────────────────────────
#define DEAUTH_WINDOW_MS            5000
#define DEAUTH_CAUTION_THRESHOLD       kDeauthCautionThreshold
#define DEAUTH_ALERT_THRESHOLD         kDeauthAlertThreshold
#define DEAUTH_BROADCAST_THRESHOLD     kDeauthBroadcastThreshold
#define MAX_DEAUTH_SOURCES            24

// ── Probe request flood ───────────────────────────────────────
// Counts 802.11 probe-request frames in a rolling window.
// A sudden flood correlates with deauth attacks (clients scanning
// for alternatives) or aggressive scanning tools.
#define PROBE_WINDOW_MS           10000
#define PROBE_CAUTION_THRESHOLD      kProbeCautionThreshold
#define PROBE_ALERT_THRESHOLD        kProbeAlertThreshold

// ── Pwnagotchi detector ───────────────────────────────────────
// Pwnagotchi devices broadcast beacon frames from MAC de:ad:be:ef:de:ad.
// The SSID is a JSON string containing device metadata including whether
// the deauth attack policy is enabled.
#define PWNA_SEEN_TIMEOUT_MS     60000   // forget pwnagotchi after 60 s quiet
#define PWNA_QUEUE_SIZE              4
#define PWNA_SSID_SNAP              96   // bytes of SSID to copy per event

// ── WiFi Pineapple OUI ────────────────────────────────────────
// Hak5 WiFi Pineapple devices use BSSIDs where bytes [1] and [2]
// are 0x13 and 0x37 ("1337"). Detected via passive scan.

// ── AP table ─────────────────────────────────────────────────
#define MAX_APS                   96
#define SSID_LEN                  33

// ── Beacon / SSID spam ────────────────────────────────────────
#define SPAM_WINDOW_MS           30000
#define SPAM_CAUTION_THRESHOLD      kSpamCautionThreshold
#define SPAM_ALERT_THRESHOLD        kSpamAlertThreshold
#define MAX_SPAM_SSIDS_TRACKED      64

// ── RSSI ─────────────────────────────────────────────────────
#define RSSI_MIN                   -95
#define RSSI_STRONGER_BY            kRssiStrongerBy

// ── Confidence scoring ────────────────────────────────────────
#define SCORE_CAUTION               kScoreCaution
#define SCORE_ALERT                 kScoreAlert
#define SCORE_MAX                   kScoreMax
#define SCORE_DECAY_INTERVAL_MS  60000
#define SCORE_DECAY_AMOUNT           1

// ── Misc ──────────────────────────────────────────────────────
#define HEARTBEAT_MS             30000

// ============================================================
// DEVICE STATE
// ============================================================

static CanaryState   g_state          = STATE_STARTUP;
static unsigned long g_stateChangedAt = 0;

// ============================================================
// AP TABLE
// ============================================================

typedef struct {
    char          ssid[SSID_LEN];
    uint8_t       bssid[6];
    int8_t        rssi;
    uint8_t       channel;
    AuthStrength  auth;
    bool          inBaseline;
    bool          activeScan;
    unsigned long firstSeen;
    unsigned long lastSeen;
} KnownAP;

static KnownAP g_aps[MAX_APS];
static int     g_apCount          = 0;
static bool    g_baselineLearned   = false;
static int     g_baselineScansDone = 0;

// ============================================================
// DEAUTH QUEUE  (callback → loop, lock-free ring)
// ============================================================

#define DEAUTH_QUEUE_SIZE  64

typedef struct {
    uint8_t src[6];
    uint8_t dst[6];
    uint8_t subtype;
    int8_t  rssi;
    uint8_t channel;
} DeauthFrame;

static volatile DeauthFrame g_deauthQ[DEAUTH_QUEUE_SIZE];
static volatile size_t      g_dqHead = 0;
static volatile size_t      g_dqTail = 0;
static volatile uint32_t    g_dqDrops = 0;
static portMUX_TYPE         g_dqMux  = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    uint8_t       src[6];
    uint32_t      count;
    uint32_t      broadcastCount;
    unsigned long windowStart;
    int8_t        lastRssi;
    uint8_t       lastChannel;
    bool          inUse;
} DeauthSrc;

static DeauthSrc g_deauthSrc[MAX_DEAUTH_SOURCES];

// ============================================================
// PROBE REQUEST FLOOD
// Counts 802.11 probe-request frames (subtype 4) in promiscuous
// mode. A flood indicates aggressive scanning or post-deauth
// client thrashing.
// ============================================================

static volatile uint32_t g_probeCount      = 0;
static portMUX_TYPE      g_probeMux        = portMUX_INITIALIZER_UNLOCKED;
static uint32_t          g_probeSampled    = 0;
static unsigned long     g_probeWindowStart = 0;

// ============================================================
// PWNAGOTCHI DETECTION
// Pwnagotchi transmits beacon frames from de:ad:be:ef:de:ad.
// The SSID field carries JSON with name, version, policy.deauth.
// ============================================================

typedef struct {
    uint8_t  ssidSnap[PWNA_SSID_SNAP];
    uint8_t  ssidLen;
    int8_t   rssi;
    uint8_t  channel;
} PwnaRawEvent;

static volatile PwnaRawEvent g_pwnaQ[PWNA_QUEUE_SIZE];
static volatile size_t       g_pwnaHead = 0;
static volatile size_t       g_pwnaTail = 0;
static volatile uint32_t     g_pwnaDrops = 0;
static portMUX_TYPE          g_pwnaMux  = portMUX_INITIALIZER_UNLOCKED;

static bool          g_pwnaDetected = false;
static bool          g_pwnaDeauth   = false;
static char          g_pwnaName[32] = "";
static int8_t        g_pwnaRssi     = -100;
static uint8_t       g_pwnaChannel  = 0;
static unsigned long g_pwnaLastSeen = 0;

// Pwnagotchi's well-known fixed MAC address
static const uint8_t PWNA_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

static void macStr(const uint8_t* m, char* buf);

// ============================================================
// BEACON / SSID SPAM TRACKER
// ============================================================

static char          g_spamSSIDs[MAX_SPAM_SSIDS_TRACKED][SSID_LEN];
static int           g_spamCount       = 0;
static int           g_spamNew         = 0;
static unsigned long g_spamWindowStart = 0;

// ============================================================
// CONFIDENCE SCORE
// ============================================================

static int           g_score       = 0;
static char          g_scoreReason[72] = "";
static unsigned long g_lastDecay   = 0;
static uint8_t       g_curChannel  = 1;
static char          g_deviceId[17] = "unknown";
static char          g_lastSource[18] = "";
static char          g_lastSsid[SSID_LEN] = "";
static int           g_lastEventChannel = -1;
static int           g_lastEventRssi = -127;
static CanaryConfig  g_config = defaultConfig();
static EventLog      g_eventLog;
static uint32_t      g_scanDurationMs = 0;
static uint32_t      g_captureGapMs = 0;
static volatile uint32_t g_parserRejects = 0;
static volatile uint32_t g_channelFrames[15] = {};
static uint32_t      g_minFreeHeap = UINT32_MAX;

static void emitEvent(const char* eventType, const char* detectorId,
                      int scoreDelta, const char* reason,
                      const char* ssid = nullptr, const char* bssid = nullptr,
                      int channel = -1, int rssi = -127) {
    char output[768];
    const EventRecord event = {
        g_deviceId,
        kFirmwareVersion,
        boardId(),
        millis(),
        eventType,
        detectorId,
        scoreDelta,
        g_score,
        stateFor(g_baselineLearned, g_score),
        reason,
        ssid,
        bssid,
        channel,
        rssi,
        {
            g_apCount,
            g_probeSampled,
            g_curChannel,
            static_cast<uint32_t>(g_dqDrops),
            static_cast<uint32_t>(g_pwnaDrops),
            g_scanDurationMs,
            g_captureGapMs,
            g_parserRejects,
            g_eventLog.losses(),
            ESP.getFreeHeap(),
            g_minFreeHeap == UINT32_MAX ? ESP.getFreeHeap() : g_minFreeHeap,
            static_cast<int>(esp_reset_reason()),
            g_curChannel < 15 ? static_cast<uint32_t>(g_channelFrames[g_curChannel]) : 0,
            static_cast<uint8_t>(g_baselineScansDone),
            g_config.baselineScans,
            g_baselineLearned,
        },
    };
    if (formatEventJson(output, sizeof(output), event)) {
        Serial.println(output);
        if (!strcmp(eventType, "boot") || !strcmp(eventType, "detection"))
            g_eventLog.append(output);
    } else {
        Serial.println("[canary] event serialization failed");
    }
}

static void scoreAdd(int pts, const char* detectorId, const char* reason,
                     const char* ssid = nullptr, const char* bssid = nullptr,
                     int channel = -1, int rssi = -127) {
    if (pts <= 0 || !detectorEnabled(g_config, detectorId)) return;
    pts = sensitivityAdjusted(g_config, pts);
    g_score = canary::addScore(g_score, pts);
    if (reason && reason[0]) {
        strncpy(g_scoreReason, reason, sizeof(g_scoreReason) - 1);
        g_scoreReason[sizeof(g_scoreReason) - 1] = '\0';
    }
    strncpy(g_lastSource, bssid ? bssid : "", sizeof(g_lastSource) - 1);
    g_lastSource[sizeof(g_lastSource) - 1] = '\0';
    strncpy(g_lastSsid, ssid ? ssid : "", sizeof(g_lastSsid) - 1);
    g_lastSsid[sizeof(g_lastSsid) - 1] = '\0';
    g_lastEventChannel = channel;
    g_lastEventRssi = rssi;
    Serial.printf("[canary] score +%d → %d  \"%s\"\n", pts, g_score, reason ? reason : "");
    emitEvent("detection", detectorId, pts, reason, ssid, bssid, channel, rssi);
}

static void scoreDecay() {
    if (millis() - g_lastDecay < SCORE_DECAY_INTERVAL_MS) return;
    g_lastDecay = millis();
    if (g_score > 0) {
        g_score = canary::decayScore(g_score, SCORE_DECAY_AMOUNT);
        Serial.printf("[canary] score decay → %d\n", g_score);
        emitEvent("decay", "score_decay", -SCORE_DECAY_AMOUNT,
                  "quiet-period score decay");
    }
}

// ============================================================
// PROMISCUOUS MODE
// ============================================================

static bool          g_promisc    = false;
static size_t        g_hopIdx     = 0;
static unsigned long g_lastHop    = 0;

// Promiscuous callback — IRAM, no Serial, no malloc, no blocking.
// Handles four management frame subtypes:
//   4  = probe request  → probe flood counter
//   8  = beacon         → pwnagotchi check
//   10 = disassociation → deauth queue
//   12 = deauthentication → deauth queue
static void IRAM_ATTR wifiSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf || type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.channel < 15) ++g_channelFrames[pkt->rx_ctrl.channel];
    ParsedMgmtFrame frame;
    if (!parseManagementFrame(pkt->payload, pkt->rx_ctrl.sig_len, &frame)) {
        ++g_parserRejects;
        return;
    }

    int8_t rssi = pkt->rx_ctrl.rssi;
    if (rssi < RSSI_MIN) return;

    const uint8_t subtype = frame.subtype;

    // ── Probe request flood counter (subtype 4) ──────────────
    if (subtype == 4) {
        portENTER_CRITICAL_ISR(&g_probeMux);
        g_probeCount++;
        portEXIT_CRITICAL_ISR(&g_probeMux);
        return;
    }

    // ── Pwnagotchi beacon detector (subtype 8) ────────────────
    // Pwnagotchi beacons from de:ad:be:ef:de:ad; SSID = JSON payload
    if (subtype == 8) {
        if (bytesEqual(frame.addr2, PWNA_MAC, 6)) {
            uint8_t ssid[PWNA_SSID_SNAP];
            size_t ssidLength = 0;
            const size_t frameLength = pkt->rx_ctrl.sig_len > 4 ? pkt->rx_ctrl.sig_len - 4 : 0;
            if (extractBeaconSsid(pkt->payload, frameLength, ssid, sizeof(ssid), &ssidLength)) {
                portENTER_CRITICAL_ISR(&g_pwnaMux);
                const size_t next = ringNext(g_pwnaHead, PWNA_QUEUE_SIZE);
                if (ringHasSpace(g_pwnaHead, g_pwnaTail, PWNA_QUEUE_SIZE)) {
                    PwnaRawEvent* e = (PwnaRawEvent*)&g_pwnaQ[g_pwnaHead];
                    memcpy((void*)e->ssidSnap, ssid, ssidLength);
                    e->ssidLen = static_cast<uint8_t>(ssidLength);
                    e->rssi = rssi;
                    e->channel = static_cast<uint8_t>(pkt->rx_ctrl.channel);
                    g_pwnaHead = next;
                } else {
                    ++g_pwnaDrops;
                }
                portEXIT_CRITICAL_ISR(&g_pwnaMux);
            }
        }
        return;
    }

    // ── Deauth / disassoc (subtypes 10 and 12) ────────────────
    if (subtype != 10 && subtype != 12) return;

    portENTER_CRITICAL_ISR(&g_dqMux);
    size_t next = ringNext(g_dqHead, DEAUTH_QUEUE_SIZE);
    if (ringHasSpace(g_dqHead, g_dqTail, DEAUTH_QUEUE_SIZE)) {
        DeauthFrame* f = (DeauthFrame*)&g_deauthQ[g_dqHead];
        memcpy((void*)f->src, frame.addr2, 6);
        memcpy((void*)f->dst, frame.addr1, 6);
        f->subtype = subtype;
        f->rssi    = rssi;
        f->channel = (uint8_t)pkt->rx_ctrl.channel;
        g_dqHead   = next;
    } else {
        ++g_dqDrops;
    }
    portEXIT_CRITICAL_ISR(&g_dqMux);
}

static void promiscStart() {
    if (g_promisc) return;
    WiFi.mode(WIFI_STA);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&wifiSniffer);
    esp_wifi_set_promiscuous(true);
    g_hopIdx     = 0;
    g_curChannel = HOP_CHANNELS[0];
    esp_wifi_set_channel(g_curChannel, WIFI_SECOND_CHAN_NONE);
    g_lastHop    = millis();
    g_promisc    = true;
}

static void promiscStop() {
    if (!g_promisc) return;
    esp_wifi_set_promiscuous(false);
    g_promisc = false;
}

static void channelHop() {
    if (!g_promisc) return;
    if (millis() - g_lastHop < CHANNEL_DWELL_MS) return;
    g_hopIdx     = (g_hopIdx + 1) % HOP_CHANNEL_COUNT;
    g_curChannel = HOP_CHANNELS[g_hopIdx];
    esp_wifi_set_channel(g_curChannel, WIFI_SECOND_CHAN_NONE);
    g_lastHop    = millis();
}

// ============================================================
// DEAUTH ANALYSIS
// ============================================================

static void drainDeauthQueue() {
    while (true) {
        portENTER_CRITICAL(&g_dqMux);
        bool empty = (g_dqHead == g_dqTail);
        portEXIT_CRITICAL(&g_dqMux);
        if (empty) break;

        DeauthFrame frame;
        portENTER_CRITICAL(&g_dqMux);
        memcpy(&frame, (void*)&g_deauthQ[g_dqTail], sizeof(DeauthFrame));
        g_dqTail = ringNext(g_dqTail, DEAUTH_QUEUE_SIZE);
        portEXIT_CRITICAL(&g_dqMux);

        unsigned long now = millis();
        DeauthSrc* slot = nullptr;
        for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
            if (g_deauthSrc[i].inUse && memcmp(g_deauthSrc[i].src, frame.src, 6) == 0) {
                slot = &g_deauthSrc[i];
                break;
            }
        }
        if (!slot) {
            for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
                if (!g_deauthSrc[i].inUse) {
                    slot = &g_deauthSrc[i];
                    memcpy(slot->src, frame.src, 6);
                    slot->count = slot->broadcastCount = 0;
                    slot->windowStart = now;
                    slot->inUse = true;
                    break;
                }
            }
        }
        if (!slot) continue;

        if (now - slot->windowStart > DEAUTH_WINDOW_MS) {
            slot->count = slot->broadcastCount = 0;
            slot->windowStart = now;
        }
        slot->count++;
        slot->lastRssi = frame.rssi;
        slot->lastChannel = frame.channel;
        if (isBroadcastMac(frame.dst)) slot->broadcastCount++;
    }
}

static void analyzeDeauthSources() {
    unsigned long now = millis();
    for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
        if (!g_deauthSrc[i].inUse) continue;
        if (now - g_deauthSrc[i].windowStart > DEAUTH_WINDOW_MS) continue;
        uint32_t cnt  = g_deauthSrc[i].count;
        uint32_t bcnt = g_deauthSrc[i].broadcastCount;
        char sourceBuf[18];
        macStr(g_deauthSrc[i].src, sourceBuf);
        const int burstPoints = deauthBurstPoints(cnt);
        if (burstPoints == 4) {
            scoreAdd(burstPoints, "deauth_burst",
                     "deauth/disassoc burst (alert-level rate)",
                     nullptr, sourceBuf, g_deauthSrc[i].lastChannel, g_deauthSrc[i].lastRssi);
            Serial.printf("[canary] DEAUTH ALERT: %lu f/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        } else if (burstPoints == 2) {
            scoreAdd(burstPoints, "deauth_burst",
                     "deauth/disassoc burst (elevated rate)",
                     nullptr, sourceBuf, g_deauthSrc[i].lastChannel, g_deauthSrc[i].lastRssi);
            Serial.printf("[canary] DEAUTH caution: %lu f/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        }
        const int broadcastPoints = broadcastDeauthPoints(bcnt);
        if (broadcastPoints > 0) {
            scoreAdd(broadcastPoints, "broadcast_deauth",
                     "broadcast deauth frames observed",
                     nullptr, sourceBuf, g_deauthSrc[i].lastChannel, g_deauthSrc[i].lastRssi);
        }
    }
}

// ============================================================
// PROBE REQUEST FLOOD ANALYSIS
// ============================================================

static void analyzeProbeFlood() {
    unsigned long now = millis();
    if (now - g_probeWindowStart < PROBE_WINDOW_MS) return;

    portENTER_CRITICAL(&g_probeMux);
    g_probeSampled = g_probeCount;
    g_probeCount   = 0;
    portEXIT_CRITICAL(&g_probeMux);
    g_probeWindowStart = now;

    if (g_probeSampled == 0) return;

    const int points = probeFloodPoints(g_probeSampled);
    if (points == 3) {
        scoreAdd(points, "probe_flood", "probe request flood (attack-tool level)",
                 nullptr, nullptr, g_curChannel);
        Serial.printf("[canary] PROBE FLOOD ALERT: %lu probes/10s\n",
                      (unsigned long)g_probeSampled);
    } else if (points == 1) {
        scoreAdd(points, "probe_flood", "probe request flood (elevated)",
                 nullptr, nullptr, g_curChannel);
        Serial.printf("[canary] PROBE FLOOD caution: %lu probes/10s\n",
                      (unsigned long)g_probeSampled);
    }
}

// ============================================================
// PWNAGOTCHI DETECTION
// Parse raw SSID bytes from the callback queue.
// Avoids JSON library by using simple byte-pattern search.
// ============================================================

static void drainPwnaQueue() {
    while (true) {
        portENTER_CRITICAL(&g_pwnaMux);
        bool empty = (g_pwnaHead == g_pwnaTail);
        portEXIT_CRITICAL(&g_pwnaMux);
        if (empty) break;

        PwnaRawEvent ev;
        portENTER_CRITICAL(&g_pwnaMux);
        memcpy(&ev, (void*)&g_pwnaQ[g_pwnaTail], sizeof(PwnaRawEvent));
        g_pwnaTail = ringNext(g_pwnaTail, PWNA_QUEUE_SIZE);
        portEXIT_CRITICAL(&g_pwnaMux);

        const uint8_t* data = ev.ssidSnap;
        int dlen = ev.ssidLen;

        const PwnagotchiMetadata metadata = parsePwnagotchiMetadata(data, dlen);
        if (!metadata.valid) continue;
        if (metadata.name[0]) {
            strncpy(g_pwnaName, metadata.name, sizeof(g_pwnaName) - 1);
            g_pwnaName[sizeof(g_pwnaName) - 1] = '\0';
        }
        const bool deauthOn = metadata.deauth;

        g_pwnaDetected = true;
        g_pwnaDeauth   = deauthOn;
        g_pwnaRssi     = ev.rssi;
        g_pwnaChannel  = ev.channel;
        g_pwnaLastSeen = millis();

        Serial.printf("[canary] PWNAGOTCHI: name='%s' deauth=%s rssi=%d\n",
                      g_pwnaName[0] ? g_pwnaName : "?",
                      deauthOn ? "YES" : "no",
                      ev.rssi);
    }
}

static void analyzePwnagotchi() {
    if (!g_pwnaDetected) return;
    unsigned long now = millis();

    if (now - g_pwnaLastSeen > PWNA_SEEN_TIMEOUT_MS) {
        g_pwnaDetected = false;
        g_pwnaDeauth   = false;
        g_pwnaName[0]  = '\0';
        return;
    }

    if (g_pwnaDeauth) {
        char bssid[18];
        macStr(PWNA_MAC, bssid);
        scoreAdd(pwnagotchiPoints(true), "pwnagotchi",
                 "pwnagotchi detected: deauth policy ACTIVE",
                 g_pwnaName, bssid, g_pwnaChannel, g_pwnaRssi);
        Serial.printf("[canary] PWNAGOTCHI ALERT: '%s' is attacking (deauth=true) rssi=%d\n",
                      g_pwnaName[0] ? g_pwnaName : "?", g_pwnaRssi);
    } else {
        char bssid[18];
        macStr(PWNA_MAC, bssid);
        scoreAdd(pwnagotchiPoints(false), "pwnagotchi",
                 "pwnagotchi detected (passive mode)",
                 g_pwnaName, bssid, g_pwnaChannel, g_pwnaRssi);
        Serial.printf("[canary] PWNAGOTCHI caution: '%s' rssi=%d (passive/harvesting)\n",
                      g_pwnaName[0] ? g_pwnaName : "?", g_pwnaRssi);
    }
}

// ============================================================
// AP TABLE HELPERS
// ============================================================

static AuthStrength mapAuth(wifi_auth_mode_t m) {
    switch (m) {
        case WIFI_AUTH_OPEN:            return AUTH_OPEN;
        case WIFI_AUTH_WEP:             return AUTH_WEP;
        case WIFI_AUTH_WPA_PSK:         return AUTH_WPA;
        case WIFI_AUTH_WPA2_PSK:        return AUTH_WPA2;
        case WIFI_AUTH_WPA_WPA2_PSK:    return AUTH_WPA2;
        case WIFI_AUTH_WPA3_PSK:        return AUTH_WPA3;
        case WIFI_AUTH_WPA2_ENTERPRISE: return AUTH_WPA2E;
        default:                        return AUTH_UNKNOWN;
    }
}

static const char* authStr(AuthStrength a) {
    switch (a) {
        case AUTH_OPEN:  return "OPEN";
        case AUTH_WEP:   return "WEP";
        case AUTH_WPA:   return "WPA";
        case AUTH_WPA2:  return "WPA2";
        case AUTH_WPA3:  return "WPA3";
        case AUTH_WPA2E: return "WPA2-ENT";
        default:         return "?";
    }
}

static void macStr(const uint8_t* m, char* buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static KnownAP* findByBSSID(const uint8_t* bssid) {
    for (int i = 0; i < g_apCount; i++)
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0) return &g_aps[i];
    return nullptr;
}

static KnownAP* upsertAP(const char* ssid, const uint8_t* bssid,
                          int8_t rssi, uint8_t ch, AuthStrength auth) {
    unsigned long now = millis();
    KnownAP* e = findByBSSID(bssid);
    if (e) {
        e->rssi = rssi; e->channel = ch; e->auth = auth;
        e->lastSeen = now; e->activeScan = true;
        if (!e->ssid[0] && ssid && ssid[0]) strncpy(e->ssid, ssid, SSID_LEN - 1);
        return e;
    }
    if (g_apCount >= MAX_APS) return nullptr;
    KnownAP* ap = &g_aps[g_apCount++];
    memset(ap, 0, sizeof(KnownAP));
    if (ssid) strncpy(ap->ssid, ssid, SSID_LEN - 1);
    memcpy(ap->bssid, bssid, 6);
    ap->rssi = rssi; ap->channel = ch; ap->auth = auth;
    ap->inBaseline = false; ap->activeScan = true;
    ap->firstSeen = ap->lastSeen = now;
    return ap;
}

static void markAllInactive() {
    for (int i = 0; i < g_apCount; i++) g_aps[i].activeScan = false;
}

// ============================================================
// BEACON / SSID SPAM TRACKER
// ============================================================

static void updateSpamTracker(int scanCount) {
    unsigned long now = millis();
    if (now - g_spamWindowStart > SPAM_WINDOW_MS) {
        g_spamWindowStart = now; g_spamNew = 0; g_spamCount = 0;
    }
    for (int i = 0; i < scanCount; i++) {
        String s = WiFi.SSID(i);
        if (s.length() == 0) continue;
        const char* ssid = s.c_str();
        bool seenInWindow = false;
        for (int j = 0; j < g_spamCount; j++) {
            if (strcmp(g_spamSSIDs[j], ssid) == 0) { seenInWindow = true; break; }
        }
        if (!seenInWindow && g_spamCount < MAX_SPAM_SSIDS_TRACKED)
            strncpy(g_spamSSIDs[g_spamCount++], ssid, SSID_LEN - 1);
        bool inBaseline = false;
        for (int j = 0; j < g_apCount; j++) {
            if (g_aps[j].inBaseline && strcasecmp(g_aps[j].ssid, ssid) == 0) {
                inBaseline = true; break;
            }
        }
        if (!inBaseline && !seenInWindow) g_spamNew++;
    }
    const int points = beaconFloodPoints(g_spamNew);
    if (points == 3) {
        scoreAdd(points, "beacon_flood", "beacon/SSID flood: very high new-SSID count");
        Serial.printf("[canary] SPAM ALERT: %d new SSIDs/%ds\n",
                      g_spamNew, SPAM_WINDOW_MS / 1000);
    } else if (points == 2) {
        scoreAdd(points, "beacon_flood", "beacon/SSID flood: elevated new-SSID count");
        Serial.printf("[canary] SPAM caution: %d new SSIDs/%ds\n",
                      g_spamNew, SPAM_WINDOW_MS / 1000);
    }
}

// ============================================================
// SCAN-BASED THREAT ANALYSIS
// ============================================================

static void analyzeScanThreats(int scanCount) {
    for (int i = 0; i < scanCount; i++) {
        String ssidStr = WiFi.SSID(i);
        const char*  ssid  = ssidStr.c_str();
        uint8_t*     bssid = WiFi.BSSID(i);
        int8_t       rssi  = (int8_t)WiFi.RSSI(i);
        AuthStrength auth  = mapAuth(WiFi.encryptionType(i));
        if (!bssid) continue;

        char bssidBuf[18];
        macStr(bssid, bssidBuf);

        // ── WiFi Pineapple OUI check ──────────────────────────
        // Hak5 WiFi Pineapple uses "1337" hex in BSSID bytes [1:2]
        if (isPineappleBssid(bssid)) {
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "WiFi Pineapple OUI: SSID='%.28s'", ssid);
            scoreAdd(4, "wifi_pineapple", reason, ssid, bssidBuf,
                     WiFi.channel(i), rssi);
            Serial.printf("[canary] PINEAPPLE ALERT: SSID='%s' bssid=%s rssi=%d\n",
                          ssid, bssidBuf, rssi);
        }

        if (ssidStr.length() == 0) continue;

        KnownAP* thisEntry = findByBSSID(bssid);
        bool bssidIsNew = (!thisEntry || !thisEntry->inBaseline);

        KnownAP* baseAP = nullptr;
        for (int j = 0; j < g_apCount; j++) {
            if (!g_aps[j].inBaseline) continue;
            if (strcasecmp(g_aps[j].ssid, ssid) != 0) continue;
            if (!baseAP || g_aps[j].rssi > baseAP->rssi) baseAP = &g_aps[j];
        }
        if (!baseAP) continue;

        const AccessPointView baseline = {
            baseAP->ssid, baseAP->bssid, baseAP->rssi, baseAP->auth
        };
        const AccessPointView observed = {ssid, bssid, rssi, auth};
        const AccessPointThreat threat = evaluateAccessPointThreat(
            baseline, observed, bssidIsNew);

        // ── Open clone of known encrypted SSID ───────────────
        if (threat.openClonePoints > 0) {
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "open clone of encrypted SSID '%.28s'", ssid);
            scoreAdd(threat.openClonePoints, "open_clone", reason, ssid, bssidBuf,
                     WiFi.channel(i), rssi);
            Serial.printf("[canary] OPEN CLONE: SSID='%s' baseline=%s clone=OPEN "
                          "bssid=%s rssi=%d/%d\n",
                          ssid, authStr(baseAP->auth), bssidBuf, rssi, baseAP->rssi);
            continue;
        }

        // ── Security downgrade ────────────────────────────────
        if (threat.downgradePoints > 0) {
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "security downgrade '%.24s': %s→%s",
                     ssid, authStr(baseAP->auth), authStr(auth));
            scoreAdd(threat.downgradePoints, "security_downgrade", reason,
                     ssid, bssidBuf, WiFi.channel(i), rssi);
            Serial.printf("[canary] SEC DOWNGRADE: SSID='%s' was=%s now=%s bssid=%s\n",
                          ssid, authStr(baseAP->auth), authStr(auth), bssidBuf);
        }

        // ── Duplicate SSID with unexpected vendor OUI ─────────
        if (threat.duplicateVendorPoints > 0) {
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "dup SSID diff vendor: '%.30s'", ssid);
            scoreAdd(threat.duplicateVendorPoints, "duplicate_ssid_vendor", reason,
                     ssid, bssidBuf, WiFi.channel(i), rssi);
            Serial.printf("[canary] DUP SSID: SSID='%s' known=%02x:%02x:%02x "
                          "new=%02x:%02x:%02x rssi=%d/%d\n",
                          ssid,
                          baseAP->bssid[0], baseAP->bssid[1], baseAP->bssid[2],
                          bssid[0], bssid[1], bssid[2],
                          rssi, baseAP->rssi);
        }
    }

    // ── Original encrypted AP absent + open clone present ────
    for (int j = 0; j < g_apCount; j++) {
        if (!g_aps[j].inBaseline)       continue;
        if (g_aps[j].auth == AUTH_OPEN) continue;
        if (g_aps[j].activeScan)        continue;
        for (int i = 0; i < scanCount; i++) {
            uint8_t* observedBssid = WiFi.BSSID(i);
            if (!observedBssid) continue;
            const AccessPointView baseline = {
                g_aps[j].ssid, g_aps[j].bssid, g_aps[j].rssi, g_aps[j].auth
            };
            const String observedSsid = WiFi.SSID(i);
            const AccessPointView observed = {
                observedSsid.c_str(), observedBssid, static_cast<int8_t>(WiFi.RSSI(i)),
                mapAuth(WiFi.encryptionType(i))
            };
            const int points = missingOriginalOpenClonePoints(
                baseline, observed, g_aps[j].activeScan);
            if (points == 0) continue;
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "original AP gone, open clone present: '%.26s'", g_aps[j].ssid);
            char bssidBuf[18];
            macStr(observedBssid, bssidBuf);
            scoreAdd(points, "missing_original_open_clone", reason,
                     observedSsid.c_str(), bssidBuf, WiFi.channel(i), WiFi.RSSI(i));
            Serial.printf("[canary] ABSENT+CLONE: original '%s' gone, open clone present\n",
                          g_aps[j].ssid);
        }
    }
}

// ============================================================
// WIFI SCAN
// ============================================================

static unsigned long g_lastScan = 0;
static bool g_radio2gReady = true;

static void performScan(bool isBaseline) {
    if (!g_radio2gReady) {
        Serial.println("[canary] 2.4 GHz radio setup failed; scan skipped");
        return;
    }
    const unsigned long scanStarted = millis();
    promiscStop();
    boardShowScan();
    Serial.printf("[canary] %s scan (aps=%d score=%d)\n",
                  isBaseline ? "baseline" : "normal", g_apCount, g_score);
    markAllInactive();

    int n = WiFi.scanNetworks(false, true, true, 300);
    g_lastScan = millis();
    g_scanDurationMs = g_lastScan - scanStarted;
    g_captureGapMs += g_scanDurationMs;

    if (n < 0) {
        Serial.printf("[canary] scan error: %d\n", n);
        promiscStart();
        return;
    }
    Serial.printf("[canary] scan found %d APs\n", n);

    for (int i = 0; i < n; i++) {
        uint8_t* bssid = WiFi.BSSID(i);
        if (!bssid) continue;
        upsertAP(WiFi.SSID(i).c_str(), bssid,
                 (int8_t)WiFi.RSSI(i),
                 (uint8_t)WiFi.channel(i),
                 mapAuth(WiFi.encryptionType(i)));
    }

    if (isBaseline) {
        g_baselineScansDone++;
        if (g_baselineScansDone >= g_config.baselineScans) {
            g_baselineLearned = true;
            for (int i = 0; i < g_apCount; i++) g_aps[i].inBaseline = true;
            Serial.printf("[canary] baseline complete: %d APs\n", g_apCount);
            for (int i = 0; i < g_apCount; i++) {
                char b[18]; macStr(g_aps[i].bssid, b);
                Serial.printf("  [%02d] %-32s %s ch%02u %-8s %d dBm\n",
                              i, g_aps[i].ssid, b,
                              g_aps[i].channel, authStr(g_aps[i].auth), g_aps[i].rssi);
            }
        } else {
            Serial.printf("[canary] baseline scan %d/%d\n",
                          g_baselineScansDone, g_config.baselineScans);
        }
    } else {
        updateSpamTracker(n);
        analyzeScanThreats(n);
    }

    if (isBaseline) emitEvent("baseline", nullptr, 0, "baseline scan complete");

    WiFi.scanDelete();
    promiscStart();
}

// ============================================================
// STATE UPDATE
// ============================================================

static void updateState() {
    const CanaryState next = stateFor(g_baselineLearned, g_score);
    if (next != g_state) {
        static const char* n[] = { "STARTUP","NORMAL","CAUTION","ALERT" };
        Serial.printf("[canary] %s → %s  (score=%d  \"%s\")\n",
                      n[g_state], n[next], g_score, g_scoreReason);
        boardNotifyState(g_state, next);
        g_state = next;
        g_stateChangedAt = millis();
        emitEvent("state", nullptr, 0, g_scoreReason);
    }
}

// ============================================================
// HEARTBEAT
// ============================================================

static unsigned long g_lastHeartbeat = 0;

static void printHeartbeat() {
    if (millis() - g_lastHeartbeat < HEARTBEAT_MS) return;
    g_lastHeartbeat = millis();
    static const char* n[] = { "STARTUP","NORMAL","CAUTION","ALERT" };
    Serial.printf("[canary] hb: state=%s score=%d reason=\"%s\" "
                  "aps=%d probes=%lu ch=%u pwna=%s\n",
                  n[g_state], g_score, g_scoreReason,
                  g_apCount, (unsigned long)g_probeSampled,
                  g_curChannel,
                  g_pwnaDetected ? (g_pwnaDeauth ? "ACTIVE" : "passive") : "none");
    emitEvent("status", nullptr, 0, g_scoreReason);
}

// ============================================================
// BUTTON — dump AP table + reset score
// ============================================================

static void handleButton() {
    if (boardButtonPressed()) {
        Serial.println("[canary] button: AP table dump + score reset");
        for (int i = 0; i < g_apCount; i++) {
            char b[18]; macStr(g_aps[i].bssid, b);
            Serial.printf("  ap[%02d] %-32s %s ch%02u %-8s %3d dBm %s\n",
                          i, g_aps[i].ssid, b,
                          g_aps[i].channel, authStr(g_aps[i].auth), g_aps[i].rssi,
                          g_aps[i].inBaseline ? "[baseline]" : "");
        }
        if (g_pwnaDetected) {
            Serial.printf("[canary] pwnagotchi: '%s' deauth=%s rssi=%d\n",
                          g_pwnaName, g_pwnaDeauth ? "YES" : "no", g_pwnaRssi);
        }
        const int clearedScore = g_score;
        g_score = 0;
        g_scoreReason[0] = '\0';
        Serial.println("[canary] score reset to 0");
        emitEvent("reset", "button", -clearedScore, "button score reset");
    }
}

static void handleSerialCommands() {
    static char command[16];
    static size_t used = 0;
    while (Serial.available()) {
        const char value = static_cast<char>(Serial.read());
        if (value == '\r') continue;
        if (value == '\n') {
            command[used] = '\0';
            if (!strcmp(command, "dumplog")) g_eventLog.dump(Serial);
            else if (!strcmp(command, "clearlog"))
                Serial.println(g_eventLog.clear() ? "[canary] log cleared" : "[canary] log clear failed");
            used = 0;
        } else if (used + 1 < sizeof(command)) command[used++] = value;
        else used = 0;
    }
}

// ============================================================
// SETUP
// ============================================================

static void initDeviceId() {
    const uint64_t mac = ESP.getEfuseMac();
    snprintf(g_deviceId, sizeof(g_deviceId), "%04x%08x",
             static_cast<unsigned int>((mac >> 32) & 0xFFFF),
             static_cast<unsigned int>(mac & 0xFFFFFFFF));
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println();
    Serial.println("================================");
    Serial.printf(" Travel WiFi Canary v%s\n", kFirmwareVersion);
    Serial.println(" Passive 2.4 GHz awareness");
    Serial.println("================================");

    initDeviceId();
    Serial.printf("[canary] event schema=%d device=%s firmware=%s board=%s\n",
                  kEventSchema, g_deviceId, kFirmwareVersion, boardId());

    const bool configValid = loadConfigPartition(&g_config);
    g_eventLog.begin();
    boardConfigure(g_config);
    boardBegin();
    Serial.printf("[canary] config=%s sensitivity=%u baseline_scans=%u engines=0x%03x\n",
                  configValid ? "stored" : "defaults", g_config.sensitivity,
                  g_config.baselineScans, g_config.engineMask);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
#if defined(CANARY_BOARD_T_DONGLE_C5)
    g_radio2gReady = esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY) == ESP_OK;
    if (!g_radio2gReady)
        Serial.println("[canary] 2.4 GHz band lock failed; scanning disabled");
#endif
    delay(100);

    memset(g_aps,       0, sizeof(g_aps));
    memset(g_deauthSrc, 0, sizeof(g_deauthSrc));
    memset(g_spamSSIDs, 0, sizeof(g_spamSSIDs));
    memset(g_pwnaName,  0, sizeof(g_pwnaName));

    g_apCount           = 0;
    g_baselineLearned   = false;
    g_baselineScansDone = 0;
    g_score             = 0;
    g_pwnaDetected      = false;
    g_probeWindowStart  = millis();
    g_spamWindowStart   = millis();
    g_lastDecay         = millis();
    g_lastScan          = 0;
    g_lastHeartbeat     = millis();

    Serial.println("[canary] setup done — starting baseline learning");
    emitEvent("boot", nullptr, 0, "starting baseline learning");
}

// ============================================================
// LOOP
// ============================================================

void loop() {
    unsigned long now = millis();
    const uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < g_minFreeHeap) g_minFreeHeap = freeHeap;

    boardTick(g_state, g_score, g_scoreReason, g_lastSource, g_lastSsid,
              g_lastEventChannel, g_lastEventRssi, g_baselineLearned);
    channelHop();
    drainDeauthQueue();
    drainPwnaQueue();

    if (g_baselineLearned) {
        analyzeDeauthSources();
        analyzeProbeFlood();
        analyzePwnagotchi();
    }

    scoreDecay();
    updateState();
    printHeartbeat();
    handleButton();
    handleSerialCommands();

    if (!g_baselineLearned) {
        if (now - g_lastScan >= BASELINE_SCAN_INTERVAL_MS)
            performScan(true);
    } else {
        if (now - g_lastScan >= SCAN_INTERVAL_MS)
            performScan(false);
    }

    delay(10);
}
