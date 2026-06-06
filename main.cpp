/*
 * Target:  M5Stack Atom Lite  (ESP32, single SK6812 RGB LED on GPIO27)
 * Purpose: Passive 2.4 GHz WiFi awareness sensor.
 *          Monitors for deauth bursts, evil-twin / open-clone SSIDs,
 *          security downgrades, and beacon floods.
 *          No network connections, no packet injection, no credential capture.
 *
 * LED legend:
 *   Blue  (pulse)  — startup / baseline learning
 *   Green (solid)  — environment looks normal
 *   Yellow (solid) — caution: suspicious pattern observed
 *   Red  (pulse)   — alert: higher-confidence threat pattern detected
 *
 * Serial output: 115200 baud, JSON-style log lines.
 */

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

// NeoPixel only on Atom Lite (default). DevKit build uses plain GPIO LED.
#ifndef DEVKIT_LED
  #include <Adafruit_NeoPixel.h>
#endif

// ============================================================
// HARDWARE PINOUT — M5Stack Atom Lite
// ============================================================

#ifndef DEVKIT_LED
  #define LED_PIN       27   // SK6812 data in
  #define NUM_LEDS       1
  Adafruit_NeoPixel pixel(NUM_LEDS, LED_PIN, NEO_GRB + NEO_KHZ800);
#else
  // Generic DevKit fallback: onboard LED on GPIO2 (binary, no color)
  #define DEVKIT_LED_PIN 2
#endif

#define BUTTON_PIN     39   // Active-low tactile button on Atom Lite

// ============================================================
// CONFIGURATION
// ============================================================

// --- Baseline learning ---
// The device performs BASELINE_SCANS quick scans on startup to build a
// reference table of "known" access points before it starts threat analysis.
#define BASELINE_SCANS          3
#define BASELINE_SCAN_INTERVAL_MS  8000   // ms between baseline scans

// --- Normal operation scan cycle ---
#define SCAN_INTERVAL_MS       20000   // re-scan every 20 s during operation

// --- Promiscuous / channel hop ---
static const uint8_t HOP_CHANNELS[]    = {1, 6, 11};
static const size_t  HOP_CHANNEL_COUNT = 3;
#define CHANNEL_DWELL_MS        300    // ms per channel before hopping

// --- Deauth / disassoc burst detection ---
// Counts deauth/disassoc management frames (subtypes 10 + 12) per source
// within a rolling DEAUTH_WINDOW_MS window.
#define DEAUTH_WINDOW_MS            5000
#define DEAUTH_CAUTION_THRESHOLD       8   // frames/window → caution +2 pts
#define DEAUTH_ALERT_THRESHOLD        20   // frames/window → alert  +4 pts
#define DEAUTH_BROADCAST_THRESHOLD     5   // broadcast deauths → +1 pt
#define MAX_DEAUTH_SOURCES            24   // max distinct sources tracked

// --- AP table ---
#define MAX_APS                   96
#define SSID_LEN                  33

// --- Beacon / SSID spam ---
// Counts new SSIDs not seen in baseline within a rolling SPAM_WINDOW_MS window.
#define SPAM_WINDOW_MS           30000
#define SPAM_CAUTION_THRESHOLD      15   // new SSIDs in window → +2 pts
#define SPAM_ALERT_THRESHOLD        30   // new SSIDs in window → +3 pts
#define MAX_SPAM_SSIDS_TRACKED      64

// --- RSSI thresholds ---
#define RSSI_MIN                   -95   // ignore frames weaker than this
// clone is this many dB stronger than known AP → extra +1 pt
#define RSSI_STRONGER_BY            10

// --- Confidence score thresholds ---
#define SCORE_CAUTION               3
#define SCORE_ALERT                 6
#define SCORE_MAX                  20
// The score decays by SCORE_DECAY_AMOUNT every SCORE_DECAY_INTERVAL_MS
// so the device self-resets if the threat disappears.
#define SCORE_DECAY_INTERVAL_MS  60000
#define SCORE_DECAY_AMOUNT           1

// --- Serial heartbeat ---
#define HEARTBEAT_MS             30000

// --- LED brightness (0–255) — dim for eye comfort ---
#define LED_DIM                    120   // global brightness cap on NeoPixel

// ============================================================
// DEVICE STATE MACHINE
// ============================================================

typedef enum : uint8_t {
    STATE_STARTUP = 0,   // blue pulse  — building baseline
    STATE_NORMAL  = 1,   // green solid — clean environment
    STATE_CAUTION = 2,   // yellow      — suspicious pattern
    STATE_ALERT   = 3,   // red pulse   — high-confidence threat
} CanaryState;

static CanaryState   g_state         = STATE_STARTUP;
static unsigned long g_stateChangedAt = 0;

// ============================================================
// AP TABLE
// ============================================================

typedef enum : uint8_t {
    AUTH_OPEN    = 0,
    AUTH_WEP     = 1,
    AUTH_WPA     = 2,
    AUTH_WPA2    = 3,
    AUTH_WPA3    = 4,
    AUTH_WPA2E   = 5,
    AUTH_UNKNOWN = 0xFF,
} AuthStrength;

typedef struct {
    char         ssid[SSID_LEN];
    uint8_t      bssid[6];
    int8_t       rssi;
    uint8_t      channel;
    AuthStrength auth;
    bool         inBaseline;   // true once baseline learning complete
    bool         activeScan;   // seen in the most recent scan pass
    unsigned long firstSeen;   // millis()
    unsigned long lastSeen;    // millis()
} KnownAP;

static KnownAP g_aps[MAX_APS];
static int     g_apCount         = 0;
static bool    g_baselineLearned  = false;
static int     g_baselineScansDone = 0;

// ============================================================
// DEAUTH TRACKING  — callback → loop via lock-free ring buffer
// ============================================================

#define DEAUTH_QUEUE_SIZE  64

typedef struct {
    uint8_t src[6];      // addr2 (transmitter)
    uint8_t dst[6];      // addr1 (receiver; ff:ff:ff:ff:ff:ff = broadcast)
    uint8_t subtype;     // 10 = disassoc, 12 = deauth
    int8_t  rssi;
    uint8_t channel;
} DeauthFrame;

static volatile DeauthFrame g_deauthQ[DEAUTH_QUEUE_SIZE];
static volatile size_t      g_dqHead  = 0;   // written by WiFi task (ISR-context)
static volatile size_t      g_dqTail  = 0;   // read by loop()
static portMUX_TYPE         g_dqMux   = portMUX_INITIALIZER_UNLOCKED;

// Per-source counters (loop-thread only — no concurrency concern)
typedef struct {
    uint8_t       src[6];
    uint32_t      count;           // total frames in current window
    uint32_t      broadcastCount;  // frames sent to ff:ff:ff:ff:ff:ff
    unsigned long windowStart;     // millis() when window opened
    bool          inUse;
} DeauthSrc;

static DeauthSrc g_deauthSrc[MAX_DEAUTH_SOURCES];

// ============================================================
// BEACON / SSID SPAM TRACKER  (loop-thread only)
// ============================================================

static char          g_spamSSIDs[MAX_SPAM_SSIDS_TRACKED][SSID_LEN];
static int           g_spamCount    = 0;
static int           g_spamNew      = 0;    // new-to-tracker SSIDs since window opened
static unsigned long g_spamWindowStart = 0;

// ============================================================
// CONFIDENCE SCORE
// ============================================================

static int           g_score       = 0;
static char          g_scoreReason[72] = "";  // last event that raised the score
static unsigned long g_lastDecay   = 0;

static void scoreAdd(int pts, const char* reason) {
    if (pts <= 0) return;
    g_score += pts;
    if (g_score > SCORE_MAX) g_score = SCORE_MAX;
    if (reason && reason[0]) {
        strncpy(g_scoreReason, reason, sizeof(g_scoreReason) - 1);
        g_scoreReason[sizeof(g_scoreReason) - 1] = '\0';
    }
    Serial.printf("[canary] score +%d → %d  \"%s\"\n", pts, g_score, reason ? reason : "");
}

static void scoreDecay() {
    if (millis() - g_lastDecay < SCORE_DECAY_INTERVAL_MS) return;
    g_lastDecay = millis();
    if (g_score > 0) {
        g_score -= SCORE_DECAY_AMOUNT;
        if (g_score < 0) g_score = 0;
        Serial.printf("[canary] score decay → %d\n", g_score);
    }
}

// ============================================================
// 802.11 FRAME HEADER
// ============================================================

typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];   // receiver / destination
    uint8_t  addr2[6];   // transmitter / source
    uint8_t  addr3[6];   // BSSID (mgmt frames)
    uint16_t seq_ctrl;
} ieee80211_hdr_t;

// ============================================================
// LED CONTROL
// ============================================================

static unsigned long g_ledLastUpdate = 0;
#define LED_TICK_MS  80   // refresh rate for smooth pulse

static void ledSetRGB(uint8_t r, uint8_t g, uint8_t b) {
#ifndef DEVKIT_LED
    pixel.setPixelColor(0, pixel.Color(r, g, b));
    pixel.show();
#else
    // DevKit: any non-zero color turns the LED on
    digitalWrite(DEVKIT_LED_PIN, (r | g | b) ? HIGH : LOW);
#endif
}

static void ledTick() {
    unsigned long now = millis();
    if (now - g_ledLastUpdate < LED_TICK_MS) return;
    g_ledLastUpdate = now;

    switch (g_state) {
        case STATE_STARTUP: {
            // Slow blue breathing pulse (2 s period)
            float phase = (float)(now % 2000) / 2000.0f;
            float bright = 0.25f + 0.75f * (phase < 0.5f ? phase * 2.0f : (1.0f - phase) * 2.0f);
            ledSetRGB(0, 0, (uint8_t)(60 * bright));
            break;
        }
        case STATE_NORMAL:
            ledSetRGB(0, 40, 0);
            break;
        case STATE_CAUTION:
            ledSetRGB(70, 35, 0);
            break;
        case STATE_ALERT: {
            // Fast red pulse (0.8 s period)
            float phase = (float)(now % 800) / 800.0f;
            float bright = 0.35f + 0.65f * (phase < 0.5f ? phase * 2.0f : (1.0f - phase) * 2.0f);
            ledSetRGB((uint8_t)(110 * bright), 0, 0);
            break;
        }
    }
}

// One-shot scan-in-progress indicator (brief cyan flash)
static void ledScanFlash() {
    ledSetRGB(0, 30, 40);
#ifndef DEVKIT_LED
    pixel.show();
#endif
}

// ============================================================
// PROMISCUOUS MODE
// ============================================================

static bool          g_promisc      = false;
static uint8_t       g_curChannel   = 1;
static size_t        g_hopIdx       = 0;
static unsigned long g_lastHop      = 0;

// Promiscuous receive callback — runs in WiFi task context.
// Must be IRAM-resident, no Serial, no malloc, no blocking.
static void IRAM_ATTR wifiSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf || type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < (uint32_t)sizeof(ieee80211_hdr_t)) return;

    int8_t rssi = pkt->rx_ctrl.rssi;
    if (rssi < RSSI_MIN) return;

    ieee80211_hdr_t* hdr = (ieee80211_hdr_t*)pkt->payload;
    uint8_t fc0     = (uint8_t)(hdr->frame_ctrl & 0xFF);
    uint8_t ftype   = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    // Management frames only; subtype 10 = disassoc, 12 = deauth
    if (ftype != 0) return;
    if (subtype != 10 && subtype != 12) return;

    portENTER_CRITICAL_ISR(&g_dqMux);
    size_t next = (g_dqHead + 1) % DEAUTH_QUEUE_SIZE;
    if (next != g_dqTail) {   // drop silently if queue full
        DeauthFrame* f = (DeauthFrame*)&g_deauthQ[g_dqHead];
        memcpy((void*)f->src, hdr->addr2, 6);
        memcpy((void*)f->dst, hdr->addr1, 6);
        f->subtype = subtype;
        f->rssi    = rssi;
        f->channel = (uint8_t)pkt->rx_ctrl.channel;
        g_dqHead   = next;
    }
    portEXIT_CRITICAL_ISR(&g_dqMux);
}

static void promiscStart() {
    if (g_promisc) return;
    WiFi.mode(WIFI_STA);
    // Filter to management frames only — reduces ISR load
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&wifiSniffer);
    esp_wifi_set_promiscuous(true);
    g_hopIdx    = 0;
    g_curChannel = HOP_CHANNELS[0];
    esp_wifi_set_channel(g_curChannel, WIFI_SECOND_CHAN_NONE);
    g_lastHop   = millis();
    g_promisc   = true;
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
// DEAUTH ANALYSIS  (loop-thread)
// ============================================================

static inline bool isBroadcastMAC(const uint8_t* m) {
    return m[0] == 0xFF && m[1] == 0xFF && m[2] == 0xFF &&
           m[3] == 0xFF && m[4] == 0xFF && m[5] == 0xFF;
}

// Drain the ring buffer and accumulate into per-source counters.
static void drainDeauthQueue() {
    while (true) {
        portENTER_CRITICAL(&g_dqMux);
        bool empty = (g_dqHead == g_dqTail);
        portEXIT_CRITICAL(&g_dqMux);
        if (empty) break;

        DeauthFrame frame;
        portENTER_CRITICAL(&g_dqMux);
        memcpy(&frame, (void*)&g_deauthQ[g_dqTail], sizeof(DeauthFrame));
        g_dqTail = (g_dqTail + 1) % DEAUTH_QUEUE_SIZE;
        portEXIT_CRITICAL(&g_dqMux);

        unsigned long now = millis();

        // Find existing source entry by MAC
        DeauthSrc* slot = nullptr;
        for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
            if (g_deauthSrc[i].inUse &&
                memcmp(g_deauthSrc[i].src, frame.src, 6) == 0) {
                slot = &g_deauthSrc[i];
                break;
            }
        }
        // Allocate new slot if needed
        if (!slot) {
            for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
                if (!g_deauthSrc[i].inUse) {
                    slot = &g_deauthSrc[i];
                    memcpy(slot->src, frame.src, 6);
                    slot->count          = 0;
                    slot->broadcastCount = 0;
                    slot->windowStart    = now;
                    slot->inUse          = true;
                    break;
                }
            }
        }
        if (!slot) continue;   // table full — drop

        // Roll window if expired
        if (now - slot->windowStart > DEAUTH_WINDOW_MS) {
            slot->count          = 0;
            slot->broadcastCount = 0;
            slot->windowStart    = now;
        }

        slot->count++;
        if (isBroadcastMAC(frame.dst)) slot->broadcastCount++;
    }
}

// Score the accumulated deauth counters. Called each loop iteration.
static void analyzeDeauthSources() {
    unsigned long now = millis();
    for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
        if (!g_deauthSrc[i].inUse) continue;
        // Only evaluate sources with an active (non-expired) window
        if (now - g_deauthSrc[i].windowStart > DEAUTH_WINDOW_MS) continue;

        uint32_t cnt  = g_deauthSrc[i].count;
        uint32_t bcnt = g_deauthSrc[i].broadcastCount;

        if (cnt >= (uint32_t)DEAUTH_ALERT_THRESHOLD) {
            scoreAdd(4, "deauth/disassoc burst (alert-level rate)");
            Serial.printf("[canary] DEAUTH ALERT: %lu frames/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        } else if (cnt >= (uint32_t)DEAUTH_CAUTION_THRESHOLD) {
            scoreAdd(2, "deauth/disassoc burst (elevated rate)");
            Serial.printf("[canary] DEAUTH caution: %lu frames/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        }

        if (bcnt >= (uint32_t)DEAUTH_BROADCAST_THRESHOLD) {
            scoreAdd(1, "broadcast deauth frames observed");
            Serial.printf("[canary] broadcast deauth: %lu frames src=%02x:%02x:%02x:...\n",
                          (unsigned long)bcnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        }
    }
}

// ============================================================
// AP TABLE HELPERS
// ============================================================

static AuthStrength mapAuth(wifi_auth_mode_t m) {
    switch (m) {
        case WIFI_AUTH_OPEN:              return AUTH_OPEN;
        case WIFI_AUTH_WEP:               return AUTH_WEP;
        case WIFI_AUTH_WPA_PSK:           return AUTH_WPA;
        case WIFI_AUTH_WPA2_PSK:          return AUTH_WPA2;
        case WIFI_AUTH_WPA_WPA2_PSK:      return AUTH_WPA2;
        case WIFI_AUTH_WPA3_PSK:          return AUTH_WPA3;
        case WIFI_AUTH_WPA2_ENTERPRISE:   return AUTH_WPA2E;
        default:                          return AUTH_UNKNOWN;
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

// Returns a simple "strength rank" where higher = more secure.
static uint8_t authRank(AuthStrength a) {
    switch (a) {
        case AUTH_OPEN:  return 0;
        case AUTH_WEP:   return 1;
        case AUTH_WPA:   return 2;
        case AUTH_WPA2:  return 3;
        case AUTH_WPA2E: return 4;
        case AUTH_WPA3:  return 5;
        default:         return 0;
    }
}

static void macStr(const uint8_t* m, char* buf) {   // buf must be ≥18 bytes
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static KnownAP* findByBSSID(const uint8_t* bssid) {
    for (int i = 0; i < g_apCount; i++)
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0) return &g_aps[i];
    return nullptr;
}

// Add new AP or update existing entry.
static KnownAP* upsertAP(const char* ssid, const uint8_t* bssid,
                          int8_t rssi, uint8_t ch, AuthStrength auth) {
    unsigned long now = millis();
    KnownAP* e = findByBSSID(bssid);
    if (e) {
        e->rssi      = rssi;
        e->channel   = ch;
        e->auth      = auth;
        e->lastSeen  = now;
        e->activeScan = true;
        if (!e->ssid[0] && ssid && ssid[0])
            strncpy(e->ssid, ssid, SSID_LEN - 1);
        return e;
    }
    if (g_apCount >= MAX_APS) return nullptr;
    KnownAP* ap   = &g_aps[g_apCount++];
    memset(ap, 0, sizeof(KnownAP));
    if (ssid) strncpy(ap->ssid, ssid, SSID_LEN - 1);
    memcpy(ap->bssid, bssid, 6);
    ap->rssi       = rssi;
    ap->channel    = ch;
    ap->auth       = auth;
    ap->inBaseline = false;
    ap->activeScan = true;
    ap->firstSeen  = now;
    ap->lastSeen   = now;
    return ap;
}

static void markAllInactive() {
    for (int i = 0; i < g_apCount; i++) g_aps[i].activeScan = false;
}

// ============================================================
// BEACON / SSID SPAM  (called after each normal scan)
// ============================================================

static void updateSpamTracker(int scanCount) {
    unsigned long now = millis();
    if (now - g_spamWindowStart > SPAM_WINDOW_MS) {
        g_spamWindowStart = now;
        g_spamNew         = 0;
        g_spamCount       = 0;
    }

    for (int i = 0; i < scanCount; i++) {
        String s = WiFi.SSID(i);
        if (s.length() == 0) continue;
        const char* ssid = s.c_str();

        // Already seen in this spam-tracker window?
        bool seenInWindow = false;
        for (int j = 0; j < g_spamCount; j++) {
            if (strcmp(g_spamSSIDs[j], ssid) == 0) { seenInWindow = true; break; }
        }
        if (!seenInWindow && g_spamCount < MAX_SPAM_SSIDS_TRACKED) {
            strncpy(g_spamSSIDs[g_spamCount++], ssid, SSID_LEN - 1);
        }

        // Was this SSID present in baseline?
        bool inBaseline = false;
        for (int j = 0; j < g_apCount; j++) {
            if (g_aps[j].inBaseline && strcasecmp(g_aps[j].ssid, ssid) == 0) {
                inBaseline = true; break;
            }
        }
        if (!inBaseline && !seenInWindow) g_spamNew++;
    }

    if (g_spamNew >= SPAM_ALERT_THRESHOLD) {
        scoreAdd(3, "beacon/SSID flood: very high new-SSID count");
        Serial.printf("[canary] SPAM ALERT: %d new SSIDs in %d s window\n",
                      g_spamNew, SPAM_WINDOW_MS / 1000);
    } else if (g_spamNew >= SPAM_CAUTION_THRESHOLD) {
        scoreAdd(2, "beacon/SSID flood: elevated new-SSID count");
        Serial.printf("[canary] SPAM caution: %d new SSIDs in %d s window\n",
                      g_spamNew, SPAM_WINDOW_MS / 1000);
    }
}

// ============================================================
// SCAN-BASED THREAT ANALYSIS  (called after each normal scan)
// ============================================================

static void analyzeScanThreats(int scanCount) {
    for (int i = 0; i < scanCount; i++) {
        String ssidStr = WiFi.SSID(i);
        if (ssidStr.length() == 0) continue;
        const char*  ssid  = ssidStr.c_str();
        uint8_t*     bssid = WiFi.BSSID(i);
        int8_t       rssi  = (int8_t)WiFi.RSSI(i);
        AuthStrength auth  = mapAuth(WiFi.encryptionType(i));
        uint8_t      ch    = (uint8_t)WiFi.channel(i);

        if (!bssid) continue;

        // Is this BSSID new (not in our baseline)?
        KnownAP* thisEntry = findByBSSID(bssid);
        bool bssidIsNew = (!thisEntry || !thisEntry->inBaseline);

        // Find the strongest-RSSI baseline entry for this SSID
        // (in mesh/enterprise there can be many — we want the expected primary)
        KnownAP* baseAP = nullptr;
        for (int j = 0; j < g_apCount; j++) {
            if (!g_aps[j].inBaseline) continue;
            if (strcasecmp(g_aps[j].ssid, ssid) != 0) continue;
            if (!baseAP || g_aps[j].rssi > baseAP->rssi) baseAP = &g_aps[j];
        }

        // No baseline entry for this SSID → nothing to compare against yet
        if (!baseAP) continue;

        char bssidBuf[18];
        macStr(bssid, bssidBuf);

        // ── Detection 1: Open clone of known encrypted network ────────────
        // This is the highest-confidence evil-twin pattern.
        if (auth == AUTH_OPEN && baseAP->auth != AUTH_OPEN) {
            int pts = 3;
            if (bssidIsNew)                               pts++;  // unexpected source
            if (rssi > baseAP->rssi + RSSI_STRONGER_BY)  pts++;  // suspiciously strong
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "open clone of encrypted SSID '%.28s'", ssid);
            scoreAdd(pts, reason);
            Serial.printf("[canary] OPEN CLONE: SSID='%s' baseline=%s clone=OPEN "
                          "bssid=%s rssi=%d/%d\n",
                          ssid, authStr(baseAP->auth), bssidBuf, rssi, baseAP->rssi);
            continue;   // don't double-score
        }

        // ── Detection 2: Security downgrade — same SSID, weaker encryption ─
        if (baseAP->auth != AUTH_UNKNOWN &&
            auth  != AUTH_UNKNOWN &&
            auth  != AUTH_OPEN &&           // already handled above
            authRank(auth) < authRank(baseAP->auth)) {

            // Score severity by how severe the downgrade is
            int delta = (int)authRank(baseAP->auth) - (int)authRank(auth);
            int pts = (delta >= 2) ? 3 : 1;

            char reason[72];
            snprintf(reason, sizeof(reason),
                     "security downgrade '%.24s': %s→%s",
                     ssid, authStr(baseAP->auth), authStr(auth));
            scoreAdd(pts, reason);
            Serial.printf("[canary] SEC DOWNGRADE: SSID='%s' was=%s now=%s bssid=%s\n",
                          ssid, authStr(baseAP->auth), authStr(auth), bssidBuf);
        }

        // ── Detection 3: Duplicate SSID from unexpected vendor ────────────
        // Same SSID and same security as baseline, but different OUI.
        // Common in enterprise/mesh — only score as caution. Combine with
        // other signals for a more confident alert.
        if (bssidIsNew && auth == baseAP->auth) {
            // Compare top 3 bytes (vendor OUI)
            if (memcmp(baseAP->bssid, bssid, 3) != 0) {
                int pts = 1;
                if (rssi > baseAP->rssi + RSSI_STRONGER_BY) pts++;  // stronger = suspicious
                char reason[72];
                snprintf(reason, sizeof(reason),
                         "dup SSID diff vendor: '%.30s'", ssid);
                scoreAdd(pts, reason);
                Serial.printf("[canary] DUP SSID: SSID='%s' known-oui=%02x:%02x:%02x "
                              "new-oui=%02x:%02x:%02x rssi=%d/%d\n",
                              ssid,
                              baseAP->bssid[0], baseAP->bssid[1], baseAP->bssid[2],
                              bssid[0], bssid[1], bssid[2],
                              rssi, baseAP->rssi);
            }
        }
    }

    // ── Detection 4: Original encrypted AP absent, open version present ──
    // Covers the case where the attacker suppresses/blocks the real AP and
    // only their open clone is visible. Checked per-baseline-AP, not per-scan.
    for (int j = 0; j < g_apCount; j++) {
        if (!g_aps[j].inBaseline)          continue;   // not a baseline AP
        if (g_aps[j].auth == AUTH_OPEN)    continue;   // only care about encrypted
        if (g_aps[j].activeScan)           continue;   // still visible — fine

        // Baseline encrypted AP is gone. Is there an open AP with the same SSID?
        for (int i = 0; i < scanCount; i++) {
            if (WiFi.encryptionType(i) != WIFI_AUTH_OPEN) continue;
            if (strcasecmp(WiFi.SSID(i).c_str(), g_aps[j].ssid) != 0) continue;

            char reason[72];
            snprintf(reason, sizeof(reason),
                     "original AP gone, open clone present: '%.26s'", g_aps[j].ssid);
            scoreAdd(3, reason);
            Serial.printf("[canary] ABSENT+CLONE: original encrypted AP '%s' gone, "
                          "open version present\n", g_aps[j].ssid);
        }
    }
}

// ============================================================
// WIFI SCAN  (stops promiscuous, scans, restarts promiscuous)
// ============================================================

static unsigned long g_lastScan = 0;

static void performScan(bool isBaseline) {
    promiscStop();
    ledScanFlash();

    Serial.printf("[canary] %s scan start (aps=%d score=%d)\n",
                  isBaseline ? "baseline" : "normal", g_apCount, g_score);

    markAllInactive();

    int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
    g_lastScan = millis();

    if (n < 0) {
        Serial.printf("[canary] scan error: %d\n", n);
        promiscStart();
        return;
    }

    Serial.printf("[canary] scan found %d APs\n", n);

    // Update AP table with scan results
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
        if (g_baselineScansDone >= BASELINE_SCANS) {
            g_baselineLearned = true;
            for (int i = 0; i < g_apCount; i++) g_aps[i].inBaseline = true;
            Serial.printf("[canary] baseline complete: %d APs learned\n", g_apCount);
            for (int i = 0; i < g_apCount; i++) {
                char bssidBuf[18];
                macStr(g_aps[i].bssid, bssidBuf);
                Serial.printf("  [%02d] %-32s %s ch%02u %-8s %d dBm\n",
                              i, g_aps[i].ssid, bssidBuf,
                              g_aps[i].channel, authStr(g_aps[i].auth), g_aps[i].rssi);
            }
        } else {
            Serial.printf("[canary] baseline scan %d/%d\n",
                          g_baselineScansDone, BASELINE_SCANS);
        }
    } else {
        // Run all scan-based threat detections
        updateSpamTracker(n);
        analyzeScanThreats(n);
    }

    WiFi.scanDelete();
    promiscStart();
}

// ============================================================
// CANARY STATE UPDATE
// ============================================================

static void updateState() {
    CanaryState next;
    if (!g_baselineLearned) {
        next = STATE_STARTUP;
    } else if (g_score >= SCORE_ALERT) {
        next = STATE_ALERT;
    } else if (g_score >= SCORE_CAUTION) {
        next = STATE_CAUTION;
    } else {
        next = STATE_NORMAL;
    }

    if (next != g_state) {
        static const char* stateNames[] = { "STARTUP", "NORMAL", "CAUTION", "ALERT" };
        Serial.printf("[canary] %s → %s  (score=%d  \"%s\")\n",
                      stateNames[g_state], stateNames[next],
                      g_score, g_scoreReason);
        g_state         = next;
        g_stateChangedAt = millis();
    }
}

// ============================================================
// HEARTBEAT
// ============================================================

static unsigned long g_lastHeartbeat = 0;

static void printHeartbeat() {
    if (millis() - g_lastHeartbeat < HEARTBEAT_MS) return;
    g_lastHeartbeat = millis();
    static const char* stateNames[] = { "STARTUP", "NORMAL", "CAUTION", "ALERT" };
    Serial.printf("[canary] hb: state=%s score=%d reason=\"%s\" aps=%d ch=%u\n",
                  stateNames[g_state], g_score, g_scoreReason,
                  g_apCount, g_curChannel);
}

// ============================================================
// BUTTON  — press to dump current AP table and reset score
// ============================================================

static uint32_t     g_btnLastMs   = 0;
static bool         g_btnLastState = true;   // active-low → idle=HIGH

static void handleButton() {
    bool pressed = (digitalRead(BUTTON_PIN) == LOW);
    // Simple debounce: require 50 ms held
    if (pressed && !g_btnLastState && (millis() - g_btnLastMs > 50)) {
        Serial.println("[canary] button: dumping AP table and resetting score");
        for (int i = 0; i < g_apCount; i++) {
            char bssidBuf[18];
            macStr(g_aps[i].bssid, bssidBuf);
            Serial.printf("  ap[%02d] %-32s %s ch%02u %-8s %3d dBm %s\n",
                          i, g_aps[i].ssid, bssidBuf,
                          g_aps[i].channel, authStr(g_aps[i].auth), g_aps[i].rssi,
                          g_aps[i].inBaseline ? "[baseline]" : "");
        }
        // Reset score so user can observe a fresh baseline
        g_score = 0;
        g_scoreReason[0] = '\0';
        Serial.println("[canary] score reset to 0");
        g_btnLastMs = millis();
    }
    g_btnLastState = pressed;
}

// ============================================================
// SETUP
// ============================================================

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println();
    Serial.println("==============================================");
    Serial.println("Travel WiFi Canary v1.0");
    Serial.println(" Passive 2.4 GHz awareness sensor");
    Serial.println("==============================================");

#ifndef DEVKIT_LED
    pixel.begin();
    pixel.setBrightness(LED_DIM);
    pixel.setPixelColor(0, pixel.Color(0, 0, 60));
    pixel.show();
#else
    pinMode(DEVKIT_LED_PIN, OUTPUT);
    digitalWrite(DEVKIT_LED_PIN, HIGH);
#endif

    pinMode(BUTTON_PIN, INPUT_PULLUP);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    // Initialize all tracking state
    memset(g_aps,         0, sizeof(g_aps));
    memset(g_deauthSrc,   0, sizeof(g_deauthSrc));
    memset(g_spamSSIDs,   0, sizeof(g_spamSSIDs));
    g_apCount          = 0;
    g_baselineLearned  = false;
    g_baselineScansDone = 0;
    g_score            = 0;
    g_spamWindowStart  = millis();
    g_lastDecay        = millis();
    g_lastScan         = 0;                // force immediate first scan
    g_lastHeartbeat    = millis();
    g_ledLastUpdate    = millis();

    Serial.println("[canary] setup done — starting baseline learning");
}

// ============================================================
// LOOP
// ============================================================

void loop() {
    unsigned long now = millis();

    // LED rendering (smooth pulse / solid color)
    ledTick();

    // Channel hopping in promiscuous mode
    channelHop();

    // Drain promiscuous deauth queue and score
    drainDeauthQueue();
    if (g_baselineLearned) analyzeDeauthSources();

    // Score decay (passive self-reset)
    scoreDecay();

    // Update device state from current score
    updateState();

    // Periodic heartbeat to serial
    printHeartbeat();

    // Button handler (dump table / reset score)
    handleButton();

    // Scan scheduler
    if (!g_baselineLearned) {
        // Baseline phase: fast scans until we have enough reference data
        if (now - g_lastScan >= BASELINE_SCAN_INTERVAL_MS) {
            performScan(/*isBaseline=*/true);
        }
    } else {
        // Normal operation: periodic re-scan and threat analysis
        if (now - g_lastScan >= SCAN_INTERVAL_MS) {
            performScan(/*isBaseline=*/false);
        }
    }

    delay(10);
}
