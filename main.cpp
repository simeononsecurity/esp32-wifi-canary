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

#ifndef DEVKIT_LED
  #include <Adafruit_NeoPixel.h>
#endif

// ============================================================
// HARDWARE — M5Stack Atom Lite
// ============================================================

#ifndef DEVKIT_LED
  #define LED_PIN    27
  #define NUM_LEDS    1
  Adafruit_NeoPixel pixel(NUM_LEDS, LED_PIN, NEO_GRB + NEO_KHZ800);
#else
  #define DEVKIT_LED_PIN 2
#endif

#define BUTTON_PIN  39

// ============================================================
// CONFIGURATION
// ============================================================

// Baseline learning
#define BASELINE_SCANS             3
#define BASELINE_SCAN_INTERVAL_MS  8000

// Normal operation
#define SCAN_INTERVAL_MS          20000

// Channel hop (promiscuous mode)
static const uint8_t HOP_CHANNELS[]    = {1, 6, 11};
static const size_t  HOP_CHANNEL_COUNT = 3;
#define CHANNEL_DWELL_MS           300

// ── Deauth / disassoc burst ───────────────────────────────────
#define DEAUTH_WINDOW_MS            5000
#define DEAUTH_CAUTION_THRESHOLD       8
#define DEAUTH_ALERT_THRESHOLD        20
#define DEAUTH_BROADCAST_THRESHOLD     5
#define MAX_DEAUTH_SOURCES            24

// ── Probe request flood ───────────────────────────────────────
// Counts 802.11 probe-request frames in a rolling window.
// A sudden flood correlates with deauth attacks (clients scanning
// for alternatives) or aggressive scanning tools.
#define PROBE_WINDOW_MS           10000
#define PROBE_CAUTION_THRESHOLD      40   // probes / 10 s → caution
#define PROBE_ALERT_THRESHOLD        80   // probes / 10 s → alert

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
#define SPAM_CAUTION_THRESHOLD      15
#define SPAM_ALERT_THRESHOLD        30
#define MAX_SPAM_SSIDS_TRACKED      64

// ── RSSI ─────────────────────────────────────────────────────
#define RSSI_MIN                   -95
#define RSSI_STRONGER_BY            10

// ── Confidence scoring ────────────────────────────────────────
#define SCORE_CAUTION               3
#define SCORE_ALERT                 6
#define SCORE_MAX                  20
#define SCORE_DECAY_INTERVAL_MS  60000
#define SCORE_DECAY_AMOUNT           1

// ── Misc ──────────────────────────────────────────────────────
#define HEARTBEAT_MS             30000
#define LED_DIM                    120

// ============================================================
// DEVICE STATE
// ============================================================

typedef enum : uint8_t {
    STATE_STARTUP = 0,
    STATE_NORMAL  = 1,
    STATE_CAUTION = 2,
    STATE_ALERT   = 3,
} CanaryState;

static CanaryState   g_state          = STATE_STARTUP;
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
static portMUX_TYPE         g_dqMux  = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    uint8_t       src[6];
    uint32_t      count;
    uint32_t      broadcastCount;
    unsigned long windowStart;
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
} PwnaRawEvent;

static volatile PwnaRawEvent g_pwnaQ[PWNA_QUEUE_SIZE];
static volatile size_t       g_pwnaHead = 0;
static volatile size_t       g_pwnaTail = 0;
static portMUX_TYPE          g_pwnaMux  = portMUX_INITIALIZER_UNLOCKED;

static bool          g_pwnaDetected = false;
static bool          g_pwnaDeauth   = false;
static char          g_pwnaName[32] = "";
static int8_t        g_pwnaRssi     = -100;
static unsigned long g_pwnaLastSeen = 0;

// Pwnagotchi's well-known fixed MAC address
static const uint8_t PWNA_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

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
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} ieee80211_hdr_t;

// ============================================================
// LED CONTROL
// ============================================================

static unsigned long g_ledLastUpdate = 0;
#define LED_TICK_MS 80

static void ledSetRGB(uint8_t r, uint8_t g, uint8_t b) {
#ifndef DEVKIT_LED
    pixel.setPixelColor(0, pixel.Color(r, g, b));
    pixel.show();
#else
    digitalWrite(DEVKIT_LED_PIN, (r | g | b) ? HIGH : LOW);
#endif
}

static void ledTick() {
    unsigned long now = millis();
    if (now - g_ledLastUpdate < LED_TICK_MS) return;
    g_ledLastUpdate = now;

    switch (g_state) {
        case STATE_STARTUP: {
            float ph = (float)(now % 2000) / 2000.0f;
            float br = 0.25f + 0.75f * (ph < 0.5f ? ph * 2.0f : (1.0f - ph) * 2.0f);
            ledSetRGB(0, 0, (uint8_t)(60 * br));
            break;
        }
        case STATE_NORMAL:
            ledSetRGB(0, 40, 0);
            break;
        case STATE_CAUTION:
            ledSetRGB(70, 35, 0);
            break;
        case STATE_ALERT: {
            float ph = (float)(now % 800) / 800.0f;
            float br = 0.35f + 0.65f * (ph < 0.5f ? ph * 2.0f : (1.0f - ph) * 2.0f);
            ledSetRGB((uint8_t)(110 * br), 0, 0);
            break;
        }
    }
}

static void ledScanFlash() {
    ledSetRGB(0, 30, 40);
#ifndef DEVKIT_LED
    pixel.show();
#endif
}

// ============================================================
// PROMISCUOUS MODE
// ============================================================

static bool          g_promisc    = false;
static uint8_t       g_curChannel = 1;
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
    if (pkt->rx_ctrl.sig_len < (uint32_t)sizeof(ieee80211_hdr_t)) return;

    int8_t rssi = pkt->rx_ctrl.rssi;
    if (rssi < RSSI_MIN) return;

    ieee80211_hdr_t* hdr = (ieee80211_hdr_t*)pkt->payload;
    uint8_t fc0     = (uint8_t)(hdr->frame_ctrl & 0xFF);
    uint8_t ftype   = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    if (ftype != 0) return;   // management frames only

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
        if (hdr->addr2[0] == PWNA_MAC[0] &&
            hdr->addr2[1] == PWNA_MAC[1] &&
            hdr->addr2[2] == PWNA_MAC[2] &&
            hdr->addr2[3] == PWNA_MAC[3] &&
            hdr->addr2[4] == PWNA_MAC[4] &&
            hdr->addr2[5] == PWNA_MAC[5]) {

            // Beacon fixed fields: 12 bytes after the 24-byte MAC header
            int bodyOffset = (int)sizeof(ieee80211_hdr_t) + 12;
            int bodyLen    = (int)pkt->rx_ctrl.sig_len - bodyOffset - 4; // strip FCS
            if (bodyLen > 2) {
                const uint8_t* body = pkt->payload + bodyOffset;
                int rem = bodyLen;
                while (rem >= 2) {
                    uint8_t tag  = body[0];
                    uint8_t elen = body[1];
                    if ((int)elen + 2 > rem) break;
                    if (tag == 0 && elen > 0) {
                        portENTER_CRITICAL_ISR(&g_pwnaMux);
                        size_t next = (g_pwnaHead + 1) % PWNA_QUEUE_SIZE;
                        if (next != g_pwnaTail) {
                            PwnaRawEvent* e = (PwnaRawEvent*)&g_pwnaQ[g_pwnaHead];
                            uint8_t snap = (elen < PWNA_SSID_SNAP) ? elen : (PWNA_SSID_SNAP - 1);
                            memcpy((void*)e->ssidSnap, body + 2, snap);
                            e->ssidLen = snap;
                            e->rssi    = rssi;
                            g_pwnaHead = next;
                        }
                        portEXIT_CRITICAL_ISR(&g_pwnaMux);
                        break;
                    }
                    body += elen + 2;
                    rem  -= elen + 2;
                }
            }
        }
        return;
    }

    // ── Deauth / disassoc (subtypes 10 and 12) ────────────────
    if (subtype != 10 && subtype != 12) return;

    portENTER_CRITICAL_ISR(&g_dqMux);
    size_t next = (g_dqHead + 1) % DEAUTH_QUEUE_SIZE;
    if (next != g_dqTail) {
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

static inline bool isBroadcastMAC(const uint8_t* m) {
    return m[0] == 0xFF && m[1] == 0xFF && m[2] == 0xFF &&
           m[3] == 0xFF && m[4] == 0xFF && m[5] == 0xFF;
}

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
        if (isBroadcastMAC(frame.dst)) slot->broadcastCount++;
    }
}

static void analyzeDeauthSources() {
    unsigned long now = millis();
    for (int i = 0; i < MAX_DEAUTH_SOURCES; i++) {
        if (!g_deauthSrc[i].inUse) continue;
        if (now - g_deauthSrc[i].windowStart > DEAUTH_WINDOW_MS) continue;
        uint32_t cnt  = g_deauthSrc[i].count;
        uint32_t bcnt = g_deauthSrc[i].broadcastCount;
        if (cnt >= (uint32_t)DEAUTH_ALERT_THRESHOLD) {
            scoreAdd(4, "deauth/disassoc burst (alert-level rate)");
            Serial.printf("[canary] DEAUTH ALERT: %lu f/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        } else if (cnt >= (uint32_t)DEAUTH_CAUTION_THRESHOLD) {
            scoreAdd(2, "deauth/disassoc burst (elevated rate)");
            Serial.printf("[canary] DEAUTH caution: %lu f/5s src=%02x:%02x:%02x:...\n",
                          (unsigned long)cnt,
                          g_deauthSrc[i].src[0], g_deauthSrc[i].src[1], g_deauthSrc[i].src[2]);
        }
        if (bcnt >= (uint32_t)DEAUTH_BROADCAST_THRESHOLD) {
            scoreAdd(1, "broadcast deauth frames observed");
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

    if (g_probeSampled >= (uint32_t)PROBE_ALERT_THRESHOLD) {
        scoreAdd(3, "probe request flood (attack-tool level)");
        Serial.printf("[canary] PROBE FLOOD ALERT: %lu probes/10s\n",
                      (unsigned long)g_probeSampled);
    } else if (g_probeSampled >= (uint32_t)PROBE_CAUTION_THRESHOLD) {
        scoreAdd(1, "probe request flood (elevated)");
        Serial.printf("[canary] PROBE FLOOD caution: %lu probes/10s\n",
                      (unsigned long)g_probeSampled);
    }
}

// ============================================================
// PWNAGOTCHI DETECTION
// Parse raw SSID bytes from the callback queue.
// Avoids JSON library by using simple byte-pattern search.
// ============================================================

static const uint8_t* memfind(const uint8_t* hay, int hlen,
                               const char* needle, int nlen) {
    for (int i = 0; i <= hlen - nlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return nullptr;
}

static void drainPwnaQueue() {
    while (true) {
        portENTER_CRITICAL(&g_pwnaMux);
        bool empty = (g_pwnaHead == g_pwnaTail);
        portEXIT_CRITICAL(&g_pwnaMux);
        if (empty) break;

        PwnaRawEvent ev;
        portENTER_CRITICAL(&g_pwnaMux);
        memcpy(&ev, (void*)&g_pwnaQ[g_pwnaTail], sizeof(PwnaRawEvent));
        g_pwnaTail = (g_pwnaTail + 1) % PWNA_QUEUE_SIZE;
        portEXIT_CRITICAL(&g_pwnaMux);

        const uint8_t* data = ev.ssidSnap;
        int dlen = ev.ssidLen;

        if (dlen < 2 || data[0] != '{') continue;

        // Extract name from "name":"VALUE"
        const uint8_t* nameToken = memfind(data, dlen, "\"name\":\"", 8);
        if (nameToken) {
            const uint8_t* nameStart = nameToken + 8;
            int remaining = dlen - (int)(nameStart - data);
            int nameLen = 0;
            while (nameLen < remaining && nameLen < 31 && nameStart[nameLen] != '"')
                nameLen++;
            memcpy(g_pwnaName, nameStart, nameLen);
            g_pwnaName[nameLen] = '\0';
        }

        // Check for active deauth policy
        bool deauthOn = (memfind(data, dlen, "\"deauth\":true", 13) != nullptr);

        g_pwnaDetected = true;
        g_pwnaDeauth   = deauthOn;
        g_pwnaRssi     = ev.rssi;
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
        scoreAdd(4, "pwnagotchi detected: deauth policy ACTIVE");
        Serial.printf("[canary] PWNAGOTCHI ALERT: '%s' is attacking (deauth=true) rssi=%d\n",
                      g_pwnaName[0] ? g_pwnaName : "?", g_pwnaRssi);
    } else {
        scoreAdd(2, "pwnagotchi detected (passive mode)");
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
    if (g_spamNew >= SPAM_ALERT_THRESHOLD) {
        scoreAdd(3, "beacon/SSID flood: very high new-SSID count");
        Serial.printf("[canary] SPAM ALERT: %d new SSIDs/%ds\n",
                      g_spamNew, SPAM_WINDOW_MS / 1000);
    } else if (g_spamNew >= SPAM_CAUTION_THRESHOLD) {
        scoreAdd(2, "beacon/SSID flood: elevated new-SSID count");
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
        if (bssid[1] == 0x13 && bssid[2] == 0x37) {
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "WiFi Pineapple OUI: SSID='%.28s'", ssid);
            scoreAdd(4, reason);
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

        // ── Open clone of known encrypted SSID ───────────────
        if (auth == AUTH_OPEN && baseAP->auth != AUTH_OPEN) {
            int pts = 3;
            if (bssidIsNew)                              pts++;
            if (rssi > baseAP->rssi + RSSI_STRONGER_BY) pts++;
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "open clone of encrypted SSID '%.28s'", ssid);
            scoreAdd(pts, reason);
            Serial.printf("[canary] OPEN CLONE: SSID='%s' baseline=%s clone=OPEN "
                          "bssid=%s rssi=%d/%d\n",
                          ssid, authStr(baseAP->auth), bssidBuf, rssi, baseAP->rssi);
            continue;
        }

        // ── Security downgrade ────────────────────────────────
        if (baseAP->auth != AUTH_UNKNOWN && auth != AUTH_UNKNOWN &&
            auth != AUTH_OPEN &&
            authRank(auth) < authRank(baseAP->auth)) {
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

        // ── Duplicate SSID with unexpected vendor OUI ─────────
        if (bssidIsNew && auth == baseAP->auth &&
            memcmp(baseAP->bssid, bssid, 3) != 0) {
            int pts = 1;
            if (rssi > baseAP->rssi + RSSI_STRONGER_BY) pts++;
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "dup SSID diff vendor: '%.30s'", ssid);
            scoreAdd(pts, reason);
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
            if (WiFi.encryptionType(i) != WIFI_AUTH_OPEN) continue;
            if (strcasecmp(WiFi.SSID(i).c_str(), g_aps[j].ssid) != 0) continue;
            char reason[72];
            snprintf(reason, sizeof(reason),
                     "original AP gone, open clone present: '%.26s'", g_aps[j].ssid);
            scoreAdd(3, reason);
            Serial.printf("[canary] ABSENT+CLONE: original '%s' gone, open clone present\n",
                          g_aps[j].ssid);
        }
    }
}

// ============================================================
// WIFI SCAN
// ============================================================

static unsigned long g_lastScan = 0;

static void performScan(bool isBaseline) {
    promiscStop();
    ledScanFlash();
    Serial.printf("[canary] %s scan (aps=%d score=%d)\n",
                  isBaseline ? "baseline" : "normal", g_apCount, g_score);
    markAllInactive();

    int n = WiFi.scanNetworks(false, true);
    g_lastScan = millis();

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
        if (g_baselineScansDone >= BASELINE_SCANS) {
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
                          g_baselineScansDone, BASELINE_SCANS);
        }
    } else {
        updateSpamTracker(n);
        analyzeScanThreats(n);
    }

    WiFi.scanDelete();
    promiscStart();
}

// ============================================================
// STATE UPDATE
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
        static const char* n[] = { "STARTUP","NORMAL","CAUTION","ALERT" };
        Serial.printf("[canary] %s → %s  (score=%d  \"%s\")\n",
                      n[g_state], n[next], g_score, g_scoreReason);
        g_state = next;
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
    static const char* n[] = { "STARTUP","NORMAL","CAUTION","ALERT" };
    Serial.printf("[canary] hb: state=%s score=%d reason=\"%s\" "
                  "aps=%d probes=%lu ch=%u pwna=%s\n",
                  n[g_state], g_score, g_scoreReason,
                  g_apCount, (unsigned long)g_probeSampled,
                  g_curChannel,
                  g_pwnaDetected ? (g_pwnaDeauth ? "ACTIVE" : "passive") : "none");
}

// ============================================================
// BUTTON — dump AP table + reset score
// ============================================================

static unsigned long g_btnLastMs    = 0;
static bool          g_btnLastState = true;

static void handleButton() {
    bool pressed = (digitalRead(BUTTON_PIN) == LOW);
    if (pressed && !g_btnLastState && (millis() - g_btnLastMs > 50)) {
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
    Serial.println("================================");
    Serial.println(" Travel WiFi Canary v1.1");
    Serial.println(" Passive 2.4 GHz awareness");
    Serial.println("================================");

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
    g_ledLastUpdate     = millis();

    Serial.println("[canary] setup done — starting baseline learning");
}

// ============================================================
// LOOP
// ============================================================

void loop() {
    unsigned long now = millis();

    ledTick();
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

    if (!g_baselineLearned) {
        if (now - g_lastScan >= BASELINE_SCAN_INTERVAL_MS)
            performScan(true);
    } else {
        if (now - g_lastScan >= SCAN_INTERVAL_MS)
            performScan(false);
    }

    delay(10);
}
