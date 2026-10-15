#pragma once

#include <Arduino.h>
#include <string.h>

#include "canary_board_profile.h"
#include "canary_config.h"
#include "canary_core.h"
#include "canary_event.h"

#if defined(CANARY_BOARD_ATOM_LITE) || defined(CANARY_BOARD_ATOM_ECHO) || \
    defined(CANARY_BOARD_ATOM_VOICE) || defined(CANARY_BOARD_T_DONGLE_C5)
  #include <Adafruit_NeoPixel.h>
  #define CANARY_NEOPIXEL 1
#endif

#if defined(CANARY_BOARD_ATOM_VOICE) || defined(CANARY_BOARD_M5STACK_BASIC) || \
    defined(CANARY_BOARD_CORE2_AWS) || defined(CANARY_BOARD_M5STICKC_PLUS_SE)
  #include <M5Unified.h>
  #define CANARY_M5UNIFIED 1
#endif

#if defined(CANARY_BOARD_T_DONGLE_C5)
  #include <Adafruit_GFX.h>
  #include <Adafruit_ST7735.h>
#endif

namespace canary {

#if defined(CANARY_BOARD_ATOM_LITE)
constexpr BoardKind kActiveBoard = BOARD_ATOM_LITE;
#elif defined(CANARY_BOARD_ATOM_ECHO)
constexpr BoardKind kActiveBoard = BOARD_ATOM_ECHO;
#elif defined(CANARY_BOARD_ATOM_VOICE)
constexpr BoardKind kActiveBoard = BOARD_ATOM_VOICE;
#elif defined(CANARY_BOARD_M5STACK_BASIC)
constexpr BoardKind kActiveBoard = BOARD_M5STACK_BASIC;
#elif defined(CANARY_BOARD_CORE2_AWS)
constexpr BoardKind kActiveBoard = BOARD_CORE2_AWS;
#elif defined(CANARY_BOARD_M5STICKC_PLUS_SE)
constexpr BoardKind kActiveBoard = BOARD_M5STICKC_PLUS_SE;
#elif defined(CANARY_BOARD_T_DONGLE_C5)
constexpr BoardKind kActiveBoard = BOARD_T_DONGLE_C5;
#else
constexpr BoardKind kActiveBoard = BOARD_ESP32DEV;
#endif

constexpr BoardProfile kBoardProfile = profileFor(kActiveBoard);

inline const char* boardId() {
    return kBoardProfile.id;
}

#if defined(CANARY_NEOPIXEL)
  #if defined(CANARY_BOARD_T_DONGLE_C5)
constexpr uint8_t kPixelPin = 11;
  #else
constexpr uint8_t kPixelPin = 27;
  #endif
static Adafruit_NeoPixel g_boardPixel(1, kPixelPin, NEO_GRB + NEO_KHZ800);
#endif

#if defined(CANARY_BOARD_T_DONGLE_C5)
static Adafruit_ST7735 g_boardTft(4, 2, 6, 5, 3);
#endif

static unsigned long g_boardLastDraw = 0;
static unsigned long g_boardAlertUntil = 0;
static unsigned long g_boardVibrationUntil = 0;
static int g_boardLastScore = -1;
static char g_boardLastReason[72] = "";
static uint8_t g_boardBrightness = 120;
static uint8_t g_boardOutputFlags = OUTPUT_LIGHT | OUTPUT_DISPLAY | OUTPUT_AUDIO | OUTPUT_HAPTIC;
static unsigned long g_boardAlertHoldMs = 15000;

inline void boardConfigure(const CanaryConfig& config) {
    g_boardBrightness = config.ledBrightness;
    g_boardOutputFlags = config.outputFlags;
    g_boardAlertHoldMs = static_cast<unsigned long>(config.alertHoldSeconds) * 1000UL;
}

inline void boardSetRgb(uint8_t red, uint8_t green, uint8_t blue) {
    if (!(g_boardOutputFlags & OUTPUT_LIGHT)) return;
#if defined(CANARY_NEOPIXEL)
    g_boardPixel.setPixelColor(0, g_boardPixel.Color(red, green, blue));
    g_boardPixel.show();
#elif defined(CANARY_BOARD_ESP32DEV)
    digitalWrite(2, (red | green | blue) ? HIGH : LOW);
#else
    (void)red;
    (void)green;
    (void)blue;
#endif
}

inline void boardApplyStateLight(CanaryState state) {
    switch (state) {
        case STATE_STARTUP: boardSetRgb(0, 0, 60); break;
        case STATE_NORMAL: boardSetRgb(0, 40, 0); break;
        case STATE_CAUTION: boardSetRgb(80, 35, 0); break;
        case STATE_ALERT: boardSetRgb(110, 0, 0); break;
    }
}

inline void boardBegin() {
#if defined(CANARY_NEOPIXEL)
    g_boardPixel.begin();
    g_boardPixel.setBrightness(g_boardBrightness);
#endif
#if defined(CANARY_BOARD_ESP32DEV)
    pinMode(2, OUTPUT);
#endif
#if defined(CANARY_M5UNIFIED)
    auto config = M5.config();
  #if defined(CANARY_BOARD_M5STICKC_PLUS_SE)
    config.internal_spk = false;
  #endif
    M5.begin(config);
  #if defined(CANARY_BOARD_ATOM_VOICE) || defined(CANARY_BOARD_M5STACK_BASIC) || \
      defined(CANARY_BOARD_CORE2_AWS)
    M5.Speaker.setVolume(160);
  #endif
  #if defined(CANARY_BOARD_M5STACK_BASIC) || defined(CANARY_BOARD_CORE2_AWS)
    M5.Display.setRotation(1);
    M5.Display.setTextSize(2);
    M5.Display.fillScreen(TFT_BLACK);
  #elif defined(CANARY_BOARD_M5STICKC_PLUS_SE)
    M5.Display.setRotation(3);
    M5.Display.setTextSize(1);
    M5.Display.fillScreen(TFT_BLACK);
    pinMode(2, OUTPUT);
  #endif
#endif
#if defined(CANARY_BOARD_T_DONGLE_C5)
    pinMode(1, OUTPUT);
    digitalWrite(1, HIGH);
    g_boardTft.initR(INITR_MINI160x80_PLUGIN);
    g_boardTft.setRotation(1);
    g_boardTft.fillScreen(ST77XX_BLACK);
#endif
#if defined(CANARY_BOARD_ATOM_LITE) || defined(CANARY_BOARD_ATOM_ECHO) || \
    defined(CANARY_BOARD_ATOM_VOICE)
    pinMode(39, INPUT_PULLUP);
#elif defined(CANARY_BOARD_T_DONGLE_C5)
    pinMode(9, INPUT_PULLUP);
#endif
    boardApplyStateLight(STATE_STARTUP);
}

inline void boardShowScan() {
    boardSetRgb(0, 30, 40);
}

inline void boardNotifyState(CanaryState previous, CanaryState next) {
    if (next <= previous || next < STATE_CAUTION) return;
    if (next == STATE_ALERT) g_boardAlertUntil = millis() + g_boardAlertHoldMs;

#if defined(CANARY_BOARD_ATOM_VOICE) || defined(CANARY_BOARD_M5STACK_BASIC) || \
    defined(CANARY_BOARD_CORE2_AWS)
    if (g_boardOutputFlags & OUTPUT_AUDIO)
        M5.Speaker.tone(next == STATE_ALERT ? 2093 : 880, next == STATE_ALERT ? 240 : 130);
#elif defined(CANARY_BOARD_M5STICKC_PLUS_SE)
    if (g_boardOutputFlags & OUTPUT_AUDIO)
        tone(2, next == STATE_ALERT ? 2093 : 880, next == STATE_ALERT ? 240 : 130);
#endif

#if defined(CANARY_BOARD_CORE2_AWS)
    if (g_boardOutputFlags & OUTPUT_HAPTIC) {
        M5.Power.setVibration(next == STATE_ALERT ? 200 : 120);
        g_boardVibrationUntil = millis() + (next == STATE_ALERT ? 400 : 180);
    }
#endif
}

inline bool boardButtonPressed() {
#if defined(CANARY_BOARD_M5STACK_BASIC) || defined(CANARY_BOARD_CORE2_AWS) || \
    defined(CANARY_BOARD_M5STICKC_PLUS_SE)
    return M5.BtnA.wasPressed();
#elif defined(CANARY_BOARD_ATOM_LITE) || defined(CANARY_BOARD_ATOM_ECHO) || \
      defined(CANARY_BOARD_ATOM_VOICE) || defined(CANARY_BOARD_T_DONGLE_C5)
  #if defined(CANARY_BOARD_T_DONGLE_C5)
    constexpr uint8_t kButtonPin = 9;
  #else
    constexpr uint8_t kButtonPin = 39;
  #endif
    static bool previous = true;
    static unsigned long lastChange = 0;
    const bool current = digitalRead(kButtonPin) == LOW;
    const bool pressed = current && !previous && millis() - lastChange > 50;
    if (current != previous) lastChange = millis();
    previous = current;
    return pressed;
#else
    return false;
#endif
}

inline void boardDrawDisplay(CanaryState state, int score, const char* reason,
                             const char* source, const char* ssid,
                             int channel, int rssi, bool baselineLearned) {
    if (!(g_boardOutputFlags & OUTPUT_DISPLAY)) return;
#if defined(CANARY_BOARD_M5STACK_BASIC) || defined(CANARY_BOARD_CORE2_AWS) || \
    defined(CANARY_BOARD_M5STICKC_PLUS_SE)
    const uint16_t background = state == STATE_ALERT ? TFT_MAROON :
                                state == STATE_CAUTION ? 0x8400 : TFT_BLACK;
    M5.Display.fillScreen(background);
    M5.Display.setTextColor(state == STATE_ALERT ? TFT_RED :
                            state == STATE_CAUTION ? TFT_YELLOW : TFT_GREEN,
                            background);
    M5.Display.setCursor(4, 4);
    M5.Display.printf("%s  SCORE %d", stateName(state), score);
    M5.Display.setTextColor(TFT_WHITE, background);
    M5.Display.setCursor(4, 28);
    M5.Display.printf("%.30s", reason && reason[0] ? reason :
                      (baselineLearned ? "Monitoring" : "Learning baseline"));
    M5.Display.setCursor(4, 52);
    M5.Display.printf("%.24s", ssid && ssid[0] ? ssid : (source ? source : ""));
    M5.Display.setCursor(4, 76);
    M5.Display.printf("CH %d  RSSI %d", channel, rssi);
    if (state == STATE_ALERT && static_cast<long>(g_boardAlertUntil - millis()) > 0) {
        M5.Display.setCursor(4, 100);
        M5.Display.printf("Alert hold %lus", (g_boardAlertUntil - millis() + 999) / 1000);
    }
#elif defined(CANARY_BOARD_T_DONGLE_C5)
    const uint16_t background = state == STATE_ALERT ? 0x8000 :
                                state == STATE_CAUTION ? 0x8400 : ST77XX_BLACK;
    g_boardTft.fillScreen(background);
    g_boardTft.setTextSize(1);
    g_boardTft.setTextColor(state == STATE_ALERT ? ST77XX_RED :
                            state == STATE_CAUTION ? ST77XX_YELLOW : ST77XX_GREEN);
    g_boardTft.setCursor(3, 3);
    g_boardTft.printf("%s %d", stateName(state), score);
    g_boardTft.setTextColor(ST77XX_WHITE);
    g_boardTft.setCursor(3, 18);
    g_boardTft.printf("%.22s", reason && reason[0] ? reason :
                      (baselineLearned ? "Monitoring" : "Learning baseline"));
    g_boardTft.setCursor(3, 42);
    g_boardTft.printf("%.20s", ssid && ssid[0] ? ssid : (source ? source : ""));
    g_boardTft.setCursor(3, 58);
    g_boardTft.printf("CH%d %ddBm", channel, rssi);
#else
    (void)state;
    (void)score;
    (void)reason;
    (void)source;
    (void)ssid;
    (void)channel;
    (void)rssi;
    (void)baselineLearned;
#endif
}

inline void boardTick(CanaryState state, int score, const char* reason,
                      const char* source, const char* ssid,
                      int channel, int rssi, bool baselineLearned) {
#if defined(CANARY_M5UNIFIED)
    M5.update();
#endif
#if defined(CANARY_BOARD_CORE2_AWS)
    if (g_boardVibrationUntil && static_cast<long>(millis() - g_boardVibrationUntil) >= 0) {
        M5.Power.setVibration(0);
        g_boardVibrationUntil = 0;
    }
#endif
    boardApplyStateLight(state);

    const bool changed = score != g_boardLastScore ||
                         strncmp(reason ? reason : "", g_boardLastReason,
                                 sizeof(g_boardLastReason)) != 0;
    if (!changed && millis() - g_boardLastDraw < 1000) return;
    g_boardLastScore = score;
    strncpy(g_boardLastReason, reason ? reason : "", sizeof(g_boardLastReason) - 1);
    g_boardLastReason[sizeof(g_boardLastReason) - 1] = '\0';
    g_boardLastDraw = millis();
    boardDrawDisplay(state, score, reason, source, ssid, channel, rssi, baselineLearned);
}

}  // namespace canary
