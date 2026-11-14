#pragma once

#include <stdint.h>

namespace canary {

enum BoardKind : uint8_t {
    BOARD_ATOM_LITE,
    BOARD_ESP32DEV,
    BOARD_ATOM_ECHO,
    BOARD_ATOM_VOICE,
    BOARD_M5STACK_BASIC,
    BOARD_CORE2_AWS,
    BOARD_M5STICKC_PLUS_SE,
    BOARD_T_DONGLE_C5,
};

struct BoardProfile {
    const char* id;
    bool rgbLed;
    bool display;
    bool audio;
    bool haptic;
    bool button;
    bool experimental;
};

constexpr BoardProfile profileFor(BoardKind kind) {
    return kind == BOARD_ATOM_LITE
               ? BoardProfile{"atom-lite", true, false, false, false, true, false}
           : kind == BOARD_ESP32DEV
               ? BoardProfile{"esp32dev", false, false, false, false, false, false}
           : kind == BOARD_ATOM_ECHO
               ? BoardProfile{"atom-echo", true, false, false, false, true, false}
           : kind == BOARD_ATOM_VOICE
               ? BoardProfile{"atom-voice", true, false, true, false, true, false}
           : kind == BOARD_M5STACK_BASIC
               ? BoardProfile{"m5stack-basic", false, true, true, false, true, false}
           : kind == BOARD_CORE2_AWS
               ? BoardProfile{"m5stack-core2-aws", false, true, true, true, true, false}
           : kind == BOARD_M5STICKC_PLUS_SE
               ? BoardProfile{"m5stickc-plus-se", false, true, true, false, true, false}
               : BoardProfile{"lilygo-t-dongle-c5", true, true, false, false, true, true};
}

}  // namespace canary
