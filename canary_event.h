#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "canary_core.h"

namespace canary {

constexpr int kEventSchema = 1;
constexpr const char* kFirmwareVersion = "1.2.0-dev";

struct HealthSnapshot {
    int apCount;
    uint32_t probes;
    int channel;
    uint32_t deauthQueueDrops;
    uint32_t pwnagotchiQueueDrops;
    uint32_t scanDurationMs;
    uint32_t captureGapMs;
    uint32_t parserRejects;
    uint32_t logLosses;
    uint32_t freeHeap;
    uint32_t minFreeHeap;
    int resetReason;
    uint32_t channelFrames;
};

struct EventRecord {
    const char* deviceId;
    const char* firmware;
    const char* board;
    unsigned long uptimeMs;
    const char* eventType;
    const char* detectorId;
    int scoreDelta;
    int score;
    CanaryState state;
    const char* reason;
    const char* ssid;
    const char* bssid;
    int channel;
    int rssi;
    HealthSnapshot health;
};

inline const char* stateName(CanaryState state) {
    switch (state) {
        case STATE_STARTUP: return "startup";
        case STATE_NORMAL: return "normal";
        case STATE_CAUTION: return "caution";
        case STATE_ALERT: return "alert";
        default: return "unknown";
    }
}

inline bool appendFormat(char* output, size_t capacity, size_t* used,
                         const char* format, ...) {
    if (!output || !used || !format || *used >= capacity) return false;
    va_list args;
    va_start(args, format);
    const int written = vsnprintf(output + *used, capacity - *used, format, args);
    va_end(args);
    if (written < 0 || static_cast<size_t>(written) >= capacity - *used) {
        output[capacity - 1] = '\0';
        return false;
    }
    *used += static_cast<size_t>(written);
    return true;
}

inline bool appendJsonString(char* output, size_t capacity, size_t* used,
                             const char* value) {
    if (!value) return appendFormat(output, capacity, used, "null");
    if (!appendFormat(output, capacity, used, "\"")) return false;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value);
         *cursor; ++cursor) {
        switch (*cursor) {
            case '"':
                if (!appendFormat(output, capacity, used, "\\\"")) return false;
                break;
            case '\\':
                if (!appendFormat(output, capacity, used, "\\\\")) return false;
                break;
            case '\b':
                if (!appendFormat(output, capacity, used, "\\b")) return false;
                break;
            case '\f':
                if (!appendFormat(output, capacity, used, "\\f")) return false;
                break;
            case '\n':
                if (!appendFormat(output, capacity, used, "\\n")) return false;
                break;
            case '\r':
                if (!appendFormat(output, capacity, used, "\\r")) return false;
                break;
            case '\t':
                if (!appendFormat(output, capacity, used, "\\t")) return false;
                break;
            default:
                if (*cursor < 0x20) {
                    if (!appendFormat(output, capacity, used, "\\u%04x", *cursor)) return false;
                } else if (!appendFormat(output, capacity, used, "%c", *cursor)) {
                    return false;
                }
        }
    }
    return appendFormat(output, capacity, used, "\"");
}

inline bool appendNamedString(char* output, size_t capacity, size_t* used,
                              const char* name, const char* value, bool comma = true) {
    return appendFormat(output, capacity, used, "\"%s\":", name) &&
           appendJsonString(output, capacity, used, value) &&
           (!comma || appendFormat(output, capacity, used, ","));
}

inline bool formatEventJson(char* output, size_t capacity, const EventRecord& event) {
    if (!output || capacity == 0) return false;
    output[0] = '\0';
    size_t used = 0;

    if (!appendFormat(output, capacity, &used, "{\"schema\":%d,", kEventSchema) ||
        !appendNamedString(output, capacity, &used, "device_id", event.deviceId) ||
        !appendNamedString(output, capacity, &used, "firmware", event.firmware) ||
        !appendNamedString(output, capacity, &used, "board", event.board) ||
        !appendFormat(output, capacity, &used, "\"uptime_ms\":%lu,", event.uptimeMs) ||
        !appendNamedString(output, capacity, &used, "event", event.eventType) ||
        !appendNamedString(output, capacity, &used, "detector", event.detectorId) ||
        !appendFormat(output, capacity, &used,
                      "\"score_delta\":%d,\"score\":%d,\"state\":",
                      event.scoreDelta, event.score) ||
        !appendJsonString(output, capacity, &used, stateName(event.state)) ||
        !appendFormat(output, capacity, &used, ",") ||
        !appendNamedString(output, capacity, &used, "reason", event.reason) ||
        !appendNamedString(output, capacity, &used, "ssid", event.ssid) ||
        !appendNamedString(output, capacity, &used, "bssid", event.bssid)) {
        return false;
    }

    if (event.channel >= 0) {
        if (!appendFormat(output, capacity, &used, "\"channel\":%d,", event.channel)) return false;
    } else if (!appendFormat(output, capacity, &used, "\"channel\":null,")) {
        return false;
    }
    if (event.rssi > -127) {
        if (!appendFormat(output, capacity, &used, "\"rssi\":%d,", event.rssi)) return false;
    } else if (!appendFormat(output, capacity, &used, "\"rssi\":null,")) {
        return false;
    }

    return appendFormat(
        output, capacity, &used,
        "\"health\":{\"aps\":%d,\"probes\":%lu,\"channel\":%d,"
        "\"deauth_queue_drops\":%lu,\"pwnagotchi_queue_drops\":%lu,"
        "\"scan_duration_ms\":%lu,\"capture_gap_ms\":%lu,\"parser_rejects\":%lu,"
        "\"log_losses\":%lu,\"free_heap\":%lu,\"min_free_heap\":%lu,\"reset_reason\":%d,"
        "\"channel_frames\":%lu}}",
        event.health.apCount,
        static_cast<unsigned long>(event.health.probes),
        event.health.channel,
        static_cast<unsigned long>(event.health.deauthQueueDrops),
        static_cast<unsigned long>(event.health.pwnagotchiQueueDrops),
        static_cast<unsigned long>(event.health.scanDurationMs),
        static_cast<unsigned long>(event.health.captureGapMs),
        static_cast<unsigned long>(event.health.parserRejects),
        static_cast<unsigned long>(event.health.logLosses),
        static_cast<unsigned long>(event.health.freeHeap),
        static_cast<unsigned long>(event.health.minFreeHeap),
        event.health.resetReason,
        static_cast<unsigned long>(event.health.channelFrames));
}

}  // namespace canary
