#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace canary {

constexpr uint32_t kConfigMagic = 0x594E4143UL;
constexpr uint16_t kConfigVersion = 1;
constexpr uint16_t kAllEngines = 0x01FF;

enum Sensitivity : uint8_t { SENSITIVITY_LOW = 0, SENSITIVITY_STANDARD = 1, SENSITIVITY_HIGH = 2 };
enum OutputFlag : uint8_t { OUTPUT_LIGHT = 1, OUTPUT_DISPLAY = 2, OUTPUT_AUDIO = 4, OUTPUT_HAPTIC = 8 };

#pragma pack(push, 1)
struct CanaryConfig {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint16_t engineMask;
    uint8_t sensitivity;
    uint8_t baselineScans;
    uint8_t ledBrightness;
    uint8_t alertHoldSeconds;
    uint8_t outputFlags;
    uint8_t reserved[15];
    uint32_t crc32;
};
#pragma pack(pop)

static_assert(sizeof(CanaryConfig) == 34, "config layout changed");

inline uint32_t configCrc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320UL & (0U - (crc & 1U)));
    }
    return ~crc;
}

inline CanaryConfig defaultConfig() {
    CanaryConfig config = {};
    config.magic = kConfigMagic;
    config.version = kConfigVersion;
    config.size = sizeof(CanaryConfig);
    config.engineMask = kAllEngines;
    config.sensitivity = SENSITIVITY_STANDARD;
    config.baselineScans = 3;
    config.ledBrightness = 120;
    config.alertHoldSeconds = 15;
    config.outputFlags = OUTPUT_LIGHT | OUTPUT_DISPLAY | OUTPUT_AUDIO | OUTPUT_HAPTIC;
    config.crc32 = configCrc32(reinterpret_cast<const uint8_t*>(&config),
                              offsetof(CanaryConfig, crc32));
    return config;
}

inline bool validateConfigBytes(const uint8_t* data, size_t length, CanaryConfig* output) {
    if (!data || length < sizeof(CanaryConfig)) return false;
    CanaryConfig config;
    memcpy(&config, data, sizeof(config));
    if (config.magic != kConfigMagic || config.version != kConfigVersion ||
        config.size != sizeof(CanaryConfig)) return false;
    if (config.engineMask & ~kAllEngines) return false;
    if (config.sensitivity > SENSITIVITY_HIGH || config.baselineScans < 1 ||
        config.baselineScans > 12 || config.alertHoldSeconds < 3 ||
        config.alertHoldSeconds > 120) return false;
    const uint32_t expected = configCrc32(data, offsetof(CanaryConfig, crc32));
    if (expected != config.crc32) return false;
    if (output) *output = config;
    return true;
}

inline uint8_t detectorBit(const char* detector) {
    if (!detector) return 0;
    if (!strcmp(detector, "pwnagotchi")) return 0;
    if (!strcmp(detector, "pineapple_oui") || !strcmp(detector, "wifi_pineapple")) return 1;
    if (!strcmp(detector, "probe_flood")) return 2;
    if (!strcmp(detector, "deauth_burst") || !strcmp(detector, "broadcast_deauth")) return 3;
    if (!strcmp(detector, "open_clone")) return 4;
    if (!strcmp(detector, "missing_original_open_clone")) return 5;
    if (!strcmp(detector, "security_downgrade")) return 6;
    if (!strcmp(detector, "duplicate_ssid_vendor")) return 7;
    if (!strcmp(detector, "beacon_flood")) return 8;
    return 0xFF;
}

inline bool detectorEnabled(const CanaryConfig& config, const char* detector) {
    const uint8_t bit = detectorBit(detector);
    return bit == 0xFF || (config.engineMask & (1U << bit));
}

inline int sensitivityAdjusted(const CanaryConfig& config, int points) {
    if (points <= 0) return points;
    if (config.sensitivity == SENSITIVITY_LOW) return points > 1 ? points - 1 : 1;
    if (config.sensitivity == SENSITIVITY_HIGH) return points + 1;
    return points;
}

}  // namespace canary
