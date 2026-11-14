#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace canary {

constexpr int kScoreCaution = 3;
constexpr int kScoreAlert = 6;
constexpr int kScoreMax = 20;

constexpr uint32_t kDeauthCautionThreshold = 8;
constexpr uint32_t kDeauthAlertThreshold = 20;
constexpr uint32_t kDeauthBroadcastThreshold = 5;
constexpr uint32_t kProbeCautionThreshold = 40;
constexpr uint32_t kProbeAlertThreshold = 80;
constexpr int kSpamCautionThreshold = 15;
constexpr int kSpamAlertThreshold = 30;
constexpr int kRssiStrongerBy = 10;

enum CanaryState : uint8_t {
    STATE_STARTUP = 0,
    STATE_NORMAL = 1,
    STATE_CAUTION = 2,
    STATE_ALERT = 3,
};

enum AuthStrength : uint8_t {
    AUTH_OPEN = 0,
    AUTH_WEP = 1,
    AUTH_WPA = 2,
    AUTH_WPA2 = 3,
    AUTH_WPA3 = 4,
    AUTH_WPA2E = 5,
    AUTH_UNKNOWN = 0xFF,
};

struct ParsedMgmtFrame {
    uint8_t subtype;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
};

struct PwnagotchiMetadata {
    bool valid;
    bool deauth;
    char name[32];
};

struct AccessPointView {
    const char* ssid;
    const uint8_t* bssid;
    int8_t rssi;
    AuthStrength auth;
};

struct AccessPointThreat {
    int openClonePoints;
    int downgradePoints;
    int duplicateVendorPoints;
};

inline bool bytesEqual(const uint8_t* left, const uint8_t* right, size_t length) {
    return left && right && memcmp(left, right, length) == 0;
}

inline uint8_t asciiLower(uint8_t value) {
    return (value >= 'A' && value <= 'Z') ? static_cast<uint8_t>(value + ('a' - 'A')) : value;
}

inline bool ssidEqualIgnoreCase(const char* left, const char* right) {
    if (!left || !right) return false;
    while (*left && *right) {
        if (asciiLower(static_cast<uint8_t>(*left)) != asciiLower(static_cast<uint8_t>(*right))) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

inline CanaryState stateFor(bool baselineLearned, int score) {
    if (!baselineLearned) return STATE_STARTUP;
    if (score >= kScoreAlert) return STATE_ALERT;
    if (score >= kScoreCaution) return STATE_CAUTION;
    return STATE_NORMAL;
}

inline int addScore(int current, int points) {
    if (points <= 0) return current;
    const int updated = current + points;
    return updated > kScoreMax ? kScoreMax : updated;
}

inline int decayScore(int current, int amount = 1) {
    if (current <= 0 || amount <= 0) return current < 0 ? 0 : current;
    return current > amount ? current - amount : 0;
}

inline uint8_t authRank(AuthStrength auth) {
    switch (auth) {
        case AUTH_OPEN: return 0;
        case AUTH_WEP: return 1;
        case AUTH_WPA: return 2;
        case AUTH_WPA2: return 3;
        case AUTH_WPA2E: return 4;
        case AUTH_WPA3: return 5;
        default: return 0;
    }
}

inline bool isBroadcastMac(const uint8_t* mac) {
    if (!mac) return false;
    for (size_t i = 0; i < 6; ++i) {
        if (mac[i] != 0xFF) return false;
    }
    return true;
}

inline bool isPineappleBssid(const uint8_t* bssid) {
    return bssid && bssid[1] == 0x13 && bssid[2] == 0x37;
}

inline bool ringHasSpace(size_t head, size_t tail, size_t capacity) {
    if (capacity < 2 || head >= capacity || tail >= capacity) return false;
    return ((head + 1) % capacity) != tail;
}

inline size_t ringNext(size_t index, size_t capacity) {
    return capacity == 0 ? 0 : (index + 1) % capacity;
}

inline bool parseManagementFrame(const uint8_t* payload, size_t length, ParsedMgmtFrame* result) {
    constexpr size_t kHeaderLength = 24;
    if (!payload || !result || length < kHeaderLength) return false;

    const uint16_t frameControl = static_cast<uint16_t>(payload[0]) |
                                  (static_cast<uint16_t>(payload[1]) << 8);
    const uint8_t frameType = static_cast<uint8_t>((frameControl >> 2) & 0x03);
    if (frameType != 0) return false;

    result->subtype = static_cast<uint8_t>((frameControl >> 4) & 0x0F);
    memcpy(result->addr1, payload + 4, 6);
    memcpy(result->addr2, payload + 10, 6);
    memcpy(result->addr3, payload + 16, 6);
    return true;
}

inline bool extractBeaconSsid(const uint8_t* payload, size_t length,
                              uint8_t* output, size_t outputCapacity,
                              size_t* outputLength) {
    constexpr size_t kHeaderLength = 24;
    constexpr size_t kBeaconFixedLength = 12;
    if (!payload || !output || outputCapacity == 0 || !outputLength ||
        length < kHeaderLength + kBeaconFixedLength + 2) {
        return false;
    }

    const uint8_t* element = payload + kHeaderLength + kBeaconFixedLength;
    size_t remaining = length - kHeaderLength - kBeaconFixedLength;
    while (remaining >= 2) {
        const uint8_t tag = element[0];
        const size_t elementLength = element[1];
        if (elementLength + 2 > remaining) return false;
        if (tag == 0 && elementLength > 0) {
            const size_t copied = elementLength < outputCapacity - 1 ? elementLength : outputCapacity - 1;
            memcpy(output, element + 2, copied);
            output[copied] = '\0';
            *outputLength = copied;
            return true;
        }
        element += elementLength + 2;
        remaining -= elementLength + 2;
    }
    return false;
}

inline const uint8_t* findBytes(const uint8_t* haystack, size_t haystackLength,
                                const char* needle, size_t needleLength) {
    if (!haystack || !needle || needleLength == 0 || haystackLength < needleLength) return nullptr;
    for (size_t i = 0; i <= haystackLength - needleLength; ++i) {
        if (memcmp(haystack + i, needle, needleLength) == 0) return haystack + i;
    }
    return nullptr;
}

inline PwnagotchiMetadata parsePwnagotchiMetadata(const uint8_t* data, size_t length) {
    PwnagotchiMetadata result = {false, false, ""};
    if (!data || length < 2 || data[0] != '{') return result;

    result.valid = true;
    result.deauth = findBytes(data, length, "\"deauth\":true", 13) != nullptr;

    const uint8_t* nameToken = findBytes(data, length, "\"name\":\"", 8);
    if (!nameToken) return result;
    const uint8_t* nameStart = nameToken + 8;
    const size_t remaining = length - static_cast<size_t>(nameStart - data);
    size_t nameLength = 0;
    while (nameLength < remaining && nameLength < sizeof(result.name) - 1 &&
           nameStart[nameLength] != '"') {
        ++nameLength;
    }
    memcpy(result.name, nameStart, nameLength);
    result.name[nameLength] = '\0';
    return result;
}

inline int deauthBurstPoints(uint32_t count) {
    if (count >= kDeauthAlertThreshold) return 4;
    if (count >= kDeauthCautionThreshold) return 2;
    return 0;
}

inline int broadcastDeauthPoints(uint32_t count) {
    return count >= kDeauthBroadcastThreshold ? 1 : 0;
}

inline int probeFloodPoints(uint32_t count) {
    if (count >= kProbeAlertThreshold) return 3;
    if (count >= kProbeCautionThreshold) return 1;
    return 0;
}

inline int pwnagotchiPoints(bool deauthEnabled) {
    return deauthEnabled ? 4 : 2;
}

inline int beaconFloodPoints(int newSsids) {
    if (newSsids >= kSpamAlertThreshold) return 3;
    if (newSsids >= kSpamCautionThreshold) return 2;
    return 0;
}

inline AccessPointThreat evaluateAccessPointThreat(const AccessPointView& baseline,
                                                   const AccessPointView& observed,
                                                   bool bssidIsNew) {
    AccessPointThreat result = {0, 0, 0};
    if (!ssidEqualIgnoreCase(baseline.ssid, observed.ssid)) return result;

    if (observed.auth == AUTH_OPEN && baseline.auth != AUTH_OPEN) {
        result.openClonePoints = 3;
        if (bssidIsNew) ++result.openClonePoints;
        if (observed.rssi > baseline.rssi + kRssiStrongerBy) ++result.openClonePoints;
        return result;
    }

    if (baseline.auth != AUTH_UNKNOWN && observed.auth != AUTH_UNKNOWN &&
        observed.auth != AUTH_OPEN && authRank(observed.auth) < authRank(baseline.auth)) {
        const int delta = static_cast<int>(authRank(baseline.auth)) -
                          static_cast<int>(authRank(observed.auth));
        result.downgradePoints = delta >= 2 ? 3 : 1;
    }

    if (bssidIsNew && observed.auth == baseline.auth &&
        baseline.bssid && observed.bssid && memcmp(baseline.bssid, observed.bssid, 3) != 0) {
        result.duplicateVendorPoints = 1;
        if (observed.rssi > baseline.rssi + kRssiStrongerBy) {
            ++result.duplicateVendorPoints;
        }
    }
    return result;
}

inline int missingOriginalOpenClonePoints(const AccessPointView& baseline,
                                          const AccessPointView& observed,
                                          bool originalActive) {
    if (originalActive || baseline.auth == AUTH_OPEN || observed.auth != AUTH_OPEN) return 0;
    return ssidEqualIgnoreCase(baseline.ssid, observed.ssid) ? 3 : 0;
}

}  // namespace canary
