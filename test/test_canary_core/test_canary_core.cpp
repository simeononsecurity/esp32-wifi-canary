#include <unity.h>

#include "canary_core.h"

using namespace canary;

void setUp() {}
void tearDown() {}

static void test_score_and_state_boundaries() {
    TEST_ASSERT_EQUAL(STATE_STARTUP, stateFor(false, 20));
    TEST_ASSERT_EQUAL(STATE_NORMAL, stateFor(true, 2));
    TEST_ASSERT_EQUAL(STATE_CAUTION, stateFor(true, 3));
    TEST_ASSERT_EQUAL(STATE_ALERT, stateFor(true, 6));
    TEST_ASSERT_EQUAL(20, addScore(19, 4));
    TEST_ASSERT_EQUAL(0, decayScore(1));
    TEST_ASSERT_EQUAL(4, decayScore(5));
}

static void test_management_frame_parser_rejects_malformed_frames() {
    ParsedMgmtFrame parsed = {};
    uint8_t shortFrame[23] = {};
    TEST_ASSERT_FALSE(parseManagementFrame(nullptr, 24, &parsed));
    TEST_ASSERT_FALSE(parseManagementFrame(shortFrame, sizeof(shortFrame), &parsed));

    uint8_t dataFrame[24] = {};
    dataFrame[0] = 0x08;
    TEST_ASSERT_FALSE(parseManagementFrame(dataFrame, sizeof(dataFrame), &parsed));
}

static void test_management_frame_parser_extracts_subtype_and_addresses() {
    uint8_t frame[24] = {};
    frame[0] = 0xC0;
    for (int i = 0; i < 6; ++i) {
        frame[4 + i] = static_cast<uint8_t>(0x10 + i);
        frame[10 + i] = static_cast<uint8_t>(0x20 + i);
        frame[16 + i] = static_cast<uint8_t>(0x30 + i);
    }
    ParsedMgmtFrame parsed = {};
    TEST_ASSERT_TRUE(parseManagementFrame(frame, sizeof(frame), &parsed));
    TEST_ASSERT_EQUAL_UINT8(12, parsed.subtype);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(frame + 4, parsed.addr1, 6);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(frame + 10, parsed.addr2, 6);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(frame + 16, parsed.addr3, 6);
}

static void test_beacon_ssid_parser_handles_valid_and_truncated_elements() {
    uint8_t frame[24 + 12 + 12] = {};
    frame[0] = 0x80;
    size_t offset = 24 + 12;
    frame[offset] = 1;
    frame[offset + 1] = 1;
    frame[offset + 2] = 0x82;
    frame[offset + 3] = 0;
    frame[offset + 4] = 6;
    memcpy(frame + offset + 5, "canary", 6);

    uint8_t ssid[16] = {};
    size_t ssidLength = 0;
    TEST_ASSERT_TRUE(extractBeaconSsid(frame, sizeof(frame), ssid, sizeof(ssid), &ssidLength));
    TEST_ASSERT_EQUAL_UINT32(6, ssidLength);
    TEST_ASSERT_EQUAL_STRING("canary", reinterpret_cast<char*>(ssid));

    frame[offset + 4] = 30;
    TEST_ASSERT_FALSE(extractBeaconSsid(frame, sizeof(frame), ssid, sizeof(ssid), &ssidLength));
}

static void test_queue_boundaries() {
    TEST_ASSERT_TRUE(ringHasSpace(0, 0, 4));
    TEST_ASSERT_FALSE(ringHasSpace(3, 0, 4));
    TEST_ASSERT_FALSE(ringHasSpace(0, 0, 1));
    TEST_ASSERT_EQUAL_UINT32(0, ringNext(3, 4));
}

static void test_threshold_engines() {
    TEST_ASSERT_EQUAL(0, deauthBurstPoints(7));
    TEST_ASSERT_EQUAL(2, deauthBurstPoints(8));
    TEST_ASSERT_EQUAL(4, deauthBurstPoints(20));
    TEST_ASSERT_EQUAL(0, broadcastDeauthPoints(4));
    TEST_ASSERT_EQUAL(1, broadcastDeauthPoints(5));
    TEST_ASSERT_EQUAL(0, probeFloodPoints(39));
    TEST_ASSERT_EQUAL(1, probeFloodPoints(40));
    TEST_ASSERT_EQUAL(3, probeFloodPoints(80));
    TEST_ASSERT_EQUAL(2, beaconFloodPoints(15));
    TEST_ASSERT_EQUAL(3, beaconFloodPoints(30));
}

static void test_pwnagotchi_metadata() {
    const char active[] = "{\"name\":\"pwn0\",\"policy\":{\"deauth\":true}}";
    PwnagotchiMetadata parsed = parsePwnagotchiMetadata(
        reinterpret_cast<const uint8_t*>(active), strlen(active));
    TEST_ASSERT_TRUE(parsed.valid);
    TEST_ASSERT_TRUE(parsed.deauth);
    TEST_ASSERT_EQUAL_STRING("pwn0", parsed.name);
    TEST_ASSERT_EQUAL(4, pwnagotchiPoints(parsed.deauth));

    const char passive[] = "{\"name\":\"friend\",\"deauth\":false}";
    parsed = parsePwnagotchiMetadata(reinterpret_cast<const uint8_t*>(passive), strlen(passive));
    TEST_ASSERT_TRUE(parsed.valid);
    TEST_ASSERT_FALSE(parsed.deauth);
    TEST_ASSERT_EQUAL(2, pwnagotchiPoints(parsed.deauth));

    const char invalid[] = "not-json";
    parsed = parsePwnagotchiMetadata(reinterpret_cast<const uint8_t*>(invalid), strlen(invalid));
    TEST_ASSERT_FALSE(parsed.valid);
}

static void test_pineapple_and_mac_helpers() {
    const uint8_t pineapple[6] = {0xAA, 0x13, 0x37, 0x01, 0x02, 0x03};
    const uint8_t normal[6] = {0xAA, 0x12, 0x37, 0x01, 0x02, 0x03};
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    TEST_ASSERT_TRUE(isPineappleBssid(pineapple));
    TEST_ASSERT_FALSE(isPineappleBssid(normal));
    TEST_ASSERT_TRUE(isBroadcastMac(broadcast));
    TEST_ASSERT_FALSE(isBroadcastMac(normal));
}

static void test_access_point_threats() {
    const uint8_t knownBssid[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    const uint8_t cloneBssid[6] = {0x90, 0x80, 0x70, 0x60, 0x50, 0x40};
    AccessPointView baseline = {"HotelWiFi", knownBssid, -60, AUTH_WPA3};

    AccessPointView openClone = {"hotelwifi", cloneBssid, -45, AUTH_OPEN};
    AccessPointThreat threat = evaluateAccessPointThreat(baseline, openClone, true);
    TEST_ASSERT_EQUAL(5, threat.openClonePoints);
    TEST_ASSERT_EQUAL(0, threat.downgradePoints);

    AccessPointView downgrade = {"HotelWiFi", cloneBssid, -60, AUTH_WPA};
    threat = evaluateAccessPointThreat(baseline, downgrade, true);
    TEST_ASSERT_EQUAL(3, threat.downgradePoints);

    AccessPointView duplicate = {"HotelWiFi", cloneBssid, -45, AUTH_WPA3};
    threat = evaluateAccessPointThreat(baseline, duplicate, true);
    TEST_ASSERT_EQUAL(2, threat.duplicateVendorPoints);

    TEST_ASSERT_EQUAL(3, missingOriginalOpenClonePoints(baseline, openClone, false));
    TEST_ASSERT_EQUAL(0, missingOriginalOpenClonePoints(baseline, openClone, true));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_score_and_state_boundaries);
    RUN_TEST(test_management_frame_parser_rejects_malformed_frames);
    RUN_TEST(test_management_frame_parser_extracts_subtype_and_addresses);
    RUN_TEST(test_beacon_ssid_parser_handles_valid_and_truncated_elements);
    RUN_TEST(test_queue_boundaries);
    RUN_TEST(test_threshold_engines);
    RUN_TEST(test_pwnagotchi_metadata);
    RUN_TEST(test_pineapple_and_mac_helpers);
    RUN_TEST(test_access_point_threats);
    return UNITY_END();
}
