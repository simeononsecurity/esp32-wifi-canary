#include <string.h>

#include <unity.h>

#include "canary_event.h"

using namespace canary;

void setUp() {}
void tearDown() {}

static EventRecord sampleEvent() {
    EventRecord event = {};
    event.deviceId = "aabbccddeeff";
    event.firmware = kFirmwareVersion;
    event.board = "atom-lite";
    event.uptimeMs = 1234;
    event.eventType = "detection";
    event.detectorId = "open_clone";
    event.scoreDelta = 4;
    event.score = 4;
    event.state = STATE_CAUTION;
    event.reason = "open clone \"Hotel\"";
    event.ssid = "Hotel\\Guest\nWiFi";
    event.bssid = "aa:bb:cc:dd:ee:ff";
    event.channel = 6;
    event.rssi = -48;
    event.health = {19, 42, 6, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, false};
    return event;
}

static void test_event_contains_required_contract_fields() {
    char output[1024];
    const EventRecord event = sampleEvent();
    TEST_ASSERT_TRUE(formatEventJson(output, sizeof(output), event));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"schema\":1"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"device_id\":\"aabbccddeeff\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"firmware\":\"1.2.0-dev\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"board\":\"atom-lite\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"event\":\"detection\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"detector\":\"open_clone\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"state\":\"caution\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"channel\":6"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"rssi\":-48"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"deauth_queue_drops\":2"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"baseline_done\":2"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"baseline_target\":3"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"baseline_learned\":false"));
}

static void test_event_escapes_strings() {
    char output[1024];
    const EventRecord event = sampleEvent();
    TEST_ASSERT_TRUE(formatEventJson(output, sizeof(output), event));
    TEST_ASSERT_NOT_NULL(strstr(output, "open clone \\\"Hotel\\\""));
    TEST_ASSERT_NOT_NULL(strstr(output, "Hotel\\\\Guest\\nWiFi"));
}

static void test_event_writes_null_for_missing_context() {
    char output[1024];
    EventRecord event = sampleEvent();
    event.detectorId = nullptr;
    event.ssid = nullptr;
    event.bssid = nullptr;
    event.channel = -1;
    event.rssi = -127;
    TEST_ASSERT_TRUE(formatEventJson(output, sizeof(output), event));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"detector\":null"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"ssid\":null"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"channel\":null"));
    TEST_ASSERT_NOT_NULL(strstr(output, "\"rssi\":null"));
}

static void test_event_rejects_small_buffer() {
    char output[32];
    const EventRecord event = sampleEvent();
    TEST_ASSERT_FALSE(formatEventJson(output, sizeof(output), event));
    TEST_ASSERT_EQUAL_CHAR('\0', output[sizeof(output) - 1]);
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_event_contains_required_contract_fields);
    RUN_TEST(test_event_escapes_strings);
    RUN_TEST(test_event_writes_null_for_missing_context);
    RUN_TEST(test_event_rejects_small_buffer);
    return UNITY_END();
}
