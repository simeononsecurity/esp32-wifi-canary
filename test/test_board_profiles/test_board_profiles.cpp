#include <unity.h>

#include "canary_board_profile.h"

using namespace canary;

void setUp() {}
void tearDown() {}

static void test_all_profiles_have_stable_ids() {
    TEST_ASSERT_EQUAL_STRING("atom-lite", profileFor(BOARD_ATOM_LITE).id);
    TEST_ASSERT_EQUAL_STRING("esp32dev", profileFor(BOARD_ESP32DEV).id);
    TEST_ASSERT_EQUAL_STRING("atom-echo", profileFor(BOARD_ATOM_ECHO).id);
    TEST_ASSERT_EQUAL_STRING("atom-voice", profileFor(BOARD_ATOM_VOICE).id);
    TEST_ASSERT_EQUAL_STRING("m5stack-basic", profileFor(BOARD_M5STACK_BASIC).id);
    TEST_ASSERT_EQUAL_STRING("m5stack-core2-aws", profileFor(BOARD_CORE2_AWS).id);
    TEST_ASSERT_EQUAL_STRING("m5stickc-plus-se", profileFor(BOARD_M5STICKC_PLUS_SE).id);
    TEST_ASSERT_EQUAL_STRING("lilygo-t-dongle-c5", profileFor(BOARD_T_DONGLE_C5).id);
}

static void test_capabilities_match_physical_outputs() {
    TEST_ASSERT_TRUE(profileFor(BOARD_ATOM_LITE).rgbLed);
    TEST_ASSERT_FALSE(profileFor(BOARD_ATOM_LITE).audio);
    TEST_ASSERT_TRUE(profileFor(BOARD_ATOM_VOICE).audio);
    TEST_ASSERT_TRUE(profileFor(BOARD_M5STACK_BASIC).display);
    TEST_ASSERT_TRUE(profileFor(BOARD_CORE2_AWS).haptic);
    TEST_ASSERT_TRUE(profileFor(BOARD_M5STICKC_PLUS_SE).audio);
    TEST_ASSERT_TRUE(profileFor(BOARD_T_DONGLE_C5).experimental);
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_all_profiles_have_stable_ids);
    RUN_TEST(test_capabilities_match_physical_outputs);
    return UNITY_END();
}
