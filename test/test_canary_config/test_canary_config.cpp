#include <unity.h>
#include "canary_config.h"

using namespace canary;

void test_default_config_is_valid() {
    CanaryConfig source = defaultConfig();
    CanaryConfig parsed = {};
    TEST_ASSERT_TRUE(validateConfigBytes(reinterpret_cast<const uint8_t*>(&source), sizeof(source), &parsed));
    TEST_ASSERT_EQUAL_UINT16(kAllEngines, parsed.engineMask);
}

void test_blank_corrupt_truncated_and_newer_are_rejected() {
    uint8_t blank[sizeof(CanaryConfig)];
    memset(blank, 0xFF, sizeof(blank));
    TEST_ASSERT_FALSE(validateConfigBytes(blank, sizeof(blank), nullptr));

    CanaryConfig config = defaultConfig();
    reinterpret_cast<uint8_t*>(&config)[8] ^= 0x20;
    TEST_ASSERT_FALSE(validateConfigBytes(reinterpret_cast<uint8_t*>(&config), sizeof(config), nullptr));

    config = defaultConfig();
    TEST_ASSERT_FALSE(validateConfigBytes(reinterpret_cast<uint8_t*>(&config), sizeof(config) - 1, nullptr));

    config = defaultConfig();
    config.version = kConfigVersion + 1;
    config.crc32 = configCrc32(reinterpret_cast<uint8_t*>(&config), offsetof(CanaryConfig, crc32));
    TEST_ASSERT_FALSE(validateConfigBytes(reinterpret_cast<uint8_t*>(&config), sizeof(config), nullptr));
}

void test_engine_toggles_and_sensitivity() {
    CanaryConfig config = defaultConfig();
    config.engineMask &= ~(1U << detectorBit("probe_flood"));
    TEST_ASSERT_FALSE(detectorEnabled(config, "probe_flood"));
    TEST_ASSERT_TRUE(detectorEnabled(config, "open_clone"));
    config.sensitivity = SENSITIVITY_LOW;
    TEST_ASSERT_EQUAL_INT(3, sensitivityAdjusted(config, 4));
    config.sensitivity = SENSITIVITY_HIGH;
    TEST_ASSERT_EQUAL_INT(5, sensitivityAdjusted(config, 4));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_default_config_is_valid);
    RUN_TEST(test_blank_corrupt_truncated_and_newer_are_rejected);
    RUN_TEST(test_engine_toggles_and_sensitivity);
    return UNITY_END();
}
