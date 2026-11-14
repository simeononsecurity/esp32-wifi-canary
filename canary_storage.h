#pragma once

#include <Arduino.h>
#include <esp_partition.h>

#include "canary_config.h"

namespace canary {

inline bool loadConfigPartition(CanaryConfig* config) {
    if (!config) return false;
    const esp_partition_t* partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, static_cast<esp_partition_subtype_t>(0x40), "canarycfg");
    if (!partition || partition->size < sizeof(CanaryConfig)) {
        *config = defaultConfig();
        return false;
    }
    CanaryConfig stored;
    if (esp_partition_read(partition, 0, &stored, sizeof(stored)) != ESP_OK ||
        !validateConfigBytes(reinterpret_cast<const uint8_t*>(&stored), sizeof(stored), config)) {
        *config = defaultConfig();
        return false;
    }
    return true;
}

}  // namespace canary
