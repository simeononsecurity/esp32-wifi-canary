#pragma once

#include <Arduino.h>
#include <esp_partition.h>

#include "canary_config.h"

namespace canary {

constexpr uint32_t kLogMagic = 0x474F4C43UL;
constexpr size_t kLogRecordSize = 512;

#pragma pack(push, 1)
struct LogRecord {
    uint32_t magic;
    uint32_t sequence;
    uint16_t length;
    uint16_t version;
    char json[496];
    uint32_t crc32;
};
#pragma pack(pop)

static_assert(sizeof(LogRecord) == kLogRecordSize, "log record layout changed");

class EventLog {
public:
    bool begin() {
        partition_ = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
            static_cast<esp_partition_subtype_t>(0x41), "canarylog");
        if (!partition_) return false;
        slots_ = partition_->size / kLogRecordSize;
        nextSlot_ = 0;
        nextSequence_ = 1;
        for (size_t slot = 0; slot < slots_; ++slot) {
            LogRecord record;
            if (esp_partition_read(partition_, slot * kLogRecordSize, &record, sizeof(record)) != ESP_OK) break;
            if (record.magic == 0xFFFFFFFFUL) { nextSlot_ = slot; break; }
            if (valid(record) && record.sequence >= nextSequence_) {
                nextSequence_ = record.sequence + 1;
                nextSlot_ = slot + 1;
            }
        }
        return true;
    }

    bool append(const char* json) {
        if (!partition_ || !json) return false;
        if (nextSlot_ >= slots_) {
            if (esp_partition_erase_range(partition_, 0, partition_->size) != ESP_OK) return false;
            losses_ += slots_;
            nextSlot_ = 0;
        }
        LogRecord record;
        memset(&record, 0xFF, sizeof(record));
        record.magic = kLogMagic;
        record.sequence = nextSequence_++;
        record.version = 1;
        const size_t length = strnlen(json, sizeof(record.json) - 1);
        record.length = static_cast<uint16_t>(length);
        memcpy(record.json, json, length);
        record.json[length] = '\0';
        record.crc32 = configCrc32(reinterpret_cast<const uint8_t*>(&record), offsetof(LogRecord, crc32));
        if (esp_partition_write(partition_, nextSlot_ * kLogRecordSize, &record, sizeof(record)) != ESP_OK) return false;
        ++nextSlot_;
        return true;
    }

    void dump(Stream& output) const {
        if (!partition_) return;
        for (size_t slot = 0; slot < slots_; ++slot) {
            LogRecord record;
            if (esp_partition_read(partition_, slot * kLogRecordSize, &record, sizeof(record)) != ESP_OK) break;
            if (record.magic == 0xFFFFFFFFUL) break;
            if (valid(record)) output.println(record.json);
        }
    }

    bool clear() {
        if (!partition_) return false;
        const bool ok = esp_partition_erase_range(partition_, 0, partition_->size) == ESP_OK;
        if (ok) { nextSlot_ = 0; nextSequence_ = 1; }
        return ok;
    }

    uint32_t losses() const { return losses_; }

private:
    bool valid(const LogRecord& record) const {
        return record.magic == kLogMagic && record.version == 1 &&
               record.length < sizeof(record.json) && record.json[record.length] == '\0' &&
               record.crc32 == configCrc32(reinterpret_cast<const uint8_t*>(&record), offsetof(LogRecord, crc32));
    }
    const esp_partition_t* partition_ = nullptr;
    size_t slots_ = 0;
    size_t nextSlot_ = 0;
    uint32_t nextSequence_ = 1;
    uint32_t losses_ = 0;
};

}  // namespace canary
