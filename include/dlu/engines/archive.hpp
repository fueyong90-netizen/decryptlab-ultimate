#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace dlu::engines {

struct ZipEntry {
    std::string name;
    uint64_t compressed_size = 0;
    uint64_t uncompressed_size = 0;
    uint16_t method = 0;         // 0 store, 8 deflate
    bool encrypted = false;
    uint32_t crc32 = 0;
};

struct ZipReport {
    bool valid = false;
    std::vector<ZipEntry> entries;
    bool has_encrypted = false;
    bool zip_bomb_suspected = false;   // extreme ratio / entry count
    uint64_t total_uncompressed = 0;
    std::string error;
    std::vector<std::string> notes;
};

// Read-only ZIP central-directory inspection. Does NOT extract; reports
// structure, password-protection flag, and zip-bomb risk (ratio & count caps).
// Deliberately avoids decompressing untrusted data.
ZipReport inspect_zip(const std::string& path);

} // namespace dlu::engines
