#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <vector>

namespace dlu::core {

struct ScanItem {
    std::string path;
    uint64_t size = 0;
    std::string sha256;
    std::string top_format;
    std::string category;
    bool extension_mismatch = false;
};

struct ScanResult {
    std::vector<ScanItem> items;
    uint64_t total_bytes = 0;
    size_t errors = 0;
};

// Walk a file or directory (optionally recursive), building an inventory with
// hashes and best-guess format per file. Memory-safe: hashing is streamed.
class Scanner {
public:
    explicit Scanner(bool recursive = true, bool hash = true)
        : recursive_(recursive), hash_(hash) {}
    ScanResult scan(const std::string& path) const;
private:
    bool recursive_;
    bool hash_;
    void scan_dir(const std::string& dir, ScanResult& out) const;
    void scan_file(const std::string& file, ScanResult& out) const;
};

} // namespace dlu::core
