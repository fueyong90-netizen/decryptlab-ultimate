#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace dlu::core {

// Read at most max_bytes from the start of a file (for header inspection).
Result<std::vector<uint8_t>> read_prefix(const std::string& path, size_t max_bytes);

// Read the whole file. Refuses files larger than limit to protect memory on
// modest machines (spec section 8). Use stream_file for large inputs.
Result<std::vector<uint8_t>> read_all(const std::string& path, size_t limit = 256u * 1024 * 1024);

// Stream a file in blocks, invoking cb for each chunk. Returns total bytes read.
// This is the memory-safe path for hashing / entropy over large files.
Result<uint64_t> stream_file(const std::string& path, size_t block_size,
                             const std::function<void(const uint8_t*, size_t)>& cb);

Result<uint64_t> file_size(const std::string& path);
bool file_exists(const std::string& path);
std::string file_extension(const std::string& path); // lowercased, without dot
std::string file_name(const std::string& path);

} // namespace dlu::core
