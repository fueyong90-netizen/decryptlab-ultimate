#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace dlu::util {

std::string to_hex(const std::vector<uint8_t>& data, bool upper = false);
std::string to_hex(const uint8_t* data, size_t len, bool upper = false);

// Render a classic hexdump (offset | hex | ascii) of up to max_bytes.
std::string hexdump(const std::vector<uint8_t>& data, size_t max_bytes = 256);

} // namespace dlu::util
