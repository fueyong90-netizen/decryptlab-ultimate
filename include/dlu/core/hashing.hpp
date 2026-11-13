#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <cstdint>

namespace dlu::core {

// Streaming SHA-256 / SHA-1 / MD5 over a file (memory-safe for large inputs).
// Backed by OpenSSL EVP. Returns lowercase hex.
Result<std::string> sha256_file(const std::string& path);
Result<std::string> sha1_file(const std::string& path);
Result<std::string> md5_file(const std::string& path);

std::string sha256_bytes(const uint8_t* data, size_t len);

} // namespace dlu::core
