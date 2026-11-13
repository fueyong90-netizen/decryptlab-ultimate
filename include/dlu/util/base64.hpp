#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace dlu::util {

// Standard Base64 (RFC 4648) encode/decode. Decode is tolerant of whitespace
// and missing padding, and returns std::nullopt on invalid input.
std::string base64_encode(const std::vector<uint8_t>& data);
std::string base64_encode(const std::string& data);
std::optional<std::vector<uint8_t>> base64_decode(const std::string& text);

// URL-safe Base64 variant (-_ instead of +/). Used by some VPN URIs.
std::optional<std::vector<uint8_t>> base64url_decode(const std::string& text);

// Heuristic: does the string look like a plausible Base64 blob of >= min_len
// decoded bytes? Used by the format detector, never as proof of encoding.
bool looks_like_base64(const std::string& text, size_t min_decoded = 8);

} // namespace dlu::util
