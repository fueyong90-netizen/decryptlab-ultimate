#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace dlu::core {

struct Signature {
    std::string id;            // e.g. "zip", "pdf", "elf"
    std::string label;         // human label
    std::string category;      // archive, document, binary, image, media, crypto, vpn
    std::vector<uint8_t> magic;
    size_t offset = 0;         // where magic must appear
    std::string mime;
    std::vector<std::string> extensions; // typical extensions (no dot)
};

// The built-in signature database (extensible at runtime via the plugin/db layer).
const std::vector<Signature>& builtin_signatures();

} // namespace dlu::core
