#pragma once
#include "dlu/util/json.hpp"
#include <string>

namespace dlu::engines {

// Metadata Intelligence Engine (spec 4.3): filesystem + container-level metadata
// that complements the analyzer (timestamps, permissions, MIME, hashes).
util::Json extract_metadata(const std::string& path);

} // namespace dlu::engines
