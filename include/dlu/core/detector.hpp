#pragma once
#include "dlu/core/common.hpp"
#include "dlu/core/signatures.hpp"
#include <string>
#include <vector>

namespace dlu::core {

struct Hypothesis {
    std::string format_id;
    std::string label;
    std::string category;
    std::string mime;
    int confidence = 0;             // 0..100
    std::vector<std::string> evidence;
};

struct DetectionReport {
    std::string path;
    std::string declared_extension;
    uint64_t size = 0;
    std::vector<Hypothesis> hypotheses;   // sorted, best first
    bool extension_mismatch = false;      // declared ext disagrees with content
    bool looks_text = false;
    bool looks_encoded_base64 = false;
};

// The Intelligent File Recognition Engine: signature match + structural hints +
// text/encoding heuristics. Explains the evidence behind each hypothesis and
// flags deceptive extensions (spec 4.1).
class Detector {
public:
    DetectionReport detect(const std::string& path) const;
    // Detect from an in-memory buffer (used by VPN/URI paths and tests).
    DetectionReport detect_bytes(const std::vector<uint8_t>& data,
                                 const std::string& declared_ext = "",
                                 const std::string& path = "<memory>") const;
};

} // namespace dlu::core
