#pragma once
#include "dlu/core/common.hpp"
#include "dlu/util/json.hpp"
#include <string>

namespace dlu::core {

// The central orchestrator (spec sec. 8): identify -> fingerprint -> inspect
// structure -> select engines -> report. Deterministic and explainable; it never
// invents a technical result. Produces a structured JSON report plus a short
// human verdict.
class Analyzer {
public:
    // Full analysis of one file. include_hashes can be disabled for speed.
    util::Json analyze(const std::string& path, bool include_hashes = true) const;
};

} // namespace dlu::core
