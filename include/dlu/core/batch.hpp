#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <vector>
#include <functional>

namespace dlu::core {

struct BatchProgress {
    size_t total = 0;
    size_t done = 0;
    size_t errors = 0;
    std::string current;
};

// Batch processing engine (spec 4.7) with resume-after-interruption.
// Walks a directory, analyzes each file, writes one NDJSON line per result, and
// checkpoints completed paths so an interrupted run can resume where it stopped.
class BatchEngine {
public:
    // checkpoint_path stores processed file paths (one per line). If it exists,
    // those files are skipped (resume). out_ndjson receives one JSON object/line.
    Result<BatchProgress> run(const std::string& root,
                              const std::string& out_ndjson,
                              const std::string& checkpoint_path,
                              bool recursive = true,
                              const std::function<void(const BatchProgress&)>& on_progress = nullptr);
};

} // namespace dlu::core
