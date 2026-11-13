#include "dlu/core/common.hpp"

namespace dlu {

const char* to_string(Support s) {
    switch (s) {
        case Support::Implemented: return "implemented+tested";
        case Support::PartiallyTested: return "implemented (partial tests)";
        case Support::InterfaceOnly: return "interface only";
        case Support::Unsupported: return "unsupported";
    }
    return "unknown";
}

const char* to_string(OpStatus s) {
    switch (s) {
        case OpStatus::Success: return "success";
        case OpStatus::Partial: return "partial";
        case OpStatus::Failed: return "failed";
        case OpStatus::Skipped: return "skipped";
    }
    return "unknown";
}

} // namespace dlu
