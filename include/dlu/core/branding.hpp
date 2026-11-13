#pragma once
#include <string>

namespace dlu::brand {

namespace ansi {
    constexpr const char* reset = "\033[0m";
    constexpr const char* bold  = "\033[1m";
    constexpr const char* red   = "\033[38;5;196m";
    constexpr const char* dred  = "\033[38;5;88m";
    constexpr const char* white = "\033[97m";
    constexpr const char* green = "\033[38;5;46m";
    constexpr const char* gray  = "\033[38;5;245m";
}

// Full ASCII logo (skull + wordmark). color=false yields a monochrome version
// for pipes / non-TTY terminals.
std::string logo_full(bool color = true);
std::string logo_compact(bool color = true);
std::string banner(bool color, const std::string& version,
                   const std::string& arch, const std::string& os);

} // namespace dlu::brand
