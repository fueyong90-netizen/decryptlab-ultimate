#include "dlu/util/hex.hpp"
#include <cstdio>
#include <cctype>

namespace dlu::util {

std::string to_hex(const uint8_t* data, size_t len, bool upper) {
    static const char* lo = "0123456789abcdef";
    static const char* hi = "0123456789ABCDEF";
    const char* t = upper ? hi : lo;
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(t[data[i] >> 4]);
        out.push_back(t[data[i] & 0xF]);
    }
    return out;
}

std::string to_hex(const std::vector<uint8_t>& data, bool upper) {
    return to_hex(data.data(), data.size(), upper);
}

std::string hexdump(const std::vector<uint8_t>& data, size_t max_bytes) {
    std::string out;
    size_t n = data.size() < max_bytes ? data.size() : max_bytes;
    char line[128];
    for (size_t off = 0; off < n; off += 16) {
        int p = snprintf(line, sizeof(line), "%08zx  ", off);
        out.append(line, p);
        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < n) {
                uint8_t b = data[off + i];
                p = snprintf(line, sizeof(line), "%02x ", b);
                out.append(line, p);
                ascii.push_back(std::isprint(b) ? (char)b : '.');
            } else {
                out.append("   ");
                ascii.push_back(' ');
            }
            if (i == 7) out.push_back(' ');
        }
        out.append(" |");
        out.append(ascii);
        out.append("|\n");
    }
    if (data.size() > n) out.append("... (truncated)\n");
    return out;
}

} // namespace dlu::util
