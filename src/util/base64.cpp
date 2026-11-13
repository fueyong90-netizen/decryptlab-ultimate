#include "dlu/util/base64.hpp"
#include <array>

namespace dlu::util {

static const char kEnc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::array<int8_t, 256> build_dec_table(bool url) {
    std::array<int8_t, 256> t{};
    t.fill(-1);
    for (int i = 0; i < 64; ++i) t[(uint8_t)kEnc[i]] = (int8_t)i;
    if (url) {
        t[(uint8_t)'-'] = 62;
        t[(uint8_t)'_'] = 63;
    }
    return t;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kEnc[(n >> 18) & 63]);
        out.push_back(kEnc[(n >> 12) & 63]);
        out.push_back(kEnc[(n >> 6) & 63]);
        out.push_back(kEnc[n & 63]);
    }
    if (i < data.size()) {
        uint32_t n = data[i] << 16;
        bool two = (i + 1 < data.size());
        if (two) n |= data[i + 1] << 8;
        out.push_back(kEnc[(n >> 18) & 63]);
        out.push_back(kEnc[(n >> 12) & 63]);
        out.push_back(two ? kEnc[(n >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::string& data) {
    return base64_encode(std::vector<uint8_t>(data.begin(), data.end()));
}

static std::optional<std::vector<uint8_t>> decode_impl(const std::string& text, bool url) {
    static const auto std_tbl = build_dec_table(false);
    static const auto url_tbl = build_dec_table(true);
    const auto& tbl = url ? url_tbl : std_tbl;

    std::vector<uint8_t> out;
    out.reserve(text.size() / 4 * 3 + 3);
    uint32_t buf = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int8_t v = tbl[(uint8_t)c];
        if (v < 0) return std::nullopt;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::optional<std::vector<uint8_t>> base64_decode(const std::string& text) {
    return decode_impl(text, false);
}

std::optional<std::vector<uint8_t>> base64url_decode(const std::string& text) {
    return decode_impl(text, true);
}

bool looks_like_base64(const std::string& text, size_t min_decoded) {
    if (text.empty()) return false;
    size_t valid = 0, total = 0;
    for (char c : text) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        ++total;
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
                  c == '-' || c == '_';
        if (ok) ++valid;
    }
    if (total == 0) return false;
    if (valid != total) return false;
    return (total * 3 / 4) >= min_decoded;
}

} // namespace dlu::util
