#include "dlu/core/entropy.hpp"
#include "dlu/core/fileio.hpp"
#include <cmath>

namespace dlu::core {

void EntropyMeter::update(const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; ++i) ++freq_[data[i]];
    total_ += n;
}

double EntropyMeter::bits_per_byte() const {
    if (total_ == 0) return 0.0;
    double h = 0.0;
    for (uint64_t c : freq_) {
        if (!c) continue;
        double p = (double)c / (double)total_;
        h -= p * std::log2(p);
    }
    return h;
}

double EntropyMeter::normalized() const { return bits_per_byte() / 8.0; }

const char* EntropyMeter::qualitative() const {
    double h = bits_per_byte();
    if (total_ == 0) return "empty";
    if (h < 1.0) return "very low (highly repetitive / padded)";
    if (h < 4.0) return "low (structured text / markup)";
    if (h < 6.5) return "medium (mixed content)";
    if (h < 7.5) return "high (compressed OR encoded)";
    return "very high (compressed, encrypted, or random)";
}

Result<double> file_entropy(const std::string& path) {
    EntropyMeter m;
    auto r = stream_file(path, 1u << 20, [&](const uint8_t* p, size_t n) {
        m.update(p, n);
    });
    if (!r) return Result<double>::fail(r.error);
    return Result<double>::good(m.bits_per_byte());
}

} // namespace dlu::core
