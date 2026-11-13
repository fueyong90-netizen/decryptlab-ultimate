#pragma once
#include "dlu/core/common.hpp"
#include <array>
#include <cstdint>

namespace dlu::core {

// Shannon entropy over a byte stream, fed incrementally. Range 0..8 bits/byte.
class EntropyMeter {
public:
    void update(const uint8_t* data, size_t n);
    double bits_per_byte() const;        // 0..8
    double normalized() const;           // 0..1
    uint64_t count() const { return total_; }

    // Interpretation helper. IMPORTANT: high entropy alone is NOT proof of
    // encryption (spec 4.3). Compressed and encrypted data both score high.
    const char* qualitative() const;

private:
    std::array<uint64_t, 256> freq_{};
    uint64_t total_ = 0;
};

// Convenience: compute entropy of a whole file via streaming.
Result<double> file_entropy(const std::string& path);

} // namespace dlu::core
