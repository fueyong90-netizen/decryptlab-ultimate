#pragma once
#include "dlu/core/common.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace dlu::engines {

// Honest inspection of proprietary tunnel-config formats (.ehi/.hc/.npvs/.hat).
// DecryptLab reports STRUCTURE and PROTECTION STATE only. It does not and will
// not defeat the obfuscation/encryption an author placed on these files, nor
// extract secrets locked inside configs the user does not own. This separation
// (detection vs. decoding vs. decryption) is mandated by the spec (sec. 13).
struct ProprietaryReport {
    std::string format_guess;       // "ehi", "hc", "npvs", "hat", "unknown-proprietary"
    std::string origin_app;         // best-effort app attribution
    double entropy = 0.0;
    bool looks_encrypted = false;
    bool looks_base64 = false;
    bool looks_compressed = false;
    std::string protection_state;   // human-readable verdict
    std::string limitation;         // explicit limitation message
    std::vector<std::string> observations;
    std::vector<std::string> readable_strings; // only non-secret plaintext hints
};

class ProprietaryInspector {
public:
    ProprietaryReport inspect(const std::string& path) const;
    ProprietaryReport inspect_bytes(const std::vector<uint8_t>& data,
                                    const std::string& ext) const;
};

} // namespace dlu::engines
