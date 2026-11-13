#include "dlu/engines/proprietary.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/core/entropy.hpp"
#include "dlu/util/base64.hpp"
#include <algorithm>
#include <cctype>

namespace dlu::engines {

static std::vector<std::string> extract_ascii_strings(const std::vector<uint8_t>& d,
                                                       size_t min_len, size_t max_out) {
    std::vector<std::string> out;
    std::string cur;
    for (uint8_t b : d) {
        if (b >= 0x20 && b < 0x7F) { cur.push_back((char)b); }
        else { if (cur.size() >= min_len) { out.push_back(cur); if (out.size()>=max_out) break; } cur.clear(); }
    }
    if (cur.size() >= min_len && out.size() < max_out) out.push_back(cur);
    return out;
}

ProprietaryReport ProprietaryInspector::inspect(const std::string& path) const {
    ProprietaryReport r;
    auto data = core::read_all(path, 32u * 1024 * 1024);
    if (!data) { r.limitation = data.error; return r; }
    return inspect_bytes(data.value, core::file_extension(path));
}

ProprietaryReport ProprietaryInspector::inspect_bytes(const std::vector<uint8_t>& data,
                                                      const std::string& ext) const {
    ProprietaryReport r;
    core::EntropyMeter m; m.update(data.data(), data.size());
    r.entropy = m.bits_per_byte();

    if (ext == "ehi") { r.format_guess = "ehi"; r.origin_app = "HTTP Injector"; }
    else if (ext == "hc") { r.format_guess = "hc"; r.origin_app = "HTTP Custom"; }
    else if (ext == "npvs" || ext == "npv4") { r.format_guess = "npvs"; r.origin_app = "NapsternetV"; }
    else if (ext == "hat") { r.format_guess = "hat"; r.origin_app = "HA Tunnel Plus"; }
    else { r.format_guess = "unknown-proprietary"; r.origin_app = "unknown"; }

    // Structural heuristics (never a decode).
    std::string head((const char*)data.data(), std::min<size_t>(data.size(), 4096));
    std::string compact = head;
    compact.erase(std::remove_if(compact.begin(), compact.end(),
                  [](char c){return c=='\n'||c=='\r'||c==' ';}), compact.end());
    r.looks_base64 = dlu::util::looks_like_base64(compact, 32);

    if (data.size() >= 2) {
        if (data[0]==0x1F && data[1]==0x8B) { r.looks_compressed = true;
            r.observations.push_back("GZIP magic at offset 0"); }
        if (data[0]==0x50 && data[1]==0x4B) { r.looks_compressed = true;
            r.observations.push_back("ZIP/PK magic at offset 0"); }
    }
    r.looks_encrypted = (r.entropy > 7.5) && !r.looks_compressed;

    r.observations.push_back("size: " + std::to_string(data.size()) + " bytes");
    r.observations.push_back("entropy: " + std::to_string(r.entropy) + " bits/byte (" +
                             std::string(m.qualitative()) + ")");
    if (r.looks_base64) r.observations.push_back("payload charset is Base64-compatible");

    // Only surface clearly non-secret plaintext hints (scheme labels, markers).
    auto strings = extract_ascii_strings(data, 5, 40);
    for (auto& s : strings) {
        std::string low = s; std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("http")!=std::string::npos || low.find("inject")!=std::string::npos ||
            low.find("config")!=std::string::npos || low.find("version")!=std::string::npos ||
            low.find("vpn")!=std::string::npos || low.find("sni")!=std::string::npos)
            r.readable_strings.push_back(s);
        if (r.readable_strings.size() >= 10) break;
    }

    // Verdict + explicit limitation (the honest core of this engine).
    if (r.looks_encrypted) {
        r.protection_state = "appears encrypted / obfuscated by the originating app";
        r.limitation =
            "This file appears to be encrypted or obfuscated by its creator. "
            "DecryptLab identifies and documents the format but does NOT break the "
            "author's protection or extract keys/passwords locked inside. Decoding it "
            "would require the format's algorithm and key, which are not derivable from "
            "the file alone.";
    } else if (r.looks_compressed) {
        r.protection_state = "compressed container (not necessarily encrypted)";
        r.limitation =
            "Content looks compressed. Decompression of a known container is possible, "
            "but any inner proprietary structure is only documented, not decrypted.";
    } else if (r.looks_base64) {
        r.protection_state = "Base64-encoded payload (encoding, not encryption)";
        r.limitation =
            "The payload is Base64-encoded. Decoding reveals the wrapped bytes, which "
            "may themselves be a proprietary or encrypted structure reported separately.";
    } else {
        r.protection_state = "no strong protection signal detected";
        r.limitation =
            "No high-entropy encryption signal detected. The structure is documented "
            "below; interpretation of proprietary fields requires the format spec.";
    }
    return r;
}

} // namespace dlu::engines
