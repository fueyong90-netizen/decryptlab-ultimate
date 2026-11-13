#include "dlu/core/detector.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/util/base64.hpp"
#include <algorithm>
#include <cctype>

namespace dlu::core {

static bool magic_at(const std::vector<uint8_t>& d, const Signature& s) {
    if (d.size() < s.offset + s.magic.size()) return false;
    for (size_t i = 0; i < s.magic.size(); ++i)
        if (d[s.offset + i] != s.magic[i]) return false;
    return true;
}

static bool mostly_text(const std::vector<uint8_t>& d) {
    if (d.empty()) return false;
    size_t printable = 0, n = std::min<size_t>(d.size(), 4096);
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = d[i];
        if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b < 0x7F)) ++printable;
        else if (b >= 0x80) ++printable; // allow UTF-8 continuation bytes
    }
    return printable * 100 / n >= 92;
}

DetectionReport Detector::detect(const std::string& path) const {
    DetectionReport rep;
    rep.path = path;
    rep.declared_extension = file_extension(path);
    auto sz = file_size(path);
    if (sz) rep.size = sz.value;
    auto pref = read_prefix(path, 65536);
    if (!pref) {
        Hypothesis h; h.format_id = "error"; h.label = pref.error; h.confidence = 0;
        rep.hypotheses.push_back(h);
        return rep;
    }
    auto out = detect_bytes(pref.value, rep.declared_extension, path);
    out.size = rep.size; // keep real file size, not prefix size
    return out;
}

// shared finalization (declared here as free function via detect_bytes)
DetectionReport Detector::detect_bytes(const std::vector<uint8_t>& data,
                                       const std::string& declared_ext,
                                       const std::string& path) const {
    DetectionReport rep;
    rep.path = path;
    rep.declared_extension = declared_ext;
    rep.size = data.size();

    for (const auto& s : builtin_signatures()) {
        if (magic_at(data, s)) {
            Hypothesis h;
            h.format_id = s.id;
            h.label = s.label;
            h.category = s.category;
            h.mime = s.mime;
            h.confidence = 90;
            h.evidence.push_back("magic bytes matched at offset " + std::to_string(s.offset));
            // Extension corroboration.
            if (!declared_ext.empty()) {
                bool listed = std::find(s.extensions.begin(), s.extensions.end(),
                                        declared_ext) != s.extensions.end();
                if (listed) { h.confidence = std::min(99, h.confidence + 8);
                    h.evidence.push_back("extension '." + declared_ext + "' consistent"); }
                else h.evidence.push_back("extension '." + declared_ext +
                                          "' not typical for this format");
            }
            rep.hypotheses.push_back(h);
        }
    }

    rep.looks_text = mostly_text(data);
    if (rep.looks_text) {
        std::string head((const char*)data.data(),
                         std::min<size_t>(data.size(), 4096));
        // Trim leading whitespace for structured sniffing.
        size_t p = head.find_first_not_of(" \t\r\n");
        std::string t = p == std::string::npos ? "" : head.substr(p);
        auto add = [&](const char* id, const char* label, int conf, const char* why) {
            Hypothesis h; h.format_id = id; h.label = label; h.category = "text";
            h.mime = "text/plain"; h.confidence = conf; h.evidence.push_back(why);
            rep.hypotheses.push_back(h);
        };
        if (t.rfind("vmess://",0)==0||t.rfind("vless://",0)==0||t.rfind("trojan://",0)==0||
            t.rfind("ss://",0)==0||t.rfind("ssr://",0)==0)
            add("vpn_uri", "VPN share URI", 85, "known VPN URI scheme prefix");
        else if (t.find("[Interface]")!=std::string::npos && t.find("[Peer]")!=std::string::npos)
            add("wireguard", "WireGuard config", 85, "[Interface]/[Peer] sections");
        else if (t.find("remote ")!=std::string::npos &&
                 (t.find("client")!=std::string::npos || t.find("dev ")!=std::string::npos))
            add("ovpn", "OpenVPN config (candidate)", 60, "contains 'remote'/'client'/'dev' directives");
        else if (!t.empty() && (t[0] == '{' || t[0] == '[')) add("json", "JSON text", 70, "starts with { or [");
        else if (t.rfind("<?xml", 0) == 0) add("xml", "XML document", 75, "XML prolog");
        else if (t.rfind("---", 0) == 0 || t.find(":\n") != std::string::npos) add("yaml", "YAML (candidate)", 45, "YAML-like structure");
        else if (util::looks_like_base64(t, 32)) {
            rep.looks_encoded_base64 = true;
            add("base64", "Base64-encoded blob", 40, "charset is pure Base64");
        } else add("text", "Plain text", 30, "mostly printable characters");
    }

    if (rep.hypotheses.empty()) {
        Hypothesis h; h.format_id = "unknown"; h.label = "Unknown / unrecognized";
        h.category = "unknown"; h.confidence = 10;
        h.evidence.push_back("no known signature; not predominantly text");
        rep.hypotheses.push_back(h);
    }

    std::sort(rep.hypotheses.begin(), rep.hypotheses.end(),
              [](const Hypothesis& a, const Hypothesis& b){ return a.confidence > b.confidence; });

    // Deceptive extension: top content hypothesis is a known binary format whose
    // extension list does not include the declared extension.
    if (!declared_ext.empty() && !rep.hypotheses.empty()) {
        const auto& top = rep.hypotheses.front();
        if (top.confidence >= 80 && top.category != "text") {
            for (const auto& s : builtin_signatures()) {
                if (s.id == top.format_id) {
                    bool listed = std::find(s.extensions.begin(), s.extensions.end(),
                                            declared_ext) != s.extensions.end();
                    if (!listed) rep.extension_mismatch = true;
                    break;
                }
            }
        }
    }
    return rep;
}

} // namespace dlu::core
