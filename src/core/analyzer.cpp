#include "dlu/core/analyzer.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/core/hashing.hpp"
#include "dlu/core/entropy.hpp"
#include "dlu/core/detector.hpp"
#include "dlu/engines/archive.hpp"
#include "dlu/engines/proprietary.hpp"
#include "dlu/vpn/parser.hpp"
#include "dlu/vpn/auditor.hpp"
#include <algorithm>

namespace dlu::core {

using util::Json;

static bool is_proprietary_ext(const std::string& e) {
    return e=="ehi"||e=="hc"||e=="npvs"||e=="npv4"||e=="hat";
}
static bool is_open_vpn_ext(const std::string& e) {
    return e=="ovpn"||e=="conf"||e=="wg"||e=="json"||e=="yaml"||e=="yml"||e=="txt";
}

Json Analyzer::analyze(const std::string& path, bool include_hashes) const {
    Json out = Json::object();
    out["tool"] = std::string("DecryptLab Ultimate ") + kVersion;
    out["file"] = file_name(path);
    out["path"] = path;

    if (!file_exists(path)) {
        out["status"] = "error";
        out["error"] = "file not found";
        return out;
    }
    auto sz = file_size(path);
    out["size"] = sz ? (int64_t)sz.value : 0;
    std::string ext = file_extension(path);
    out["declared_extension"] = ext;

    // Fingerprints.
    if (include_hashes) {
        Json h = Json::object();
        auto s256 = sha256_file(path);
        if (s256) h["sha256"] = s256.value;
        auto s1 = sha1_file(path);
        if (s1) h["sha1"] = s1.value;
        out["hashes"] = h;
    }

    // Entropy.
    auto ent = file_entropy(path);
    if (ent) {
        Json e = Json::object();
        e["bits_per_byte"] = ent.value;
        EntropyMeter tmp; // for qualitative label
        out["entropy"] = e;
        out["entropy"]["note"] = "high entropy alone is NOT proof of encryption";
    }

    // Detection.
    Detector det;
    auto rep = det.detect(path);
    Json dj = Json::object();
    dj["extension_mismatch"] = rep.extension_mismatch;
    dj["looks_text"] = rep.looks_text;
    Json hyps = Json::array();
    for (const auto& h : rep.hypotheses) {
        Json jh = Json::object();
        jh["format"] = h.format_id; jh["label"] = h.label;
        jh["category"] = h.category; jh["confidence"] = h.confidence;
        Json ev = Json::array(); for (auto& e : h.evidence) ev.push_back(e);
        jh["evidence"] = ev;
        hyps.push_back(jh);
    }
    dj["hypotheses"] = hyps;
    out["detection"] = dj;

    std::string top_cat = rep.hypotheses.empty()? "" : rep.hypotheses.front().category;
    std::string top_fmt = rep.hypotheses.empty()? "" : rep.hypotheses.front().format_id;

    // Route: proprietary VPN formats -> honest inspector (no cracking).
    if (is_proprietary_ext(ext)) {
        engines::ProprietaryInspector insp;
        auto pr = insp.inspect(path);
        Json j = Json::object();
        j["format_guess"] = pr.format_guess;
        j["origin_app"] = pr.origin_app;
        j["entropy"] = pr.entropy;
        j["looks_encrypted"] = pr.looks_encrypted;
        j["looks_base64"] = pr.looks_base64;
        j["looks_compressed"] = pr.looks_compressed;
        j["protection_state"] = pr.protection_state;
        j["limitation"] = pr.limitation;
        Json obs = Json::array(); for (auto& o : pr.observations) obs.push_back(o);
        j["observations"] = obs;
        out["proprietary"] = j;
        out["support_level"] = "detection+documentation only (no decryption)";
    }
    // Route: ZIP (and zip-based office) -> read-only structure.
    else if (top_fmt == "zip" || top_fmt == "zip_empty") {
        auto zr = engines::inspect_zip(path);
        Json j = Json::object();
        j["valid"] = zr.valid;
        j["entry_count"] = (int64_t)zr.entries.size();
        j["has_encrypted_entries"] = zr.has_encrypted;
        j["zip_bomb_suspected"] = zr.zip_bomb_suspected;
        j["total_uncompressed"] = (int64_t)zr.total_uncompressed;
        Json notes = Json::array(); for (auto& n : zr.notes) notes.push_back(n);
        j["notes"] = notes;
        Json entries = Json::array();
        size_t shown = 0;
        for (const auto& e : zr.entries) {
            if (shown++ >= 50) break;
            Json je = Json::object();
            je["name"] = e.name; je["size"] = (int64_t)e.uncompressed_size;
            je["encrypted"] = e.encrypted; je["method"] = (int)e.method;
            entries.push_back(je);
        }
        j["entries"] = entries;
        out["archive"] = j;
    }
    // Route: open VPN configs -> parse + audit.
    else if (is_open_vpn_ext(ext) || top_fmt=="wireguard" || top_fmt=="ovpn" || top_fmt=="vpn_uri") {
        auto bytes = read_all(path, 8u*1024*1024);
        if (bytes) {
            std::string text((char*)bytes.value.data(), bytes.value.size());
            auto doc = vpn::parse_any(text, ext);
            if (!doc.profiles.empty()) {
                Json j = Json::object();
                j["source_format"] = doc.source_format;
                Json profs = Json::array();
                for (const auto& p : doc.profiles) {
                    auto mp = vpn::mask_profile(p);
                    Json jp = Json::object();
                    jp["protocol"] = vpn::to_string(mp.protocol);
                    jp["tag"] = mp.tag; jp["address"] = mp.address; jp["port"] = mp.port;
                    jp["network"] = mp.network; jp["security"] = mp.security;
                    if (!mp.uuid.empty()) jp["uuid"] = mp.uuid;
                    if (!mp.password.empty()) jp["password"] = mp.password;
                    if (!mp.method.empty()) jp["method"] = mp.method;
                    if (!mp.sni.empty()) jp["sni"] = mp.sni;
                    profs.push_back(jp);
                }
                j["profiles"] = profs;
                // Audit.
                auto a1 = vpn::audit_profiles(doc);
                auto a2 = vpn::audit_text(text);
                Json findings = Json::array();
                int score = std::min(a1.score, a2.score);
                for (auto* a : {&a1, &a2})
                    for (const auto& f : a->findings) {
                        Json jf = Json::object();
                        jf["severity"] = vpn::to_string(f.severity);
                        jf["code"] = f.code; jf["title"] = f.title;
                        jf["recommendation"] = f.recommendation;
                        findings.push_back(jf);
                    }
                Json audit = Json::object();
                audit["score"] = score; audit["findings"] = findings;
                j["security_audit"] = audit;
                out["vpn"] = j;
                out["note_secrets"] = "secrets shown masked; use --reveal on your own files only";
            }
        }
    }

    out["status"] = "ok";
    return out;
}

} // namespace dlu::core
