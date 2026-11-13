#include "dlu/vpn/auditor.hpp"
#include <algorithm>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <ctime>

namespace dlu::vpn {

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "?";
}

static int penalty(Severity s) {
    switch (s) {
        case Severity::Info: return 0;
        case Severity::Low: return 5;
        case Severity::Medium: return 12;
        case Severity::High: return 25;
        case Severity::Critical: return 40;
    }
    return 0;
}

void AuditReport::add(Severity s, std::string code, std::string title,
                      std::string detail, std::string rec) {
    findings.push_back({s, std::move(code), std::move(title),
                        std::move(detail), std::move(rec)});
    score -= penalty(s);
    if (score < 0) score = 0;
}

std::string mask_secret(const std::string& s) {
    if (s.empty()) return "";
    if (s.size() <= 4) return std::string(s.size(), '*');
    return s.substr(0, 3) + std::string(s.size() - 3 > 8 ? 8 : s.size() - 3, '*');
}

VpnProfile mask_profile(const VpnProfile& p) {
    VpnProfile m = p;
    if (!m.uuid.empty()) m.uuid = mask_secret(m.uuid);
    if (!m.password.empty()) m.password = mask_secret(m.password);
    if (!m.wg_private_key.empty()) m.wg_private_key = mask_secret(m.wg_private_key);
    if (!m.wg_preshared_key.empty()) m.wg_preshared_key = mask_secret(m.wg_preshared_key);
    return m;
}

static const std::vector<std::string> kWeakCiphers = {
    "rc4", "rc4-md5", "des", "3des", "aes-128-cfb", "aes-256-cfb",
    "chacha20", "salsa20", "bf-cfb", "table"
};

AuditReport audit_profiles(const VpnDocument& doc) {
    AuditReport r;
    if (doc.profiles.empty())
        r.add(Severity::Info, "NO_PROFILE", "No profile parsed",
              "No endpoint could be read from this config.", "Verify the input format.");
    for (const auto& p : doc.profiles) {
        if (p.security == "none" &&
            (p.protocol==Protocol::VMess||p.protocol==Protocol::VLESS||p.protocol==Protocol::Trojan))
            r.add(Severity::High, "TLS_NONE", "No transport encryption",
                  "Profile '" + p.tag + "' uses security=none.",
                  "Enable TLS/Reality for this protocol.");
        if (p.allow_insecure)
            r.add(Severity::High, "TLS_INSECURE", "Certificate validation disabled",
                  "allowInsecure is set; TLS will accept any certificate.",
                  "Set allowInsecure=false and use a valid certificate/SNI.");
        if (p.protocol==Protocol::VMess && p.alter_id > 0)
            r.add(Severity::Medium, "VMESS_ALTERID", "Legacy VMess alterId in use",
                  "alterId=" + std::to_string(p.alter_id) + " is deprecated (VMessAEAD).",
                  "Use alterId=0 (AEAD) or migrate to VLESS.");
        std::string m = p.method;
        std::transform(m.begin(), m.end(), m.begin(), ::tolower);
        if (!m.empty() && std::find(kWeakCiphers.begin(), kWeakCiphers.end(), m) != kWeakCiphers.end())
            r.add(Severity::Medium, "WEAK_CIPHER", "Weak/legacy cipher",
                  "Cipher '" + p.method + "' is considered weak.",
                  "Prefer chacha20-ietf-poly1305 or aes-256-gcm.");
        if (!p.wg_private_key.empty())
            r.add(Severity::Info, "WG_PRIVKEY_PRESENT", "WireGuard private key present",
                  "A private key is embedded in this config (expected for WG clients).",
                  "Keep the file permissions at 600 and never share it.");
    }
    return r;
}

AuditReport audit_text(const std::string& text) {
    AuditReport r;
    auto has = [&](const char* n){ return text.find(n) != std::string::npos; };
    if (has("-----BEGIN RSA PRIVATE KEY-----") || has("-----BEGIN PRIVATE KEY-----") ||
        has("-----BEGIN OPENSSH PRIVATE KEY-----") || has("-----BEGIN EC PRIVATE KEY-----"))
        r.add(Severity::High, "INLINE_PRIVKEY", "Private key embedded in config",
              "A PEM/OpenSSH private key block is present in plaintext.",
              "Store keys separately with 0600 permissions; do not distribute this file.");
    if (has("auth-user-pass") && (has("\n") && text.find("auth-user-pass\n")==std::string::npos))
        r.add(Severity::Info, "OVPN_AUTH", "OpenVPN user/pass auth referenced",
              "auth-user-pass directive found.",
              "Ensure credentials are not stored inline in the .ovpn file.");

    // Parse any embedded X.509 certificates and check expiry via OpenSSL.
    size_t pos = 0;
    const std::string begin = "-----BEGIN CERTIFICATE-----";
    const std::string end = "-----END CERTIFICATE-----";
    while ((pos = text.find(begin, pos)) != std::string::npos) {
        size_t e = text.find(end, pos);
        if (e == std::string::npos) break;
        std::string pem = text.substr(pos, e + end.size() - pos);
        pos = e + end.size();
        BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (cert) {
            const ASN1_TIME* na = X509_get0_notAfter(cert);
            int day = 0, sec = 0;
            if (ASN1_TIME_diff(&day, &sec, nullptr, na)) {
                if (day < 0 || (day == 0 && sec < 0))
                    r.add(Severity::High, "CERT_EXPIRED", "Expired certificate",
                          "An embedded certificate is past its notAfter date.",
                          "Replace the certificate; connections may fail or be insecure.");
                else if (day < 30)
                    r.add(Severity::Medium, "CERT_EXPIRING", "Certificate expiring soon",
                          "A certificate expires in " + std::to_string(day) + " day(s).",
                          "Plan certificate rotation.");
            }
            X509_free(cert);
        }
        BIO_free(bio);
    }
    if (r.findings.empty())
        r.add(Severity::Info, "CLEAN", "No obvious issues",
              "No plaintext private keys or expired certs detected in the text.",
              "This is a heuristic check, not a full audit.");
    return r;
}

} // namespace dlu::vpn
