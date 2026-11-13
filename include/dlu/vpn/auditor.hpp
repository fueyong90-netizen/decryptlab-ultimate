#pragma once
#include "dlu/vpn/model.hpp"
#include <string>
#include <vector>

namespace dlu::vpn {

enum class Severity { Info, Low, Medium, High, Critical };
const char* to_string(Severity s);

struct Finding {
    Severity severity;
    std::string code;     // stable identifier, e.g. "TLS_INSECURE"
    std::string title;
    std::string detail;
    std::string recommendation;
};

struct AuditReport {
    std::vector<Finding> findings;
    int score = 100;      // 0..100, lower = riskier
    void add(Severity s, std::string code, std::string title,
             std::string detail, std::string rec);
};

// Audit normalized profiles for common misconfigurations and exposed secrets.
AuditReport audit_profiles(const VpnDocument& doc);
// Audit raw config text (catches inline private keys, expired PEM certs, etc.).
AuditReport audit_text(const std::string& text);

// Mask a secret for safe display: keep a short prefix, redact the rest.
std::string mask_secret(const std::string& s);
// Return a copy of the profile with all secret fields masked (for reports).
VpnProfile mask_profile(const VpnProfile& p);

} // namespace dlu::vpn
