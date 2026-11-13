#pragma once
#include "dlu/core/common.hpp"
#include "dlu/vpn/model.hpp"
#include <string>

namespace dlu::vpn {

// Options for generating a config for a server the operator controls.
struct GenOptions {
    Protocol protocol = Protocol::VLESS;
    std::string address = "example.com";
    int port = 443;
    std::string uuid;            // auto-generated if empty (vmess/vless)
    std::string password;        // auto-generated if empty (trojan/ss)
    std::string method = "chacha20-ietf-poly1305"; // ss cipher / vmess security
    std::string network = "ws";
    std::string security = "tls";
    std::string sni;
    std::string host;
    std::string path = "/dlu";
    std::string tag = "dlu-generated";
    // SSH / SlowDNS / UDP extras.
    std::string ssh_user = "user";
    std::string dns_ns;          // SlowDNS nameserver
    std::string udp_ports = "1-65535";
};

struct GenResult {
    std::string filename;        // suggested output filename
    std::string content;         // config text / JSON / script
    std::string language;        // "json", "ini", "conf", "bash", "uri"
    std::vector<std::string> notes;
};

// Generate a random RFC-4122 v4 UUID (OpenSSL RAND). Used for vmess/vless ids.
std::string generate_uuid();
// Generate a random URL-safe password of n bytes (base64, no padding).
std::string generate_password(size_t bytes = 16);

// Build a V2Ray/Xray CLIENT config (JSON) with a single outbound from a profile.
std::string generate_v2ray_client_json(const VpnProfile& p);
// Build a single outbound object (for embedding) as JSON text.
std::string generate_outbound_json(const VpnProfile& p);

// Top-level: produce a config/script for the requested protocol.
// Server-side generation for infrastructure the operator runs.
Result<GenResult> generate(const GenOptions& opt);

// Convert a parsed profile to the requested target format (round-trip helper).
Result<GenResult> emit(const VpnProfile& p, const std::string& target);

} // namespace dlu::vpn
