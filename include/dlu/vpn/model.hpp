#pragma once
#include <string>
#include <vector>
#include <map>

namespace dlu::vpn {

enum class Protocol {
    Unknown, VMess, VLESS, Trojan, Shadowsocks, ShadowsocksR,
    OpenVPN, WireGuard, SSH, SlowDNS, UDPCustom, Socks, Http
};

const char* to_string(Protocol p);
Protocol protocol_from_string(const std::string& s);

// A normalized, protocol-agnostic VPN endpoint profile. Open formats are parsed
// into this model; generators emit from it. Fields left empty when N/A.
struct VpnProfile {
    Protocol protocol = Protocol::Unknown;
    std::string tag;            // display name / remark
    std::string address;        // host or IP
    int port = 0;

    // Identity / secret material (as present in the user's own config).
    std::string uuid;           // vmess/vless
    std::string password;       // trojan/ss/ssr
    std::string method;         // ss cipher, vmess security
    int alter_id = 0;           // vmess legacy

    // Transport.
    std::string network = "tcp"; // tcp, ws, grpc, h2, kcp, quic
    std::string security = "none"; // none, tls, reality, xtls
    std::string sni;            // server name indication
    std::string host;           // ws/h2 Host header
    std::string path;           // ws/h2 path or grpc serviceName
    std::string flow;           // vless xtls flow
    bool allow_insecure = false;

    // WireGuard-specific.
    std::string wg_private_key;
    std::string wg_public_key;
    std::string wg_preshared_key;
    std::vector<std::string> wg_addresses;
    std::vector<std::string> wg_allowed_ips;
    std::vector<std::string> wg_dns;
    std::string wg_endpoint;

    // Raw passthrough fields for round-tripping unknown keys.
    std::map<std::string, std::string> extra;
};

// A parsed config may contain multiple profiles (subscription, V2Ray outbounds).
struct VpnDocument {
    std::string source_format;  // "vmess-uri", "ovpn", "wireguard", "v2ray-json"...
    std::vector<VpnProfile> profiles;
    std::vector<std::string> warnings;
    std::vector<std::string> notes;
};

} // namespace dlu::vpn
