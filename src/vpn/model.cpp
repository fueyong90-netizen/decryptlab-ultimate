#include "dlu/vpn/model.hpp"
#include <algorithm>

namespace dlu::vpn {

const char* to_string(Protocol p) {
    switch (p) {
        case Protocol::VMess: return "vmess";
        case Protocol::VLESS: return "vless";
        case Protocol::Trojan: return "trojan";
        case Protocol::Shadowsocks: return "shadowsocks";
        case Protocol::ShadowsocksR: return "shadowsocksr";
        case Protocol::OpenVPN: return "openvpn";
        case Protocol::WireGuard: return "wireguard";
        case Protocol::SSH: return "ssh";
        case Protocol::SlowDNS: return "slowdns";
        case Protocol::UDPCustom: return "udp-custom";
        case Protocol::Socks: return "socks";
        case Protocol::Http: return "http";
        default: return "unknown";
    }
}

Protocol protocol_from_string(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    if (t == "vmess") return Protocol::VMess;
    if (t == "vless") return Protocol::VLESS;
    if (t == "trojan") return Protocol::Trojan;
    if (t == "shadowsocks" || t == "ss") return Protocol::Shadowsocks;
    if (t == "shadowsocksr" || t == "ssr") return Protocol::ShadowsocksR;
    if (t == "openvpn" || t == "ovpn") return Protocol::OpenVPN;
    if (t == "wireguard" || t == "wg") return Protocol::WireGuard;
    if (t == "ssh") return Protocol::SSH;
    if (t == "slowdns") return Protocol::SlowDNS;
    if (t == "udp" || t == "udp-custom" || t == "udpcustom") return Protocol::UDPCustom;
    if (t == "socks" || t == "socks5") return Protocol::Socks;
    if (t == "http" || t == "https") return Protocol::Http;
    return Protocol::Unknown;
}

} // namespace dlu::vpn
