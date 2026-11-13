#pragma once
#include "dlu/vpn/model.hpp"
#include <string>

namespace dlu::vpn {

// Parse open, text-based VPN configuration files into the normalized model.
// These read plaintext the user already possesses; nothing is cracked.
VpnDocument parse_openvpn(const std::string& text);
VpnDocument parse_wireguard(const std::string& text);
VpnDocument parse_v2ray_json(const std::string& text);

// Dispatch by sniffing the content; falls back to subscription/URI parsing.
VpnDocument parse_any(const std::string& text, const std::string& hint_ext = "");

} // namespace dlu::vpn
