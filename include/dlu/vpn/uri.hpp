#pragma once
#include "dlu/core/common.hpp"
#include "dlu/vpn/model.hpp"
#include <string>
#include <optional>

namespace dlu::vpn {

// Parse a single share URI (vmess://, vless://, trojan://, ss://, ssr://, socks://)
// into a normalized profile. These are OPEN, documented share formats; parsing
// only decodes what the user already holds in plaintext/Base64.
Result<VpnProfile> parse_uri(const std::string& uri);

// Serialize a profile back to the canonical share URI for its protocol.
Result<std::string> to_uri(const VpnProfile& p);

// Parse a subscription blob (often Base64 of newline-separated URIs).
VpnDocument parse_subscription(const std::string& blob);

} // namespace dlu::vpn
