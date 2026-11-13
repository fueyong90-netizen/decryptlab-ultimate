# VPN FORMATS — DecryptLab Ultimate

## Open / documented formats (fully handled)

| Format | Parse | Audit | Generate | Convert |
|--------|:----:|:----:|:-------:|:------:|
| `vmess://` (Base64 JSON) | ✅ | ✅ | ✅ | ✅ |
| `vless://` | ✅ | ✅ | ✅ | ✅ |
| `trojan://` | ✅ | ✅ | ✅ | ✅ |
| `ss://` (SIP002 + legacy) | ✅ | ✅ | ✅ | ✅ |
| Subscription (base64 / multi-URI) | ✅ | ✅ | — | — |
| OpenVPN `.ovpn` | ✅ | ✅ | ✅ (skeleton) | — |
| WireGuard `.conf` | ✅ | ✅ | ✅ | — |
| V2Ray / Xray JSON (`outbounds`) | ✅ | ✅ | ✅ | ✅ |
| SSH tunnel | — | — | ✅ (script) | — |
| SlowDNS (dnstt) | — | — | ✅ (template) | — |
| UDP-custom | — | — | ✅ (config) | — |

"Parse" reads only what is already plaintext/Base64 in **your own** file; nothing
is cracked. Generation targets **servers you operate** and creates fresh
UUIDs/keys locally.

## Normalized model (`vpn::VpnProfile`)

Protocol-agnostic fields: `protocol, tag, address, port, uuid, password, method,
alter_id, network, security, sni, host, path, flow, allow_insecure`, plus
WireGuard keys/addresses and an `extra` passthrough map. Parsers fill it;
generators/converters emit from it, so any supported input can round-trip to any
compatible output.

## Transport / security recognized

- Networks: `tcp, ws, grpc, h2, kcp, quic`
- Security: `none, tls, reality, xtls`
- Fields: SNI, Host header, ws/grpc path/serviceName, VLESS `flow`, `allowInsecure`

## Security audit rules (examples)

| Code | Severity | Trigger |
|------|----------|---------|
| `TLS_NONE` | high | security=none on vmess/vless/trojan |
| `TLS_INSECURE` | high | allowInsecure true |
| `INLINE_PRIVKEY` | high | PEM/OpenSSH private key in the file |
| `CERT_EXPIRED` / `CERT_EXPIRING` | high / medium | X.509 notAfter passed / < 30 days |
| `VMESS_ALTERID` | medium | legacy alterId > 0 |
| `WEAK_CIPHER` | medium | rc4/des/3des/cfb/… |

## Proprietary formats — documentation only

| Ext | Origin app | What DecryptLab does |
|-----|-----------|----------------------|
| `.ehi` | HTTP Injector | Detect, entropy, structure, **state the limitation** |
| `.hc` | HTTP Custom | same |
| `.npvs` | NapsternetV | same |
| `.hat` | HA Tunnel Plus | same |

For these, DecryptLab reports whether the payload looks **encrypted**,
**compressed** or **Base64-encoded**, surfaces non-secret plaintext markers, and
explains that decoding requires the author's algorithm and key. It never breaks
the protection or extracts secrets — see SECURITY.md.
