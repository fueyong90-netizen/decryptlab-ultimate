#include "dlu/vpn/generator.hpp"
#include "dlu/vpn/uri.hpp"
#include "dlu/util/json.hpp"
#include "dlu/util/hex.hpp"
#include "dlu/util/base64.hpp"
#include <openssl/rand.h>
#include <cstdio>

namespace dlu::vpn {

using util::Json;

std::string generate_uuid() {
    uint8_t b[16];
    if (RAND_bytes(b, 16) != 1) { for (int i=0;i<16;++i) b[i]=(uint8_t)(i*37+11); }
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant
    char s[37];
    snprintf(s, sizeof(s),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    return std::string(s);
}

std::string generate_password(size_t bytes) {
    std::vector<uint8_t> buf(bytes);
    if (RAND_bytes(buf.data(), (int)bytes) != 1)
        for (size_t i=0;i<bytes;++i) buf[i]=(uint8_t)(i*53+7);
    std::string b64 = util::base64_encode(buf);
    for (auto& c : b64) { if(c=='+')c='-'; else if(c=='/')c='_'; }
    while (!b64.empty() && b64.back()=='=') b64.pop_back();
    return b64;
}

std::string generate_outbound_json(const VpnProfile& p) {
    Json ob = Json::object();
    ob["tag"] = p.tag.empty() ? std::string("proxy") : p.tag;
    ob["protocol"] = to_string(p.protocol);
    Json settings = Json::object();

    if (p.protocol==Protocol::VMess || p.protocol==Protocol::VLESS) {
        Json vnext = Json::array();
        Json srv = Json::object();
        srv["address"] = p.address; srv["port"] = p.port;
        Json users = Json::array();
        Json u = Json::object();
        u["id"] = p.uuid;
        if (p.protocol==Protocol::VMess) { u["alterId"] = p.alter_id;
            u["security"] = p.method.empty()?std::string("auto"):p.method; }
        else { u["encryption"] = "none"; if(!p.flow.empty()) u["flow"]=p.flow; }
        users.push_back(u);
        srv["users"] = users;
        vnext.push_back(srv);
        settings["vnext"] = vnext;
    } else if (p.protocol==Protocol::Trojan || p.protocol==Protocol::Shadowsocks) {
        Json servers = Json::array();
        Json srv = Json::object();
        srv["address"] = p.address; srv["port"] = p.port;
        srv["password"] = p.password;
        if (p.protocol==Protocol::Shadowsocks) srv["method"] = p.method;
        servers.push_back(srv);
        settings["servers"] = servers;
    }
    ob["settings"] = settings;

    Json stream = Json::object();
    stream["network"] = p.network;
    stream["security"] = p.security;
    if (p.security=="tls") {
        Json tls = Json::object();
        tls["serverName"] = p.sni.empty()?p.address:p.sni;
        tls["allowInsecure"] = p.allow_insecure;
        stream["tlsSettings"] = tls;
    }
    if (p.network=="ws") {
        Json ws = Json::object();
        ws["path"] = p.path.empty()?std::string("/"):p.path;
        Json hdr = Json::object();
        hdr["Host"] = p.host.empty()?(p.sni.empty()?p.address:p.sni):p.host;
        ws["headers"] = hdr;
        stream["wsSettings"] = ws;
    } else if (p.network=="grpc") {
        Json g = Json::object(); g["serviceName"] = p.path; stream["grpcSettings"] = g;
    }
    ob["streamSettings"] = stream;
    return ob.dump(2);
}

std::string generate_v2ray_client_json(const VpnProfile& p) {
    Json root = Json::object();
    // log
    Json log = Json::object(); log["loglevel"] = "warning"; root["log"] = log;
    // inbounds: a local socks + http
    Json inbounds = Json::array();
    Json socks = Json::object();
    socks["tag"]="socks"; socks["port"]=10808; socks["listen"]="127.0.0.1"; socks["protocol"]="socks";
    Json ss = Json::object(); ss["udp"]=true; socks["settings"]=ss;
    inbounds.push_back(socks);
    Json http = Json::object();
    http["tag"]="http"; http["port"]=10809; http["listen"]="127.0.0.1"; http["protocol"]="http";
    inbounds.push_back(http);
    root["inbounds"]=inbounds;
    // outbounds
    Json outs = Json::array();
    auto ob = Json::parse(generate_outbound_json(p));
    if (ob) outs.push_back(*ob);
    Json direct = Json::object(); direct["tag"]="direct"; direct["protocol"]="freedom";
    outs.push_back(direct);
    root["outbounds"]=outs;
    return root.dump(2);
}

static GenResult ssh_script(const GenOptions& o) {
    GenResult r; r.language="bash"; r.filename="ssh_tunnel.sh";
    std::string s;
    s += "#!/usr/bin/env bash\n";
    s += "# DecryptLab Ultimate - SSH tunnel helper (SOCKS proxy over SSH)\n";
    s += "# For servers you own or are authorized to use.\n";
    s += "set -euo pipefail\n\n";
    s += "SERVER=\"" + o.address + "\"\nPORT=\"" + std::to_string(o.port?o.port:22) + "\"\n";
    s += "USER=\"" + o.ssh_user + "\"\nLOCAL_SOCKS=\"1080\"\n\n";
    s += "# Dynamic port forward: local SOCKS5 proxy -> remote server\n";
    s += "ssh -N -D \"127.0.0.1:${LOCAL_SOCKS}\" -p \"${PORT}\" \\\n";
    s += "    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\\n";
    s += "    \"${USER}@${SERVER}\"\n\n";
    s += "# Then point your app at socks5://127.0.0.1:1080\n";
    r.content=s;
    r.notes.push_back("Uses key-based auth if your ~/.ssh is configured; never hardcode passwords.");
    return r;
}

static GenResult slowdns_script(const GenOptions& o) {
    GenResult r; r.language="bash"; r.filename="slowdns_client.sh";
    std::string s;
    s += "#!/usr/bin/env bash\n";
    s += "# DecryptLab Ultimate - SlowDNS (dnstt) client launcher template\n";
    s += "# Requires a dnstt-client binary and a nameserver you control.\n";
    s += "set -euo pipefail\n\n";
    s += "NS=\"" + (o.dns_ns.empty()?std::string("ns.example.com"):o.dns_ns) + "\"   # your delegated NS\n";
    s += "PUBKEY=\"REPLACE_WITH_SERVER_PUBLIC_KEY\"\n";
    s += "RESOLVER=\"8.8.8.8:53\"\nLOCAL=\"127.0.0.1:" + std::to_string(o.port?o.port:2222) + "\"\n\n";
    s += "dnstt-client -udp \"${RESOLVER}\" -pubkey \"${PUBKEY}\" \"${NS}\" \"${LOCAL}\"\n\n";
    s += "# Tunnel SSH/other traffic through ${LOCAL} once the tunnel is up.\n";
    r.content=s;
    r.notes.push_back("SlowDNS requires a nameserver delegation you administer; this is a template.");
    return r;
}

static GenResult udp_config(const GenOptions& o) {
    GenResult r; r.language="json"; r.filename="udp_custom.json";
    Json j = Json::object();
    j["listen"] = ":36712";
    j["stream_buffer"] = 33554432;
    j["receive_buffer"] = 83886080;
    Json auth = Json::object(); auth["mode"]="passwords";
    Json pwds = Json::array(); pwds.push_back(o.password.empty()?generate_password():o.password);
    auth["passwords"] = pwds; j["auth"] = auth;
    j["ignore_list"] = Json::array();
    r.content = j.dump(2);
    r.notes.push_back("UDP-custom style server config (for a server you operate). Ports: " + o.udp_ports);
    return r;
}

Result<GenResult> generate(const GenOptions& opt) {
    GenOptions o = opt;
    if (o.uuid.empty()) o.uuid = generate_uuid();
    if (o.password.empty()) o.password = generate_password();

    VpnProfile p;
    p.protocol=o.protocol; p.address=o.address; p.port=o.port; p.uuid=o.uuid;
    p.password=o.password; p.method=o.method; p.network=o.network; p.security=o.security;
    p.sni=o.sni.empty()?o.address:o.sni; p.host=o.host; p.path=o.path; p.tag=o.tag;

    switch (o.protocol) {
        case Protocol::VMess:
        case Protocol::VLESS:
        case Protocol::Trojan:
        case Protocol::Shadowsocks: {
            GenResult r; r.language="json";
            r.filename = std::string(to_string(o.protocol)) + "_client.json";
            r.content = generate_v2ray_client_json(p);
            auto uri = to_uri(p);
            if (uri) r.notes.push_back("share URI: " + uri.value);
            r.notes.push_back("UUID/password generated locally; keep them secret.");
            return Result<GenResult>::good(r);
        }
        case Protocol::WireGuard: {
            GenResult r; r.language="ini"; r.filename="wg0.conf";
            std::string priv = generate_password(32);
            std::string s;
            s += "[Interface]\n";
            s += "PrivateKey = " + priv + "\n";
            s += "Address = 10.66.66.2/32\nDNS = 1.1.1.1\n\n";
            s += "[Peer]\n";
            s += "PublicKey = REPLACE_WITH_SERVER_PUBLIC_KEY\n";
            s += "Endpoint = " + o.address + ":" + std::to_string(o.port?o.port:51820) + "\n";
            s += "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";
            r.content=s;
            r.notes.push_back("Keys here are placeholders generated locally; exchange real public keys with the server.");
            return Result<GenResult>::good(r);
        }
        case Protocol::OpenVPN: {
            GenResult r; r.language="conf"; r.filename="client.ovpn";
            std::string s;
            s += "client\ndev tun\nproto " + (o.network=="tcp"?std::string("tcp"):std::string("udp")) + "\n";
            s += "remote " + o.address + " " + std::to_string(o.port?o.port:1194) + "\n";
            s += "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n";
            s += "remote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n";
            s += "verb 3\n\n";
            s += "# <ca>, <cert>, <key> inline blocks must be added from your PKI.\n";
            r.content=s;
            r.notes.push_back("Add your CA/cert/key inline blocks; this is a client skeleton.");
            return Result<GenResult>::good(r);
        }
        case Protocol::SSH: return Result<GenResult>::good(ssh_script(o));
        case Protocol::SlowDNS: return Result<GenResult>::good(slowdns_script(o));
        case Protocol::UDPCustom: return Result<GenResult>::good(udp_config(o));
        default:
            return Result<GenResult>::fail(std::string("generation not supported for ") + to_string(o.protocol));
    }
}

Result<GenResult> emit(const VpnProfile& p, const std::string& target) {
    GenResult r;
    if (target=="uri") {
        auto u = to_uri(p);
        if (!u) return Result<GenResult>::fail(u.error);
        r.language="uri"; r.filename="profile.uri"; r.content=u.value;
        return Result<GenResult>::good(r);
    }
    if (target=="v2ray" || target=="json" || target=="xray") {
        r.language="json"; r.filename="client.json";
        r.content = generate_v2ray_client_json(p);
        return Result<GenResult>::good(r);
    }
    if (target=="outbound") {
        r.language="json"; r.filename="outbound.json";
        r.content = generate_outbound_json(p);
        return Result<GenResult>::good(r);
    }
    return Result<GenResult>::fail("unknown target format: " + target);
}

} // namespace dlu::vpn
