#include "dlu/vpn/parser.hpp"
#include "dlu/vpn/uri.hpp"
#include "dlu/util/json.hpp"
#include <sstream>
#include <algorithm>

namespace dlu::vpn {

using util::Json;

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

VpnDocument parse_openvpn(const std::string& text) {
    VpnDocument doc; doc.source_format = "ovpn";
    VpnProfile p; p.protocol = Protocol::OpenVPN;
    std::stringstream ss(text);
    std::string line;
    bool in_inline = false; std::string inline_tag;
    int remotes = 0;
    while (std::getline(ss, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0]=='#' || t[0]==';') continue;
        if (!t.empty() && t[0]=='<') {
            if (t.rfind("</",0)==0) { in_inline=false; inline_tag.clear(); }
            else { in_inline=true; inline_tag=t.substr(1, t.size()-2);
                   doc.notes.push_back("inline block: <" + inline_tag + ">"); }
            continue;
        }
        if (in_inline) continue;
        std::istringstream ls(t);
        std::string key; ls >> key;
        if (key == "remote") {
            std::string host; int port=0; ls >> host >> port;
            if (remotes==0){ p.address=host; p.port=port; }
            p.extra["remote_"+std::to_string(remotes)] = host + ":" + std::to_string(port);
            ++remotes;
        } else if (key=="proto") { std::string v; ls>>v; p.network=v; }
        else if (key=="cipher") { std::string v; ls>>v; p.method=v; }
        else if (key=="auth") { std::string v; ls>>v; p.extra["auth"]=v; }
        else if (key=="dev") { std::string v; ls>>v; p.extra["dev"]=v; }
        else if (key=="tls-version-min"){ std::string v; ls>>v; p.extra["tls_min"]=v; }
        else if (key=="auth-user-pass"){ p.extra["auth_user_pass"]="required"; }
    }
    if (remotes>1) p.tag = std::to_string(remotes) + " remotes";
    doc.profiles.push_back(p);
    return doc;
}

VpnDocument parse_wireguard(const std::string& text) {
    VpnDocument doc; doc.source_format = "wireguard";
    VpnProfile p; p.protocol = Protocol::WireGuard;
    std::stringstream ss(text);
    std::string line, section;
    auto split_csv = [](const std::string& v){
        std::vector<std::string> out; std::stringstream s(v); std::string item;
        while (std::getline(s,item,',')) { item=trim(item); if(!item.empty()) out.push_back(item); }
        return out;
    };
    while (std::getline(ss, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0]=='#') continue;
        if (t[0]=='[') { section=t; continue; }
        auto eq = t.find('=');
        if (eq==std::string::npos) continue;
        std::string k = trim(t.substr(0,eq)), v = trim(t.substr(eq+1));
        std::string kl=k; std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
        if (kl=="privatekey") p.wg_private_key=v;
        else if (kl=="publickey") p.wg_public_key=v;
        else if (kl=="presharedkey") p.wg_preshared_key=v;
        else if (kl=="address") p.wg_addresses=split_csv(v);
        else if (kl=="dns") p.wg_dns=split_csv(v);
        else if (kl=="allowedips") p.wg_allowed_ips=split_csv(v);
        else if (kl=="endpoint") { p.wg_endpoint=v; auto c=v.rfind(':');
            if(c!=std::string::npos){p.address=v.substr(0,c);p.port=std::atoi(v.substr(c+1).c_str());} }
        else p.extra[k]=v;
    }
    doc.profiles.push_back(p);
    return doc;
}

VpnDocument parse_v2ray_json(const std::string& text) {
    VpnDocument doc; doc.source_format = "v2ray-json";
    auto jv = Json::parse(text);
    if (!jv) { doc.warnings.push_back("JSON parse failed"); return doc; }
    const Json& j = *jv;
    const Json* outs = j.find("outbounds");
    if (!outs || !outs->is_array()) {
        doc.warnings.push_back("no 'outbounds' array; not a V2Ray/Xray client config");
        return doc;
    }
    for (const auto& ob : outs->items()) {
        const Json* proto = ob.find("protocol");
        if (!proto) continue;
        std::string pr = proto->as_string();
        VpnProfile p; p.protocol = protocol_from_string(pr);
        const Json* tag = ob.find("tag"); if (tag) p.tag = tag->as_string();
        const Json* settings = ob.find("settings");
        if (settings) {
            const Json* vnext = settings->find("vnext");
            if (vnext && vnext->is_array() && !vnext->items().empty()) {
                const Json& v0 = vnext->items()[0];
                if (auto a=v0.find("address")) p.address=a->as_string();
                if (auto pt=v0.find("port")) p.port=(int)pt->as_int();
                const Json* users = v0.find("users");
                if (users && users->is_array() && !users->items().empty()) {
                    const Json& u0 = users->items()[0];
                    if (auto id=u0.find("id")) p.uuid=id->as_string();
                    if (auto ai=u0.find("alterId")) p.alter_id=(int)ai->as_int();
                    if (auto fl=u0.find("flow")) p.flow=fl->as_string();
                }
            }
            const Json* servers = settings->find("servers");
            if (servers && servers->is_array() && !servers->items().empty()) {
                const Json& s0 = servers->items()[0];
                if (auto a=s0.find("address")) p.address=a->as_string();
                if (auto pt=s0.find("port")) p.port=(int)pt->as_int();
                if (auto pw=s0.find("password")) p.password=pw->as_string();
                if (auto mt=s0.find("method")) p.method=mt->as_string();
            }
        }
        const Json* stream = ob.find("streamSettings");
        if (stream) {
            if (auto n=stream->find("network")) p.network=n->as_string();
            if (auto s=stream->find("security")) p.security=s->as_string();
            const Json* ws = stream->find("wsSettings");
            if (ws) { if(auto pa=ws->find("path"))p.path=pa->as_string();
                const Json* hdr=ws->find("headers"); if(hdr){if(auto h=hdr->find("Host"))p.host=h->as_string();} }
            const Json* tls = stream->find("tlsSettings");
            if (tls && tls->find("serverName")) p.sni=tls->find("serverName")->as_string();
        }
        if (p.protocol != Protocol::Unknown) doc.profiles.push_back(p);
    }
    doc.notes.push_back(std::to_string(doc.profiles.size()) + " outbound(s) parsed");
    return doc;
}

VpnDocument parse_any(const std::string& text, const std::string& hint_ext) {
    std::string t = trim(text);
    if (t.find("[Interface]")!=std::string::npos) return parse_wireguard(text);
    if (!t.empty() && (t[0]=='{'||t[0]=='[') && t.find("outbounds")!=std::string::npos)
        return parse_v2ray_json(text);
    if (t.rfind("vmess://",0)==0||t.rfind("vless://",0)==0||t.rfind("trojan://",0)==0||
        t.rfind("ss://",0)==0||t.rfind("ssr://",0)==0) {
        VpnDocument d; d.source_format="uri";
        auto r = parse_uri(t);
        if (r) d.profiles.push_back(r.value); else d.warnings.push_back(r.error);
        return d;
    }
    if (t.find("remote ")!=std::string::npos || t.find("client")!=std::string::npos ||
        hint_ext=="ovpn") return parse_openvpn(text);
    // Try subscription (multi-URI / base64 list).
    auto sub = parse_subscription(text);
    if (!sub.profiles.empty()) return sub;
    VpnDocument d; d.source_format="unknown";
    d.warnings.push_back("could not identify an open VPN config format");
    return d;
}

} // namespace dlu::vpn
