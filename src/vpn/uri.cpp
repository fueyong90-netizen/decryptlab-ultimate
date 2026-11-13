#include "dlu/vpn/uri.hpp"
#include "dlu/util/base64.hpp"
#include "dlu/util/json.hpp"
#include <sstream>
#include <algorithm>
#include <cstdio>

namespace dlu::vpn {

using util::Json;

static std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = s.substr(i + 1, 2);
            out.push_back((char)std::stoi(hex, nullptr, 16));
            i += 2;
        } else if (s[i] == '+') out.push_back(' ');
        else out.push_back(s[i]);
    }
    return out;
}

static std::string url_encode(const std::string& s) {
    static const char* h = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (isalnum(c) || c=='-'||c=='_'||c=='.'||c=='~') out.push_back(c);
        else { out.push_back('%'); out.push_back(h[c>>4]); out.push_back(h[c&0xF]); }
    }
    return out;
}

static std::map<std::string,std::string> parse_query(const std::string& q) {
    std::map<std::string,std::string> m;
    std::stringstream ss(q);
    std::string kv;
    while (std::getline(ss, kv, '&')) {
        auto eq = kv.find('=');
        if (eq == std::string::npos) m[url_decode(kv)] = "";
        else m[url_decode(kv.substr(0,eq))] = url_decode(kv.substr(eq+1));
    }
    return m;
}

// Split "userinfo@host:port?query#frag" (scheme already stripped).
struct UriParts {
    std::string userinfo, host; int port = 0;
    std::map<std::string,std::string> query; std::string frag;
};
static UriParts split_authority(const std::string& rest) {
    UriParts u;
    std::string s = rest;
    auto hash = s.find('#');
    if (hash != std::string::npos) { u.frag = url_decode(s.substr(hash+1)); s = s.substr(0,hash); }
    auto qm = s.find('?');
    if (qm != std::string::npos) { u.query = parse_query(s.substr(qm+1)); s = s.substr(0,qm); }
    auto at = s.rfind('@');
    if (at != std::string::npos) { u.userinfo = s.substr(0,at); s = s.substr(at+1); }
    // host:port (host may be bracketed IPv6)
    if (!s.empty() && s[0]=='[') {
        auto rb = s.find(']');
        u.host = s.substr(1, rb-1);
        auto colon = s.find(':', rb);
        if (colon != std::string::npos) u.port = std::atoi(s.substr(colon+1).c_str());
    } else {
        auto colon = s.rfind(':');
        if (colon != std::string::npos) { u.host = s.substr(0,colon); u.port = std::atoi(s.substr(colon+1).c_str()); }
        else u.host = s;
    }
    return u;
}

static void apply_transport(VpnProfile& p, const std::map<std::string,std::string>& q) {
    auto get = [&](const char* k)->std::string{ auto it=q.find(k); return it==q.end()?"":it->second; };
    if (!get("type").empty()) p.network = get("type");
    if (!get("security").empty()) p.security = get("security");
    if (!get("sni").empty()) p.sni = get("sni");
    if (!get("host").empty()) p.host = get("host");
    if (!get("path").empty()) p.path = get("path");
    if (!get("flow").empty()) p.flow = get("flow");
    if (!get("serviceName").empty()) p.path = get("serviceName");
    if (get("allowInsecure")=="1"||get("allowInsecure")=="true") p.allow_insecure = true;
}

Result<VpnProfile> parse_uri(const std::string& uri) {
    auto scheme_end = uri.find("://");
    if (scheme_end == std::string::npos)
        return Result<VpnProfile>::fail("no scheme in URI");
    std::string scheme = uri.substr(0, scheme_end);
    std::string rest = uri.substr(scheme_end + 3);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), ::tolower);

    VpnProfile p;
    if (scheme == "vmess") {
        auto dec = util::base64_decode(rest);
        if (!dec) dec = util::base64url_decode(rest);
        if (!dec) return Result<VpnProfile>::fail("vmess: base64 decode failed");
        std::string js((char*)dec->data(), dec->size());
        auto jv = Json::parse(js);
        if (!jv) return Result<VpnProfile>::fail("vmess: inner JSON parse failed");
        const Json& j = *jv;
        p.protocol = Protocol::VMess;
        auto gs = [&](const char* k)->std::string{ auto f=j.find(k); return f?f->as_string():""; };
        auto gi = [&](const char* k)->int{ auto f=j.find(k); if(!f)return 0; if(f->is_string()){return std::atoi(f->as_string().c_str());} return (int)f->as_int(); };
        p.tag = gs("ps");
        p.address = gs("add");
        p.port = gi("port");
        p.uuid = gs("id");
        p.alter_id = gi("aid");
        p.network = gs("net").empty()?"tcp":gs("net");
        p.host = gs("host");
        p.path = gs("path");
        p.security = gs("tls").empty()?"none":gs("tls");
        p.sni = gs("sni");
        p.method = gs("scy").empty()?"auto":gs("scy");
        return Result<VpnProfile>::good(p);
    }
    if (scheme == "vless" || scheme == "trojan") {
        auto u = split_authority(rest);
        p.protocol = scheme=="vless"?Protocol::VLESS:Protocol::Trojan;
        if (scheme=="vless") p.uuid = url_decode(u.userinfo);
        else p.password = url_decode(u.userinfo);
        p.address = u.host; p.port = u.port; p.tag = u.frag;
        apply_transport(p, u.query);
        if (p.security=="none" && scheme=="trojan") p.security = "tls";
        return Result<VpnProfile>::good(p);
    }
    if (scheme == "ss") {
        // SIP002: ss://BASE64(method:password)@host:port#tag
        //  legacy: ss://BASE64(method:password@host:port)#tag
        p.protocol = Protocol::Shadowsocks;
        auto hash = rest.find('#');
        std::string frag = hash==std::string::npos?"":url_decode(rest.substr(hash+1));
        std::string body = hash==std::string::npos?rest:rest.substr(0,hash);
        p.tag = frag;
        auto at = body.find('@');
        if (at != std::string::npos) {
            auto creds = util::base64_decode(body.substr(0,at));
            if (!creds) creds = util::base64url_decode(body.substr(0,at));
            std::string mc = creds ? std::string((char*)creds->data(),creds->size())
                                   : url_decode(body.substr(0,at));
            auto colon = mc.find(':');
            if (colon!=std::string::npos){ p.method=mc.substr(0,colon); p.password=mc.substr(colon+1); }
            auto hp = split_authority(body.substr(at+1));
            p.address = hp.host; p.port = hp.port;
        } else {
            auto dec = util::base64_decode(body);
            if (!dec) dec = util::base64url_decode(body);
            if (!dec) return Result<VpnProfile>::fail("ss: base64 decode failed");
            std::string all((char*)dec->data(),dec->size());
            auto at2 = all.find('@');
            if (at2==std::string::npos) return Result<VpnProfile>::fail("ss: malformed");
            std::string mc = all.substr(0,at2);
            auto colon = mc.find(':');
            if (colon!=std::string::npos){ p.method=mc.substr(0,colon); p.password=mc.substr(colon+1); }
            auto hp = split_authority(all.substr(at2+1));
            p.address = hp.host; p.port = hp.port;
        }
        return Result<VpnProfile>::good(p);
    }
    if (scheme == "socks" || scheme == "socks5") {
        auto u = split_authority(rest);
        p.protocol = Protocol::Socks; p.address=u.host; p.port=u.port; p.tag=u.frag;
        if (!u.userinfo.empty()){ auto c=u.userinfo.find(':'); if(c!=std::string::npos){p.method=u.userinfo.substr(0,c);p.password=u.userinfo.substr(c+1);} }
        return Result<VpnProfile>::good(p);
    }
    return Result<VpnProfile>::fail("unsupported URI scheme: " + scheme);
}

Result<std::string> to_uri(const VpnProfile& p) {
    switch (p.protocol) {
        case Protocol::VMess: {
            Json j = Json::object();
            j["v"] = "2"; j["ps"] = p.tag; j["add"] = p.address;
            j["port"] = std::to_string(p.port); j["id"] = p.uuid;
            j["aid"] = std::to_string(p.alter_id); j["scy"] = p.method.empty()?"auto":p.method;
            j["net"] = p.network; j["type"] = "none"; j["host"] = p.host;
            j["path"] = p.path; j["tls"] = (p.security=="tls")?"tls":""; j["sni"] = p.sni;
            return Result<std::string>::good("vmess://" + util::base64_encode(j.dump(0)));
        }
        case Protocol::VLESS:
        case Protocol::Trojan: {
            std::string s = (p.protocol==Protocol::VLESS?"vless://":"trojan://");
            s += url_encode(p.protocol==Protocol::VLESS?p.uuid:p.password);
            s += "@" + p.address + ":" + std::to_string(p.port);
            std::string q = "type=" + p.network + "&security=" + p.security;
            if (!p.sni.empty()) q += "&sni=" + url_encode(p.sni);
            if (!p.host.empty()) q += "&host=" + url_encode(p.host);
            if (!p.path.empty()) q += "&path=" + url_encode(p.path);
            if (!p.flow.empty()) q += "&flow=" + url_encode(p.flow);
            s += "?" + q;
            if (!p.tag.empty()) s += "#" + url_encode(p.tag);
            return Result<std::string>::good(s);
        }
        case Protocol::Shadowsocks: {
            std::string creds = p.method + ":" + p.password;
            std::string s = "ss://" + util::base64_encode(creds) +
                            "@" + p.address + ":" + std::to_string(p.port);
            if (!p.tag.empty()) s += "#" + url_encode(p.tag);
            return Result<std::string>::good(s);
        }
        default:
            return Result<std::string>::fail(
                std::string("no URI form for protocol ") + to_string(p.protocol));
    }
}

VpnDocument parse_subscription(const std::string& blob) {
    VpnDocument doc;
    doc.source_format = "subscription";
    std::string text = blob;
    // A subscription is often a single Base64 blob of the whole list.
    std::string trimmed = text;
    trimmed.erase(std::remove_if(trimmed.begin(), trimmed.end(),
                  [](char c){return c=='\n'||c=='\r'||c==' ';}), trimmed.end());
    if (util::looks_like_base64(trimmed, 16) && trimmed.find("://")==std::string::npos) {
        auto dec = util::base64_decode(trimmed);
        if (!dec) dec = util::base64url_decode(trimmed);
        if (dec) text = std::string((char*)dec->data(), dec->size());
    }
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back()=='\r'||line.back()==' ')) line.pop_back();
        if (line.empty() || line.find("://")==std::string::npos) continue;
        auto r = parse_uri(line);
        if (r) doc.profiles.push_back(r.value);
        else doc.warnings.push_back("could not parse line: " + r.error);
    }
    doc.notes.push_back(std::to_string(doc.profiles.size()) + " profile(s) parsed");
    return doc;
}

} // namespace dlu::vpn
