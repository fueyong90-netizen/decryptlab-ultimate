#include "dlu/net/http_server.hpp"
#include "dlu/core/analyzer.hpp"
#include "dlu/core/common.hpp"
#include "dlu/engines/metadata.hpp"
#include "dlu/vpn/parser.hpp"
#include "dlu/vpn/auditor.hpp"
#include "dlu/vpn/generator.hpp"
#include "dlu/util/json.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <unistd.h>

using namespace dlu;
using util::Json;

static std::string tmp_write(const std::string& data, const std::string& ext) {
    char tmpl[] = "/tmp/dlu_apiXXXXXX";
    int fd = mkstemp(tmpl);
    std::string path = tmpl;
    if (fd >= 0) { ssize_t w = write(fd, data.data(), data.size()); (void)w; close(fd); }
    if (!ext.empty()) {
        std::string p2 = path + "." + ext;
        rename(path.c_str(), p2.c_str());
        return p2;
    }
    return path;
}

int main(int argc, char** argv) {
    std::string host = "0.0.0.0";
    uint16_t port = 8090;
    // Cloud platforms (Render/Railway/Fly/Koyeb) inject $PORT.
    if (const char* p = std::getenv("PORT")) port = (uint16_t)std::atoi(p);
    std::string web_root = "apps/web";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = (uint16_t)std::atoi(argv[++i]);
        else if (a == "--host" && i + 1 < argc) host = argv[++i];
        else if (a == "--web" && i + 1 < argc) web_root = argv[++i];
    }

    net::HttpServer server(host, port);
    server.set_static_root(web_root);

    server.route("GET", "/api/health", [](const net::HttpRequest&) {
        return net::HttpResponse::json("{\"status\":\"ok\"}");
    });

    server.route("GET", "/api/version", [](const net::HttpRequest&) {
        Json j = Json::object();
        j["tool"] = "DecryptLab Ultimate";
        j["version"] = kVersion;
        j["author"] = "JORDAN HACKER";
        Json eng = Json::array();
        for (const char* e : {"scanner","detector","entropy","hashing","archive-zip",
                              "vpn-open","proprietary-inspector","auditor","generator",
                              "metadata","sigdb-sqlite","batch","http-api"})
            eng.push_back(std::string(e));
        j["engines"] = eng;
        return net::HttpResponse::json(j.dump(2));
    });

    // POST raw file bytes -> analysis.
    server.route("POST", "/api/analyze", [](const net::HttpRequest& req) {
        if (req.body.empty()) return net::HttpResponse::json("{\"error\":\"empty body\"}", 400);
        std::string ext = req.query_get("ext");
        std::string path = tmp_write(req.body, ext);
        core::Analyzer an;
        auto j = an.analyze(path, true);
        ::remove(path.c_str());
        return net::HttpResponse::json(j.dump(2));
    });

    // POST raw file bytes -> metadata.
    server.route("POST", "/api/metadata", [](const net::HttpRequest& req) {
        if (req.body.empty()) return net::HttpResponse::json("{\"error\":\"empty body\"}", 400);
        std::string path = tmp_write(req.body, req.query_get("ext"));
        auto j = engines::extract_metadata(path);
        ::remove(path.c_str());
        return net::HttpResponse::json(j.dump(2));
    });

    // POST VPN config text -> parse (masked unless ?reveal=1).
    server.route("POST", "/api/vpn/parse", [](const net::HttpRequest& req) {
        auto doc = vpn::parse_any(req.body, req.query_get("ext"));
        bool reveal = req.query_get("reveal") == "1";
        Json j = Json::object();
        j["source_format"] = doc.source_format;
        Json profs = Json::array();
        for (auto& p : doc.profiles) {
            auto pp = reveal ? p : vpn::mask_profile(p);
            Json jp = Json::object();
            jp["protocol"] = vpn::to_string(pp.protocol);
            jp["tag"] = pp.tag; jp["address"] = pp.address; jp["port"] = pp.port;
            jp["network"] = pp.network; jp["security"] = pp.security;
            if (!pp.uuid.empty()) jp["uuid"] = pp.uuid;
            if (!pp.password.empty()) jp["password"] = pp.password;
            if (!pp.method.empty()) jp["method"] = pp.method;
            if (!pp.sni.empty()) jp["sni"] = pp.sni;
            profs.push_back(jp);
        }
        j["profiles"] = profs;
        return net::HttpResponse::json(j.dump(2));
    });

    // POST VPN config text -> audit.
    server.route("POST", "/api/vpn/audit", [](const net::HttpRequest& req) {
        auto doc = vpn::parse_any(req.body, "");
        auto a1 = vpn::audit_profiles(doc);
        auto a2 = vpn::audit_text(req.body);
        Json j = Json::object();
        j["score"] = std::min(a1.score, a2.score);
        Json fs = Json::array();
        for (auto* a : {&a1, &a2})
            for (auto& f : a->findings) {
                Json jf = Json::object();
                jf["severity"] = vpn::to_string(f.severity);
                jf["code"] = f.code; jf["title"] = f.title;
                jf["recommendation"] = f.recommendation;
                fs.push_back(jf);
            }
        j["findings"] = fs;
        return net::HttpResponse::json(j.dump(2));
    });

    // GET generate a config for YOUR server.
    server.route("GET", "/api/vpn/generate", [](const net::HttpRequest& req) {
        vpn::GenOptions o;
        o.protocol = vpn::protocol_from_string(req.query_get("proto"));
        if (o.protocol == vpn::Protocol::Unknown) o.protocol = vpn::Protocol::VLESS;
        std::string addr = req.query_get("addr"); if (!addr.empty()) o.address = addr;
        std::string port = req.query_get("port"); if (!port.empty()) o.port = std::atoi(port.c_str());
        std::string net = req.query_get("net"); if (!net.empty()) o.network = net;
        std::string sec = req.query_get("security"); if (!sec.empty()) o.security = sec;
        std::string sni = req.query_get("sni"); if (!sni.empty()) o.sni = sni;
        auto r = vpn::generate(o);
        if (!r) return net::HttpResponse::json("{\"error\":\"" + r.error + "\"}", 400);
        Json j = Json::object();
        j["filename"] = r.value.filename;
        j["language"] = r.value.language;
        j["content"] = r.value.content;
        Json notes = Json::array(); for (auto& n : r.value.notes) notes.push_back(n);
        j["notes"] = notes;
        return net::HttpResponse::json(j.dump(2));
    });

    std::printf("DecryptLab Ultimate API + PWA on http://%s:%u  (web root: %s)\n",
                host.c_str(), (unsigned)port, web_root.c_str());
    std::printf("Endpoints: /api/health /api/version /api/analyze /api/metadata "
                "/api/vpn/parse /api/vpn/audit /api/vpn/generate\n");
    int rc = server.run();
    if (rc) std::fprintf(stderr, "server failed to start (code %d); is the port free?\n", rc);
    return rc;
}
