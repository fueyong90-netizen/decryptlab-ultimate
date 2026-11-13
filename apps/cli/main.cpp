#include "dlu/core/common.hpp"
#include "dlu/core/branding.hpp"
#include "dlu/core/analyzer.hpp"
#include "dlu/core/scanner.hpp"
#include "dlu/core/batch.hpp"
#include "dlu/core/sigdb.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/engines/metadata.hpp"
#include "dlu/vpn/parser.hpp"
#include "dlu/vpn/uri.hpp"
#include "dlu/vpn/generator.hpp"
#include "dlu/vpn/auditor.hpp"
#include "dlu/util/json.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/utsname.h>

using namespace dlu;
using util::Json;

static bool g_color = true;

static std::string get_arch() { struct utsname u{}; return uname(&u)==0?u.machine:"unknown"; }
static std::string get_os() { struct utsname u{}; return uname(&u)==0?u.sysname:"Linux"; }

// Simple flag parser.
struct Args {
    std::vector<std::string> pos;
    std::map<std::string,std::string> opt;
    bool has(const std::string& k) const { return opt.count(k); }
    std::string get(const std::string& k, const std::string& d="") const {
        auto it = opt.find(k); return it==opt.end()?d:it->second;
    }
};
static Args parse_args(int argc, char** argv, int start) {
    Args a;
    for (int i=start;i<argc;++i) {
        std::string s = argv[i];
        if (s.rfind("--",0)==0) {
            std::string key = s.substr(2);
            if (i+1<argc && std::string(argv[i+1]).rfind("--",0)!=0 &&
                (key=="to"||key=="proto"||key=="addr"||key=="port"||key=="uuid"||
                 key=="password"||key=="sni"||key=="host"||key=="path"||key=="net"||
                 key=="security"||key=="method"||key=="tag"||key=="out"||key=="user"||key=="ns"||
                 key=="checkpoint")) {
                a.opt[key]=argv[++i];
            } else a.opt[key]="1";
        } else if (s.rfind("-o",0)==0 && s.size()==2 && i+1<argc) {
            a.opt["out"]=argv[++i];
        } else a.pos.push_back(s);
    }
    return a;
}

static void print_usage() {
    std::cout << brand::logo_compact(g_color);
    std::cout <<
"\nUsage: decryptlab <command> [options]\n\n"
"Commands:\n"
"  scan <path>                 Inventory a file or directory (hash + format)\n"
"  analyze <file>              Full analysis (detect, entropy, route to engine)\n"
"  inspect <file>              Alias of analyze\n"
"  report <file>               Human-readable analysis report\n"
"  metadata <file>             Filesystem + container metadata (JSON)\n"
"  batch <dir> [--out f]       Analyze a folder, NDJSON output, resumable\n"
"  sigdb <db> [--seed]         Manage the SQLite signature database\n"
"  vpn parse <file>            Parse an OPEN vpn config / URI / subscription\n"
"  vpn audit <file>            Security audit of a vpn config (secrets masked)\n"
"  vpn convert <file> --to X   Convert profile to: uri | v2ray | json | outbound\n"
"  vpn generate --proto P ...  Generate a config/script for YOUR server\n"
"  version                     Show version and engine status\n"
"  menu                        Interactive menu\n\n"
"Global options:\n"
"  --json        Machine-readable JSON output\n"
"  --no-color    Disable ANSI colors\n"
"  --no-hash     Skip hashing (scan/analyze)\n"
"  --reveal      Show secrets in clear (use only on files you own)\n"
"  -o <file>     Write generated output to a file\n\n"
"generate options: --addr --port --uuid --password --sni --host --path\n"
"                  --net ws|grpc|tcp --security tls|none --method <cipher>\n"
"                  --tag --user (ssh) --ns (slowdns)\n\n"
"Note: proprietary formats (.ehi/.hc/.npvs/.hat) are DETECTED and DOCUMENTED\n"
"only. DecryptLab does not break author-applied encryption or recover secrets\n"
"from files you do not own.\n";
}

static int cmd_version() {
    std::cout << brand::banner(g_color, kVersion, get_arch(), get_os());
    std::cout << "Engines: scanner, detector, entropy, archive(zip), vpn(open), "
                 "proprietary-inspector, auditor, generator\n";
    return 0;
}

static int cmd_scan(const Args& a) {
    if (a.pos.empty()) { std::cerr << "scan: missing path\n"; return 2; }
    core::Scanner sc(!a.has("no-recursive"), !a.has("no-hash"));
    auto res = sc.scan(a.pos[0]);
    if (a.has("json")) {
        Json j = Json::object();
        j["total_bytes"] = (int64_t)res.total_bytes;
        j["errors"] = (int64_t)res.errors;
        Json items = Json::array();
        for (auto& it : res.items) {
            Json ji = Json::object();
            ji["path"]=it.path; ji["size"]=(int64_t)it.size; ji["sha256"]=it.sha256;
            ji["format"]=it.top_format; ji["category"]=it.category;
            ji["extension_mismatch"]=it.extension_mismatch;
            items.push_back(ji);
        }
        j["items"]=items;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << brand::logo_compact(g_color);
        std::cout << "\nScanned " << res.items.size() << " file(s), "
                  << res.total_bytes << " bytes, " << res.errors << " error(s)\n\n";
        for (auto& it : res.items) {
            std::cout << "  " << it.top_format << "  [" << it.category << "]  "
                      << it.size << "B  " << core::file_name(it.path);
            if (it.extension_mismatch) std::cout << "  <!> extension mismatch";
            std::cout << "\n";
            if (!it.sha256.empty()) std::cout << "      sha256: " << it.sha256 << "\n";
        }
    }
    return 0;
}

static int cmd_analyze(const Args& a) {
    if (a.pos.empty()) { std::cerr << "analyze: missing file\n"; return 2; }
    core::Analyzer an;
    auto j = an.analyze(a.pos[0], !a.has("no-hash"));
    std::cout << j.dump(2) << "\n";
    return 0;
}

static int cmd_report(const Args& a) {
    if (a.pos.empty()) { std::cerr << "report: missing file\n"; return 2; }
    core::Analyzer an;
    auto j = an.analyze(a.pos[0], true);
    std::cout << brand::logo_compact(g_color) << "\n";
    auto gs = [&](const char* k)->std::string{ auto f=j.find(k); return f?f->as_string():""; };
    std::cout << "File        : " << gs("file") << "\n";
    auto sz = j.find("size"); std::cout << "Size        : " << (sz?sz->as_int():0) << " bytes\n";
    std::cout << "Extension   : ." << gs("declared_extension") << "\n";
    if (auto h = j.find("hashes")) if (auto s=h->find("sha256")) std::cout << "SHA-256     : " << s->as_string() << "\n";
    if (auto e = j.find("entropy")) std::cout << "Entropy     : " << e->as_double(0) << " bits/byte\n";
    if (auto d = j.find("detection")) {
        auto hyps = d->find("hypotheses");
        if (hyps && hyps->is_array() && !hyps->items().empty()) {
            const auto& top = hyps->items().front();
            std::cout << "Best guess  : " << (top.find("label")?top.find("label")->as_string():"?")
                      << " (" << (top.find("confidence")?top.find("confidence")->as_int():0) << "%)\n";
        }
        if (d->find("extension_mismatch") && d->find("extension_mismatch")->as_bool())
            std::cout << "  <!> declared extension disagrees with content\n";
    }
    if (auto p = j.find("proprietary")) {
        std::cout << "\n[Proprietary format]\n";
        std::cout << "  guess      : " << (p->find("format_guess")?p->find("format_guess")->as_string():"") << "\n";
        std::cout << "  origin app : " << (p->find("origin_app")?p->find("origin_app")->as_string():"") << "\n";
        std::cout << "  state      : " << (p->find("protection_state")?p->find("protection_state")->as_string():"") << "\n";
        std::cout << "  limitation : " << (p->find("limitation")?p->find("limitation")->as_string():"") << "\n";
    }
    if (auto ar = j.find("archive")) {
        std::cout << "\n[Archive / ZIP]\n";
        std::cout << "  entries    : " << (ar->find("entry_count")?ar->find("entry_count")->as_int():0) << "\n";
        std::cout << "  encrypted  : " << ((ar->find("has_encrypted_entries") && ar->find("has_encrypted_entries")->as_bool())?"yes":"no") << "\n";
        std::cout << "  zip-bomb?  : " << ((ar->find("zip_bomb_suspected") && ar->find("zip_bomb_suspected")->as_bool())?"SUSPECTED":"no") << "\n";
    }
    if (auto v = j.find("vpn")) {
        std::cout << "\n[VPN config]\n";
        std::cout << "  format     : " << (v->find("source_format")?v->find("source_format")->as_string():"") << "\n";
        if (auto pr = v->find("profiles")) std::cout << "  profiles   : " << pr->items().size() << "\n";
        if (auto au = v->find("security_audit")) {
            std::cout << "  audit score: " << (au->find("score")?au->find("score")->as_int():0) << "/100\n";
            if (auto f = au->find("findings"))
                for (auto& fi : f->items())
                    std::cout << "    - [" << (fi.find("severity")?fi.find("severity")->as_string():"") << "] "
                              << (fi.find("title")?fi.find("title")->as_string():"") << "\n";
        }
        std::cout << "  (secrets masked)\n";
    }
    return 0;
}

static int write_out(const Args& a, const vpn::GenResult& r) {
    if (a.has("out")) {
        std::ofstream f(a.get("out"), std::ios::binary);
        f << r.content;
        std::cout << "Wrote " << r.content.size() << " bytes to " << a.get("out") << "\n";
    } else {
        std::cout << r.content << "\n";
    }
    for (auto& n : r.notes) std::cout << "# " << n << "\n";
    return 0;
}

static int cmd_vpn(const Args& a, const std::string& sub) {
    if (sub == "generate") {
        vpn::GenOptions o;
        o.protocol = vpn::protocol_from_string(a.get("proto","vless"));
        if (o.protocol==vpn::Protocol::Unknown) { std::cerr << "unknown --proto\n"; return 2; }
        o.address = a.get("addr","example.com");
        if (a.has("port")) o.port = std::atoi(a.get("port").c_str());
        else o.port = 443;
        if (a.has("uuid")) o.uuid=a.get("uuid");
        if (a.has("password")) o.password=a.get("password");
        if (a.has("method")) o.method=a.get("method");
        if (a.has("net")) o.network=a.get("net");
        if (a.has("security")) o.security=a.get("security");
        if (a.has("sni")) o.sni=a.get("sni");
        if (a.has("host")) o.host=a.get("host");
        if (a.has("path")) o.path=a.get("path");
        if (a.has("tag")) o.tag=a.get("tag");
        if (a.has("user")) o.ssh_user=a.get("user");
        if (a.has("ns")) o.dns_ns=a.get("ns");
        auto r = vpn::generate(o);
        if (!r) { std::cerr << "generate: " << r.error << "\n"; return 1; }
        return write_out(a, r.value);
    }
    if (a.pos.empty()) { std::cerr << "vpn " << sub << ": missing file\n"; return 2; }
    auto bytes = core::read_all(a.pos[0], 8u*1024*1024);
    if (!bytes) { std::cerr << bytes.error << "\n"; return 1; }
    std::string text((char*)bytes.value.data(), bytes.value.size());
    std::string ext = core::file_extension(a.pos[0]);

    if (sub == "parse") {
        auto doc = vpn::parse_any(text, ext);
        Json j = Json::object();
        j["source_format"]=doc.source_format;
        Json profs = Json::array();
        bool reveal = a.has("reveal");
        for (auto& p : doc.profiles) {
            auto pp = reveal ? p : vpn::mask_profile(p);
            Json jp = Json::object();
            jp["protocol"]=vpn::to_string(pp.protocol); jp["tag"]=pp.tag;
            jp["address"]=pp.address; jp["port"]=pp.port;
            jp["network"]=pp.network; jp["security"]=pp.security;
            if(!pp.uuid.empty())jp["uuid"]=pp.uuid;
            if(!pp.password.empty())jp["password"]=pp.password;
            if(!pp.method.empty())jp["method"]=pp.method;
            if(!pp.sni.empty())jp["sni"]=pp.sni;
            profs.push_back(jp);
        }
        j["profiles"]=profs;
        Json warns = Json::array(); for(auto&w:doc.warnings)warns.push_back(w); j["warnings"]=warns;
        std::cout << j.dump(2) << "\n";
        return 0;
    }
    if (sub == "audit") {
        auto doc = vpn::parse_any(text, ext);
        auto a1 = vpn::audit_profiles(doc);
        auto a2 = vpn::audit_text(text);
        std::cout << brand::logo_compact(g_color) << "\nSecurity audit: " << core::file_name(a.pos[0]) << "\n";
        std::cout << "Score: " << std::min(a1.score,a2.score) << "/100\n\n";
        for (auto* ar : {&a1,&a2})
            for (auto& f : ar->findings)
                std::cout << "  [" << vpn::to_string(f.severity) << "] " << f.title
                          << "\n      " << f.detail << "\n      -> " << f.recommendation << "\n";
        return 0;
    }
    if (sub == "convert") {
        std::string to = a.get("to","uri");
        auto doc = vpn::parse_any(text, ext);
        if (doc.profiles.empty()) { std::cerr << "no profile parsed\n"; return 1; }
        auto r = vpn::emit(doc.profiles.front(), to);
        if (!r) { std::cerr << r.error << "\n"; return 1; }
        return write_out(a, r.value);
    }
    std::cerr << "unknown vpn subcommand: " << sub << "\n";
    return 2;
}

static int cmd_metadata(const Args& a) {
    if (a.pos.empty()) { std::cerr << "metadata: missing file\n"; return 2; }
    auto j = engines::extract_metadata(a.pos[0]);
    std::cout << j.dump(2) << "\n";
    return 0;
}

static int cmd_batch(const Args& a) {
    if (a.pos.empty()) { std::cerr << "batch: missing directory\n"; return 2; }
    std::string out = a.get("out", "batch_results.ndjson");
    std::string cp = a.get("checkpoint", out + ".checkpoint");
    core::BatchEngine be;
    std::cerr << brand::logo_compact(g_color);
    auto r = be.run(a.pos[0], out, cp, !a.has("no-recursive"),
        [&](const core::BatchProgress& p){
            std::cerr << "\r  [" << p.done << "/" << p.total << "] errors=" << p.errors
                      << "  " << core::file_name(p.current) << std::string(10,' ') << std::flush;
        });
    std::cerr << "\n";
    if (!r) { std::cerr << "batch: " << r.error << "\n"; return 1; }
    std::cout << "Done: " << r.value.done << "/" << r.value.total
              << " files, " << r.value.errors << " error(s)\n";
    std::cout << "Results : " << out << "\nCheckpoint: " << cp
              << " (re-run to resume)\n";
    return 0;
}

static int cmd_sigdb(const Args& a) {
    if (a.pos.empty()) { std::cerr << "sigdb: missing db path\n"; return 2; }
    core::SignatureDB db;
    if (!db.open(a.pos[0])) { std::cerr << "cannot open db\n"; return 1; }
    if (a.has("seed")) {
        auto r = db.seed_builtins();
        if (!r) { std::cerr << r.error << "\n"; return 1; }
        std::cout << "Seeded " << r.value << " built-in signatures.\n";
    }
    std::cout << "Signature DB: " << db.path() << " — " << db.count() << " record(s)\n";
    return 0;
}

static int interactive_menu() {
    std::cout << brand::banner(g_color, kVersion, get_arch(), get_os());
    while (true) {
        std::cout << brand::ansi::green << "\n  [1]" << brand::ansi::reset << " Analyser un fichier\n"
                  << brand::ansi::green << "  [2]" << brand::ansi::reset << " Scanner un dossier\n"
                  << brand::ansi::green << "  [3]" << brand::ansi::reset << " Parser une config VPN (ouverte)\n"
                  << brand::ansi::green << "  [4]" << brand::ansi::reset << " Auditer une config VPN\n"
                  << brand::ansi::green << "  [5]" << brand::ansi::reset << " Generer une config VPN\n"
                  << brand::ansi::green << "  [0]" << brand::ansi::reset << " Quitter\n";
        if (!g_color) {}
        std::cout << "\n  Choix: ";
        std::string c; if (!std::getline(std::cin, c)) break;
        if (c=="0"||c=="q") break;
        std::string path;
        if (c=="1"||c=="2"||c=="3"||c=="4") {
            std::cout << "  Chemin du fichier: "; std::getline(std::cin, path);
        }
        Args a; a.pos.push_back(path);
        if (c=="1") cmd_analyze(a);
        else if (c=="2") cmd_scan(a);
        else if (c=="3") cmd_vpn(a, "parse");
        else if (c=="4") cmd_vpn(a, "audit");
        else if (c=="5") {
            std::cout << "  Protocole (vless/vmess/trojan/shadowsocks/wireguard/openvpn/ssh/slowdns/udp): ";
            std::string proto; std::getline(std::cin, proto);
            std::cout << "  Adresse serveur: "; std::string addr; std::getline(std::cin, addr);
            Args g; g.opt["proto"]=proto; g.opt["addr"]=addr.empty()?"example.com":addr;
            cmd_vpn(g, "generate");
        }
    }
    std::cout << "Bye.\n";
    return 0;
}

int main(int argc, char** argv) {
    // Color only on a TTY unless forced off.
    g_color = isatty(fileno(stdout));
    // Collect argv while stripping leading global flags so the command can be
    // given before or after --no-color.
    std::vector<char*> av; av.push_back(argv[0]);
    for (int i=1;i<argc;++i) {
        std::string s = argv[i];
        if (s=="--no-color") { g_color=false; continue; }
        av.push_back(argv[i]);
    }
    argc = (int)av.size();
    argv = av.data();

    if (argc < 2) return interactive_menu();
    std::string cmd = argv[1];

    if (cmd=="-h"||cmd=="--help"||cmd=="help") { print_usage(); return 0; }
    if (cmd=="version"||cmd=="--version") return cmd_version();
    if (cmd=="menu") return interactive_menu();

    if (cmd=="vpn") {
        if (argc < 3) { std::cerr << "vpn: missing subcommand\n"; return 2; }
        std::string sub = argv[2];
        Args a = parse_args(argc, argv, 3);
        return cmd_vpn(a, sub);
    }
    Args a = parse_args(argc, argv, 2);
    if (cmd=="scan") return cmd_scan(a);
    if (cmd=="analyze"||cmd=="inspect") return cmd_analyze(a);
    if (cmd=="report") return cmd_report(a);
    if (cmd=="metadata") return cmd_metadata(a);
    if (cmd=="batch") return cmd_batch(a);
    if (cmd=="sigdb") return cmd_sigdb(a);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    print_usage();
    return 2;
}
