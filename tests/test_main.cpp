#include "framework.hpp"
#include "dlu/util/base64.hpp"
#include "dlu/util/json.hpp"
#include "dlu/util/hex.hpp"
#include "dlu/core/entropy.hpp"
#include "dlu/core/detector.hpp"
#include "dlu/vpn/uri.hpp"
#include "dlu/vpn/parser.hpp"
#include "dlu/vpn/generator.hpp"
#include "dlu/vpn/auditor.hpp"
#include "dlu/engines/proprietary.hpp"
#include "dlu/engines/metadata.hpp"
#include "dlu/core/sigdb.hpp"
#include "dlu/core/batch.hpp"
#include "dlu/net/http_server.hpp"
#include <fstream>
#include <cstdio>
#include <cstdlib>

using namespace dlu;

// ---------- util ----------
TEST(base64_roundtrip) {
    std::string in = "Hello, DecryptLab! 1234";
    auto enc = util::base64_encode(in);
    auto dec = util::base64_decode(enc);
    CHECK(dec.has_value());
    std::string out((char*)dec->data(), dec->size());
    CHECK_EQ(out, in);
}

TEST(base64_known_vector) {
    CHECK_EQ(util::base64_encode(std::string("foobar")), std::string("Zm9vYmFy"));
}

TEST(hex_encode) {
    std::vector<uint8_t> d = {0x00, 0xFF, 0x10};
    CHECK_EQ(util::to_hex(d), std::string("00ff10"));
}

// ---------- json ----------
TEST(json_parse_dump) {
    auto j = util::Json::parse(R"({"a":1,"b":[true,null,"x"],"c":{"d":2.5}})");
    CHECK(j.has_value());
    CHECK_EQ(j->find("a")->as_int(), (int64_t)1);
    CHECK(j->find("b")->is_array());
    CHECK_EQ(j->find("b")->items().size(), (size_t)3);
    CHECK_EQ(j->find("c")->find("d")->as_double(), 2.5);
}

TEST(json_build) {
    util::Json o = util::Json::object();
    o["name"] = "dlu"; o["n"] = 42;
    auto s = o.dump(0);
    CHECK(s.find("\"name\":\"dlu\"") != std::string::npos);
    CHECK(s.find("\"n\":42") != std::string::npos);
}

// ---------- entropy ----------
TEST(entropy_zero_for_constant) {
    std::vector<uint8_t> z(1000, 0x41);
    core::EntropyMeter m; m.update(z.data(), z.size());
    CHECK(m.bits_per_byte() < 0.01);
}
TEST(entropy_high_for_counter) {
    std::vector<uint8_t> d(256);
    for (int i=0;i<256;++i) d[i]=(uint8_t)i;
    core::EntropyMeter m; m.update(d.data(), d.size());
    CHECK(m.bits_per_byte() > 7.9);
}

// ---------- detector ----------
TEST(detect_png_magic) {
    std::vector<uint8_t> png = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A, 0,0,0,0};
    core::Detector d;
    auto r = d.detect_bytes(png, "png");
    CHECK_EQ(r.hypotheses.front().format_id, std::string("png"));
    CHECK(r.hypotheses.front().confidence >= 90);
}
TEST(detect_extension_mismatch) {
    std::vector<uint8_t> elf = {0x7F,0x45,0x4C,0x46, 2,1,1,0};
    core::Detector d;
    auto r = d.detect_bytes(elf, "txt"); // ELF content, .txt extension
    CHECK(r.extension_mismatch);
}

// ---------- vpn uri ----------
TEST(vmess_uri_roundtrip) {
    vpn::VpnProfile p; p.protocol=vpn::Protocol::VMess;
    p.address="a.example.com"; p.port=443; p.uuid="11111111-2222-3333-4444-555555555555";
    p.network="ws"; p.path="/x"; p.security="tls"; p.tag="t";
    auto uri = vpn::to_uri(p);
    CHECK(uri.ok);
    CHECK(uri.value.rfind("vmess://",0)==0);
    auto back = vpn::parse_uri(uri.value);
    CHECK(back.ok);
    CHECK_EQ(back.value.address, p.address);
    CHECK_EQ(back.value.uuid, p.uuid);
    CHECK_EQ(back.value.port, 443);
}
TEST(vless_uri_parse) {
    std::string u = "vless://uuid-abc@host.net:443?type=ws&security=tls&sni=cdn.net&path=%2Fws#MyNode";
    auto r = vpn::parse_uri(u);
    CHECK(r.ok);
    CHECK_EQ(r.value.protocol == vpn::Protocol::VLESS, true);
    CHECK_EQ(r.value.address, std::string("host.net"));
    CHECK_EQ(r.value.port, 443);
    CHECK_EQ(r.value.network, std::string("ws"));
    CHECK_EQ(r.value.path, std::string("/ws"));
    CHECK_EQ(r.value.tag, std::string("MyNode"));
}
TEST(ss_uri_parse) {
    // ss://base64(method:password)@host:port#tag
    std::string creds = util::base64_encode(std::string("aes-256-gcm:secretpw"));
    std::string u = "ss://" + creds + "@1.2.3.4:8388#SS";
    auto r = vpn::parse_uri(u);
    CHECK(r.ok);
    CHECK_EQ(r.value.method, std::string("aes-256-gcm"));
    CHECK_EQ(r.value.password, std::string("secretpw"));
    CHECK_EQ(r.value.port, 8388);
}

// ---------- vpn parser ----------
TEST(wireguard_parse) {
    std::string wg =
        "[Interface]\nPrivateKey = ABCDEF==\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n"
        "[Peer]\nPublicKey = XYZ==\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n";
    auto doc = vpn::parse_wireguard(wg);
    CHECK_EQ(doc.profiles.size(), (size_t)1);
    CHECK_EQ(doc.profiles[0].address, std::string("vpn.example.com"));
    CHECK_EQ(doc.profiles[0].port, 51820);
    CHECK_EQ(doc.profiles[0].wg_private_key, std::string("ABCDEF=="));
}
TEST(openvpn_parse) {
    std::string ov = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\ncipher AES-256-GCM\n";
    auto doc = vpn::parse_openvpn(ov);
    CHECK_EQ(doc.profiles.size(), (size_t)1);
    CHECK_EQ(doc.profiles[0].address, std::string("vpn.example.com"));
    CHECK_EQ(doc.profiles[0].port, 1194);
    CHECK_EQ(doc.profiles[0].method, std::string("AES-256-GCM"));
}
TEST(v2ray_json_parse) {
    std::string js = R"({"outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"h.com","port":443,"users":[{"id":"uu","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"ws","security":"tls"}}]})";
    auto doc = vpn::parse_v2ray_json(js);
    CHECK_EQ(doc.profiles.size(), (size_t)1);
    CHECK_EQ(doc.profiles[0].address, std::string("h.com"));
    CHECK_EQ(doc.profiles[0].uuid, std::string("uu"));
    CHECK_EQ(doc.profiles[0].network, std::string("ws"));
}

// ---------- generator ----------
TEST(uuid_format) {
    auto u = vpn::generate_uuid();
    CHECK_EQ(u.size(), (size_t)36);
    CHECK_EQ(u[14], '4'); // version nibble
}
TEST(generate_vless_client) {
    vpn::GenOptions o; o.protocol=vpn::Protocol::VLESS; o.address="my.server";
    o.port=443; o.network="ws"; o.security="tls";
    auto r = vpn::generate(o);
    CHECK(r.ok);
    auto j = util::Json::parse(r.value.content);
    CHECK(j.has_value());
    CHECK(j->find("outbounds") != nullptr);
}
TEST(generate_wireguard) {
    vpn::GenOptions o; o.protocol=vpn::Protocol::WireGuard; o.address="wg.server";
    auto r = vpn::generate(o);
    CHECK(r.ok);
    CHECK(r.value.content.find("[Interface]") != std::string::npos);
    CHECK(r.value.content.find("[Peer]") != std::string::npos);
}
TEST(generate_ssh_script) {
    vpn::GenOptions o; o.protocol=vpn::Protocol::SSH; o.address="ssh.server"; o.ssh_user="me";
    auto r = vpn::generate(o);
    CHECK(r.ok);
    CHECK(r.value.content.find("ssh -N -D") != std::string::npos);
}

// ---------- auditor ----------
TEST(audit_flags_insecure_tls) {
    vpn::VpnDocument doc;
    vpn::VpnProfile p; p.protocol=vpn::Protocol::VLESS; p.security="none"; p.tag="x";
    doc.profiles.push_back(p);
    auto r = vpn::audit_profiles(doc);
    bool found=false;
    for (auto& f : r.findings) if (f.code=="TLS_NONE") found=true;
    CHECK(found);
    CHECK(r.score < 100);
}
TEST(mask_secret_hides) {
    auto m = vpn::mask_secret("supersecretpassword");
    CHECK(m.find("supersecretpassword") == std::string::npos);
    CHECK(m.rfind("sup",0)==0);
}

// ---------- proprietary inspector (honest, no cracking) ----------
TEST(proprietary_reports_limitation) {
    // random-ish high entropy bytes with .ehi extension
    std::vector<uint8_t> d(2048);
    for (size_t i=0;i<d.size();++i) d[i]=(uint8_t)((i*131+7)^(i>>3));
    engines::ProprietaryInspector insp;
    auto r = insp.inspect_bytes(d, "ehi");
    CHECK_EQ(r.format_guess, std::string("ehi"));
    CHECK_EQ(r.origin_app, std::string("HTTP Injector"));
    CHECK(!r.limitation.empty());
}

// ---------- V2: signature DB ----------
TEST(sigdb_seed_and_load) {
    std::string path = "/tmp/dlu_test_sig.db";
    ::remove(path.c_str());
    core::SignatureDB db;
    CHECK(db.open(path));
    auto r = db.seed_builtins();
    CHECK(r.ok);
    CHECK(r.value > 10);
    CHECK(db.count() == r.value);
    auto all = db.load_all();
    bool has_zip=false; for (auto& s : all) if (s.id=="zip") has_zip=true;
    CHECK(has_zip);
    db.close();
    ::remove(path.c_str());
}

// ---------- V2: batch engine + resume ----------
TEST(batch_runs_and_resumes) {
    std::string dir = "/tmp/dlu_batch_test";
    int rc0 = system("rm -rf /tmp/dlu_batch_test && mkdir -p /tmp/dlu_batch_test"); (void)rc0;
    { std::ofstream(dir+"/a.txt") << "hello"; std::ofstream(dir+"/b.bin").put('\x7f'); }
    std::string out="/tmp/dlu_batch.ndjson", cp="/tmp/dlu_batch.cp";
    ::remove(out.c_str()); ::remove(cp.c_str());
    core::BatchEngine be;
    auto r = be.run(dir, out, cp, true);
    CHECK(r.ok);
    CHECK(r.value.total == 2);
    CHECK(r.value.done == 2);
    // Resume: second run should skip both (done stays 2, no new output lines).
    auto r2 = be.run(dir, out, cp, true);
    CHECK(r2.ok);
    CHECK(r2.value.done == 2);
    int rc1 = system("rm -rf /tmp/dlu_batch_test /tmp/dlu_batch.ndjson /tmp/dlu_batch.cp"); (void)rc1;
}

// ---------- V2: metadata ----------
TEST(metadata_has_fields) {
    std::string p="/tmp/dlu_meta.txt";
    { std::ofstream(p) << "metadata test content"; }
    auto j = engines::extract_metadata(p);
    CHECK(j.find("size") != nullptr);
    CHECK(j.find("sha256") != nullptr);
    CHECK(j.find("permissions") != nullptr);
    ::remove(p.c_str());
}

// ---------- V2: http request query parse ----------
TEST(http_query_parse) {
    net::HttpRequest r; r.query="proto=vless&addr=my.server&port=443";
    CHECK_EQ(r.query_get("proto"), std::string("vless"));
    CHECK_EQ(r.query_get("addr"), std::string("my.server"));
    CHECK_EQ(r.query_get("port"), std::string("443"));
    CHECK_EQ(r.query_get("missing"), std::string(""));
}

RUN_TESTS()
