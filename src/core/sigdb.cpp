#include "dlu/core/sigdb.hpp"
#include "dlu/util/hex.hpp"
#include <sqlite3.h>
#include <sstream>

namespace dlu::core {

static std::vector<uint8_t> hex_to_bytes(const std::string& h) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
    return out;
}

bool SignatureDB::open(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    db_ = db;
    path_ = path;
    return exec(
        "CREATE TABLE IF NOT EXISTS signatures("
        "id TEXT PRIMARY KEY, label TEXT, category TEXT,"
        "magic_hex TEXT, offset INTEGER, mime TEXT, extensions TEXT);"
        "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);");
}

void SignatureDB::close() {
    if (db_) { sqlite3_close((sqlite3*)db_); db_ = nullptr; }
}
SignatureDB::~SignatureDB() { close(); }

bool SignatureDB::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec((sqlite3*)db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

Result<bool> SignatureDB::upsert(const Signature& s) {
    if (!db_) return Result<bool>::fail("db not open");
    std::string ext;
    for (size_t i = 0; i < s.extensions.size(); ++i) {
        if (i) ext += ",";
        ext += s.extensions[i];
    }
    const char* sql =
        "INSERT INTO signatures(id,label,category,magic_hex,offset,mime,extensions) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
        "label=excluded.label,category=excluded.category,magic_hex=excluded.magic_hex,"
        "offset=excluded.offset,mime=excluded.mime,extensions=excluded.extensions;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2((sqlite3*)db_, sql, -1, &st, nullptr) != SQLITE_OK)
        return Result<bool>::fail(sqlite3_errmsg((sqlite3*)db_));
    std::string magic = util::to_hex(s.magic);
    sqlite3_bind_text(st, 1, s.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, s.label.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, s.category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, magic.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)s.offset);
    sqlite3_bind_text(st, 6, s.mime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ext.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return Result<bool>::fail("step failed");
    return Result<bool>::good(true);
}

Result<int> SignatureDB::seed_builtins() {
    if (!db_) return Result<int>::fail("db not open");
    exec("BEGIN;");
    int n = 0;
    for (const auto& s : builtin_signatures()) { if (upsert(s)) ++n; }
    exec("COMMIT;");
    return Result<int>::good(n);
}

std::vector<Signature> SignatureDB::load_all() const {
    std::vector<Signature> out;
    if (!db_) return out;
    sqlite3_stmt* st = nullptr;
    const char* sql = "SELECT id,label,category,magic_hex,offset,mime,extensions FROM signatures;";
    if (sqlite3_prepare_v2((sqlite3*)db_, sql, -1, &st, nullptr) != SQLITE_OK) return out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        Signature s;
        auto txt = [&](int c)->std::string{ const unsigned char* p = sqlite3_column_text(st, c);
            return p ? std::string((const char*)p) : ""; };
        s.id = txt(0); s.label = txt(1); s.category = txt(2);
        s.magic = hex_to_bytes(txt(3));
        s.offset = (size_t)sqlite3_column_int64(st, 4);
        s.mime = txt(5);
        std::string ext = txt(6);
        std::stringstream ss(ext); std::string e;
        while (std::getline(ss, e, ',')) if (!e.empty()) s.extensions.push_back(e);
        out.push_back(std::move(s));
    }
    sqlite3_finalize(st);
    return out;
}

int SignatureDB::count() const {
    if (!db_) return 0;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2((sqlite3*)db_, "SELECT COUNT(*) FROM signatures;", -1, &st, nullptr) != SQLITE_OK)
        return 0;
    int n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

} // namespace dlu::core
