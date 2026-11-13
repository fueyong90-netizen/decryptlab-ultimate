#pragma once
#include "dlu/core/common.hpp"
#include "dlu/core/signatures.hpp"
#include <string>
#include <vector>

namespace dlu::core {

// SQLite-backed, extensible signature & learning database (spec 4.10 / V2).
// Verifiable, optional, and not required for offline use: if the DB is absent
// the detector falls back to the built-in table. Updates are explicit.
class SignatureDB {
public:
    // Open (and create schema if needed). Returns false on error.
    bool open(const std::string& path);
    void close();
    ~SignatureDB();

    // Seed the DB from the built-in signature table (idempotent upsert).
    Result<int> seed_builtins();

    // Add or update one signature record.
    Result<bool> upsert(const Signature& s);

    // Load all signatures from the DB (merged with built-ins by the caller).
    std::vector<Signature> load_all() const;

    // Simple stats for reports / version output.
    int count() const;
    std::string path() const { return path_; }
    bool is_open() const { return db_ != nullptr; }

private:
    void* db_ = nullptr;  // sqlite3*
    std::string path_;
    bool exec(const std::string& sql);
};

} // namespace dlu::core
