#include "dlu/core/scanner.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/core/hashing.hpp"
#include "dlu/core/detector.hpp"
#include <filesystem>

namespace fs = std::filesystem;

namespace dlu::core {

void Scanner::scan_file(const std::string& file, ScanResult& out) const {
    ScanItem it;
    it.path = file;
    auto sz = file_size(file);
    if (!sz) { ++out.errors; return; }
    it.size = sz.value;
    out.total_bytes += it.size;
    if (hash_) {
        auto h = sha256_file(file);
        if (h) it.sha256 = h.value; else ++out.errors;
    }
    Detector det;
    auto rep = det.detect(file);
    if (!rep.hypotheses.empty()) {
        it.top_format = rep.hypotheses.front().label;
        it.category = rep.hypotheses.front().category;
    }
    it.extension_mismatch = rep.extension_mismatch;
    out.items.push_back(std::move(it));
}

void Scanner::scan_dir(const std::string& dir, ScanResult& out) const {
    std::error_code ec;
    if (recursive_) {
        for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ++out.errors; ec.clear(); continue; }
            if (it->is_regular_file(ec)) scan_file(it->path().string(), out);
        }
    } else {
        for (auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) { ++out.errors; ec.clear(); continue; }
            if (it->is_regular_file(ec)) scan_file(it->path().string(), out);
        }
    }
}

ScanResult Scanner::scan(const std::string& path) const {
    ScanResult out;
    std::error_code ec;
    if (fs::is_directory(path, ec)) scan_dir(path, out);
    else if (fs::is_regular_file(path, ec)) scan_file(path, out);
    else ++out.errors;
    return out;
}

} // namespace dlu::core
