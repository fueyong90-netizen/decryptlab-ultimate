#include "dlu/core/fileio.hpp"
#include <cstdio>
#include <sys/stat.h>
#include <algorithm>

namespace dlu::core {

Result<uint64_t> file_size(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0)
        return Result<uint64_t>::fail("cannot stat: " + path);
    if (!S_ISREG(st.st_mode))
        return Result<uint64_t>::fail("not a regular file: " + path);
    return Result<uint64_t>::good((uint64_t)st.st_size);
}

bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

std::string file_extension(const std::string& path) {
    auto slash = path.find_last_of("/\\");
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    auto dot = name.find_last_of('.');
    if (dot == std::string::npos || dot == 0) return "";
    std::string ext = name.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

std::string file_name(const std::string& path) {
    auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

Result<std::vector<uint8_t>> read_prefix(const std::string& path, size_t max_bytes) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return Result<std::vector<uint8_t>>::fail("cannot open: " + path);
    std::vector<uint8_t> buf(max_bytes);
    size_t n = std::fread(buf.data(), 1, max_bytes, f);
    std::fclose(f);
    buf.resize(n);
    return Result<std::vector<uint8_t>>::good(std::move(buf));
}

Result<std::vector<uint8_t>> read_all(const std::string& path, size_t limit) {
    auto sz = file_size(path);
    if (!sz) return Result<std::vector<uint8_t>>::fail(sz.error);
    if (sz.value > limit)
        return Result<std::vector<uint8_t>>::fail(
            "file exceeds in-memory limit (" + std::to_string(sz.value) +
            " bytes); use streaming mode");
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return Result<std::vector<uint8_t>>::fail("cannot open: " + path);
    std::vector<uint8_t> buf((size_t)sz.value);
    size_t n = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    buf.resize(n);
    return Result<std::vector<uint8_t>>::good(std::move(buf));
}

Result<uint64_t> stream_file(const std::string& path, size_t block_size,
                             const std::function<void(const uint8_t*, size_t)>& cb) {
    if (block_size == 0) block_size = 1u << 20;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return Result<uint64_t>::fail("cannot open: " + path);
    std::vector<uint8_t> buf(block_size);
    uint64_t total = 0;
    size_t n;
    while ((n = std::fread(buf.data(), 1, block_size, f)) > 0) {
        cb(buf.data(), n);
        total += n;
    }
    std::fclose(f);
    return Result<uint64_t>::good(total);
}

} // namespace dlu::core
