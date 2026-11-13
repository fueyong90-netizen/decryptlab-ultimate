#include "dlu/core/hashing.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/util/hex.hpp"
#include <openssl/evp.h>

namespace dlu::core {

static Result<std::string> digest_file(const std::string& path, const EVP_MD* md) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return Result<std::string>::fail("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<std::string>::fail("digest init failed");
    }
    auto r = stream_file(path, 1u << 20, [&](const uint8_t* p, size_t n) {
        EVP_DigestUpdate(ctx, p, n);
    });
    if (!r) { EVP_MD_CTX_free(ctx); return Result<std::string>::fail(r.error); }
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    return Result<std::string>::good(util::to_hex(out, len));
}

Result<std::string> sha256_file(const std::string& path) { return digest_file(path, EVP_sha256()); }
Result<std::string> sha1_file(const std::string& path)   { return digest_file(path, EVP_sha1()); }
Result<std::string> md5_file(const std::string& path)     { return digest_file(path, EVP_md5()); }

std::string sha256_bytes(const uint8_t* data, size_t len) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int olen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &olen);
    EVP_MD_CTX_free(ctx);
    return util::to_hex(out, olen);
}

} // namespace dlu::core
