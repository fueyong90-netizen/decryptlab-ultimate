#include "dlu/engines/archive.hpp"
#include "dlu/core/fileio.hpp"
#include <cstring>

namespace dlu::engines {

static uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

ZipReport inspect_zip(const std::string& path) {
    ZipReport r;
    // Read the tail to find the End Of Central Directory (EOCD).
    auto sz = core::file_size(path);
    if (!sz) { r.error = sz.error; return r; }
    size_t tail = sz.value < 66000 ? (size_t)sz.value : 66000;
    auto buf = core::read_prefix(path, (size_t)sz.value); // small-to-mid files
    if (!buf) { r.error = buf.error; return r; }
    const auto& d = buf.value;
    if (d.size() < 22) { r.error = "too small for ZIP"; return r; }

    // Find EOCD signature 0x06054b50 scanning backwards.
    const uint32_t EOCD = 0x06054b50;
    size_t eocd = std::string::npos;
    size_t start = d.size() >= tail ? d.size() - tail : 0;
    for (size_t i = d.size() - 22 + 1; i-- > start; ) {
        if (rd32(&d[i]) == EOCD) { eocd = i; break; }
    }
    if (eocd == std::string::npos) { r.error = "EOCD not found (not a ZIP or truncated)"; return r; }

    uint16_t total_entries = rd16(&d[eocd + 10]);
    uint32_t cd_offset = rd32(&d[eocd + 16]);
    r.valid = true;

    const uint32_t CEN = 0x02014b50;
    size_t p = cd_offset;
    size_t count = 0;
    const size_t kMaxEntries = 100000;    // zip-bomb guard
    const uint64_t kMaxRatioCeil = 1000;  // compression ratio alarm
    while (p + 46 <= d.size() && rd32(&d[p]) == CEN) {
        ZipEntry e;
        uint16_t flags = rd16(&d[p + 8]);
        e.method = rd16(&d[p + 10]);
        e.crc32 = rd32(&d[p + 16]);
        e.compressed_size = rd32(&d[p + 20]);
        e.uncompressed_size = rd32(&d[p + 24]);
        uint16_t nlen = rd16(&d[p + 28]);
        uint16_t elen = rd16(&d[p + 30]);
        uint16_t clen = rd16(&d[p + 32]);
        e.encrypted = (flags & 0x1) != 0;
        if (p + 46 + nlen <= d.size())
            e.name.assign((const char*)&d[p + 46], nlen);
        if (e.encrypted) r.has_encrypted = true;
        r.total_uncompressed += e.uncompressed_size;
        if (e.compressed_size > 0 &&
            e.uncompressed_size / (e.compressed_size ? e.compressed_size : 1) > kMaxRatioCeil)
            r.zip_bomb_suspected = true;
        r.entries.push_back(std::move(e));
        p += 46 + nlen + elen + clen;
        if (++count > kMaxEntries) { r.zip_bomb_suspected = true;
            r.notes.push_back("entry count cap reached; aborting walk"); break; }
    }
    if (total_entries != r.entries.size())
        r.notes.push_back("declared entries=" + std::to_string(total_entries) +
                          " walked=" + std::to_string(r.entries.size()));
    if (r.has_encrypted)
        r.notes.push_back("archive contains password-protected entries; "
                          "extraction needs the owner's password (not recovered here)");
    if (r.zip_bomb_suspected)
        r.notes.push_back("WARNING: zip-bomb characteristics; do not auto-extract");
    return r;
}

} // namespace dlu::engines
