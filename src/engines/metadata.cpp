#include "dlu/engines/metadata.hpp"
#include "dlu/core/fileio.hpp"
#include "dlu/core/hashing.hpp"
#include "dlu/core/detector.hpp"
#include <sys/stat.h>
#include <ctime>
#include <cstdio>

namespace dlu::engines {

using util::Json;

static std::string iso_time(time_t t) {
    char buf[32];
    struct tm tmv{};
    gmtime_r(&t, &tmv);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

util::Json extract_metadata(const std::string& path) {
    Json j = Json::object();
    j["file"] = core::file_name(path);
    j["extension"] = core::file_extension(path);

    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        j["size"] = (int64_t)st.st_size;
        j["modified"] = iso_time(st.st_mtime);
        j["accessed"] = iso_time(st.st_atime);
        j["changed"] = iso_time(st.st_ctime);
        char perm[11] = "----------";
        mode_t m = st.st_mode;
        if (m & S_IRUSR) { perm[1]='r'; }
        if (m & S_IWUSR) { perm[2]='w'; }
        if (m & S_IXUSR) { perm[3]='x'; }
        if (m & S_IRGRP) { perm[4]='r'; }
        if (m & S_IWGRP) { perm[5]='w'; }
        if (m & S_IXGRP) { perm[6]='x'; }
        if (m & S_IROTH) { perm[7]='r'; }
        if (m & S_IWOTH) { perm[8]='w'; }
        if (m & S_IXOTH) { perm[9]='x'; }
        j["permissions"] = std::string(perm + 1);
        char oct[8]; snprintf(oct, sizeof(oct), "%03o", m & 0777);
        j["mode_octal"] = std::string(oct);
    }

    core::Detector det;
    auto rep = det.detect(path);
    if (!rep.hypotheses.empty()) {
        j["mime"] = rep.hypotheses.front().mime;
        j["detected_format"] = rep.hypotheses.front().label;
    }
    auto h = core::sha256_file(path);
    if (h) j["sha256"] = h.value;
    return j;
}

} // namespace dlu::engines
