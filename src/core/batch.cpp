#include "dlu/core/batch.hpp"
#include "dlu/core/analyzer.hpp"
#include <filesystem>
#include <fstream>
#include <set>

namespace fs = std::filesystem;

namespace dlu::core {

static std::set<std::string> load_checkpoint(const std::string& path) {
    std::set<std::string> done;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) if (!line.empty()) done.insert(line);
    return done;
}

Result<BatchProgress> BatchEngine::run(const std::string& root,
                                       const std::string& out_ndjson,
                                       const std::string& checkpoint_path,
                                       bool recursive,
                                       const std::function<void(const BatchProgress&)>& on_progress) {
    BatchProgress prog;
    std::error_code ec;

    // Collect target files first (for a stable total).
    std::vector<std::string> files;
    if (fs::is_directory(root, ec)) {
        if (recursive) {
            for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_regular_file(ec)) files.push_back(it->path().string());
            }
        } else {
            for (auto it = fs::directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
                 it != fs::directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_regular_file(ec)) files.push_back(it->path().string());
            }
        }
    } else if (fs::is_regular_file(root, ec)) {
        files.push_back(root);
    } else {
        return Result<BatchProgress>::fail("not a file or directory: " + root);
    }

    prog.total = files.size();
    auto done = load_checkpoint(checkpoint_path);

    // Append mode so resume keeps earlier results.
    std::ofstream out(out_ndjson, std::ios::app);
    std::ofstream cp(checkpoint_path, std::ios::app);
    if (!out) return Result<BatchProgress>::fail("cannot open output: " + out_ndjson);

    Analyzer an;
    for (const auto& f : files) {
        prog.current = f;
        if (done.count(f)) { ++prog.done; if (on_progress) on_progress(prog); continue; }
        auto j = an.analyze(f, true);
        out << j.dump(0) << "\n";
        out.flush();
        cp << f << "\n"; cp.flush();         // checkpoint immediately for safe resume
        auto st = j.find("status");
        if (st && st->as_string() == "error") ++prog.errors;
        ++prog.done;
        if (on_progress) on_progress(prog);
    }
    return Result<BatchProgress>::good(prog);
}

} // namespace dlu::core
