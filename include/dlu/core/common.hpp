#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace dlu {

constexpr const char* kVersion = "1.0.0";
constexpr const char* kCodename = "Ultimate";

// Support level, as required by the spec (section 10 / 13): every capability
// reports honestly where it stands. Never claim a higher level than reality.
enum class Support {
    Implemented,      // implemented and covered by tests
    PartiallyTested,  // implemented, limited test coverage
    InterfaceOnly,    // interface defined, engine not yet implemented
    Unsupported       // explicitly not supported
};

const char* to_string(Support s);

// Generic operation status for reports.
enum class OpStatus { Success, Partial, Failed, Skipped };
const char* to_string(OpStatus s);

// A lightweight Result<T> without exceptions for the hot paths.
template <typename T>
struct Result {
    bool ok = false;
    T value{};
    std::string error;
    static Result good(T v) { return {true, std::move(v), ""}; }
    static Result fail(std::string e) { return {false, {}, std::move(e)}; }
    explicit operator bool() const { return ok; }
};

} // namespace dlu
