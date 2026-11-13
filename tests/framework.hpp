#pragma once
// Minimal dependency-free test framework (no gtest/catch available offline).
#include <cstdio>
#include <string>
#include <vector>
#include <functional>

namespace dlutest {

struct Case { std::string name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
inline int& failures() { static int f = 0; return f; }
inline int& checks() { static int c = 0; return c; }

struct Reg { Reg(const std::string& n, std::function<void()> f){ registry().push_back({n,std::move(f)}); } };

inline void report_fail(const char* file, int line, const std::string& msg) {
    ++failures();
    std::printf("  \033[31mFAIL\033[0m %s:%d  %s\n", file, line, msg.c_str());
}

inline int run_all() {
    int passed = 0;
    for (auto& c : registry()) {
        int before = failures();
        try { c.fn(); }
        catch (const std::exception& e) { report_fail("<exception>", 0, e.what()); }
        catch (...) { report_fail("<exception>", 0, "unknown"); }
        if (failures()==before) { std::printf("  \033[32mPASS\033[0m %s\n", c.name.c_str()); ++passed; }
    }
    std::printf("\n%d/%zu cases passed, %d checks, %d failure(s)\n",
                passed, registry().size(), checks(), failures());
    return failures()==0 ? 0 : 1;
}

} // namespace dlutest

#define TEST(name) \
    static void name(); \
    static dlutest::Reg reg_##name(#name, name); \
    static void name()

#define CHECK(cond) do { ++dlutest::checks(); if(!(cond)) \
    dlutest::report_fail(__FILE__, __LINE__, "CHECK failed: " #cond); } while(0)

#define CHECK_EQ(a,b) do { ++dlutest::checks(); auto _va=(a); auto _vb=(b); if(!(_va==_vb)) \
    dlutest::report_fail(__FILE__, __LINE__, std::string("CHECK_EQ failed: " #a " == " #b)); } while(0)

#define RUN_TESTS() int main(){ return dlutest::run_all(); }
