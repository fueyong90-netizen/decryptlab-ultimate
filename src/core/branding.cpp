#include "dlu/core/branding.hpp"
#include "dlu/core/common.hpp"
#include <sstream>

namespace dlu::brand {

// Skull & crossbones rendered with binary/hex glyphs, echoing the brief's
// ASCII identity. Kept compact to stay readable in a standard 80-col terminal.
static const char* kSkull =
"            01000100 01001100 01010101            \n"
"          .d88888888888888888888b.          \n"
"        .8888P\"\"       \"\"       \"Y8888b.        \n"
"       d88P    01    .--.    10    Y88b       \n"
"      d8888   .--.  /0xFF\\  .--.   8888b      \n"
"      88888  ( OO )  \\__/  ( OO )  88888      \n"
"      Y8888   `--'  _.__._  `--'   8888P      \n"
"       Y88b        ( 1001 )       d88P       \n"
"        `Y88b.      `wwww'      .d88P'        \n"
"          `\"Y8b.___________.d8Y\"'          \n"
"      __/`---._ 11010 010 _.---'\\__      \n"
"     /.--.      `-._____.-'      .--.\\     \n"
"    //    \\      /0110110\\      /    \\\\    \n"
"   //      `.__.'        `.__.'      \\\\   \n";

std::string logo_full(bool color) {
    std::ostringstream o;
    if (color) o << ansi::red;
    o << kSkull;
    if (color) o << ansi::reset;
    if (color) o << ansi::bold << ansi::white;
    o <<
"  ____                        _   _          _     \n"
" |  _ \\  ___  ___ _ __ _   _ _ __ | |_| |    __ _| |__  \n"
" | | | |/ _ \\/ __| '__| | | | '_ \\| __| |   / _` | '_ \\ \n"
" | |_| |  __/ (__| |  | |_| | |_) | |_| |__| (_| | |_) |\n"
" |____/ \\___|\\___|_|   \\__, | .__/ \\__|_____\\__,_|_.__/ \n"
"                       |___/|_|       U L T I M A T E   \n";
    if (color) o << ansi::reset;
    if (color) o << ansi::red;
    o << "                     by JORDAN HACKER\n";
    if (color) o << ansi::reset;
    return o.str();
}

std::string logo_compact(bool color) {
    std::ostringstream o;
    if (color) o << ansi::bold << ansi::white;
    o << "☠ DECRYPTLAB ULTIMATE";
    if (color) o << ansi::reset << ansi::red;
    o << "  by JORDAN HACKER";
    if (color) o << ansi::reset;
    o << "\n";
    return o.str();
}

std::string banner(bool color, const std::string& version,
                   const std::string& arch, const std::string& os) {
    std::ostringstream o;
    o << logo_full(color);
    auto line = [&](const char* k, const std::string& v, const char* vcol) {
        if (color) o << ansi::green << "[+] " << ansi::gray;
        else o << "[+] ";
        o << k;
        if (color) o << ansi::reset << (vcol ? vcol : "");
        o << v;
        if (color) o << ansi::reset;
        o << "\n";
    };
    line("Version      : ", version, ansi::white);
    line("OS           : ", os, ansi::white);
    line("Architecture : ", arch, ansi::white);
    line("Status       : ", "Ready", ansi::green);
    o << "\n";
    return o.str();
}

} // namespace dlu::brand
