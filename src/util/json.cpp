#include "dlu/util/json.hpp"
#include <cmath>
#include <cstdio>
#include <cctype>
#include <sstream>

namespace dlu::util {

Json& Json::operator[](const std::string& key) {
    if (type_ != Type::Object) { type_ = Type::Object; obj_.clear(); }
    for (auto& kv : obj_) if (kv.first == key) return kv.second;
    obj_.emplace_back(key, Json());
    return obj_.back().second;
}

const Json* Json::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (auto& kv : obj_) if (kv.first == key) return &kv.second;
    return nullptr;
}

void Json::push_back(Json v) {
    if (type_ != Type::Array) { type_ = Type::Array; arr_.clear(); }
    arr_.push_back(std::move(v));
}

std::string Json::as_string(const std::string& def) const {
    return type_ == Type::String ? str_ : def;
}
int64_t Json::as_int(int64_t def) const {
    if (type_ == Type::Int) return int_;
    if (type_ == Type::Double) return (int64_t)dbl_;
    return def;
}
double Json::as_double(double def) const {
    if (type_ == Type::Double) return dbl_;
    if (type_ == Type::Int) return (double)int_;
    return def;
}
bool Json::as_bool(bool def) const {
    return type_ == Type::Bool ? bool_ : def;
}

void Json::escape(const std::string& s, std::string& out) {
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else out.push_back(c);
        }
    }
    out.push_back('"');
}

void Json::dump_to(std::string& out, int indent, int depth) const {
    auto pad = [&](int d) { if (indent > 0) out.append((size_t)d * indent, ' '); };
    const char* nl = indent > 0 ? "\n" : "";
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Int: out += std::to_string(int_); break;
        case Type::Double: {
            if (std::isfinite(dbl_)) {
                std::ostringstream ss; ss << dbl_; out += ss.str();
            } else out += "null";
            break;
        }
        case Type::String: escape(str_, out); break;
        case Type::Array: {
            if (arr_.empty()) { out += "[]"; break; }
            out += "["; out += nl;
            for (size_t i = 0; i < arr_.size(); ++i) {
                pad(depth + 1);
                arr_[i].dump_to(out, indent, depth + 1);
                if (i + 1 < arr_.size()) out += ",";
                out += nl;
            }
            pad(depth); out += "]";
            break;
        }
        case Type::Object: {
            if (obj_.empty()) { out += "{}"; break; }
            out += "{"; out += nl;
            for (size_t i = 0; i < obj_.size(); ++i) {
                pad(depth + 1);
                escape(obj_[i].first, out);
                out += indent > 0 ? ": " : ":";
                obj_[i].second.dump_to(out, indent, depth + 1);
                if (i + 1 < obj_.size()) out += ",";
                out += nl;
            }
            pad(depth); out += "}";
            break;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    dump_to(out, indent, 0);
    return out;
}

// ---- Parser ----
namespace {
struct P {
    const std::string& s;
    size_t i = 0;
    bool ok = true;
    explicit P(const std::string& str) : s(str) {}
    void ws() { while (i < s.size() && (s[i]==' '||s[i]=='\t'||s[i]=='\n'||s[i]=='\r')) ++i; }
    Json value();
    Json str() {
        std::string out; ++i; // skip "
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return Json(out);
            if (c == '\\' && i < s.size()) {
                char e = s[i++];
                switch (e) {
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case '/': out.push_back('/'); break;
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case 'u': {
                        if (i + 4 > s.size()) { ok = false; return Json(); }
                        int cp = std::stoi(s.substr(i, 4), nullptr, 16); i += 4;
                        if (cp < 0x80) out.push_back((char)cp);
                        else if (cp < 0x800) {
                            out.push_back((char)(0xC0 | (cp >> 6)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back((char)(0xE0 | (cp >> 12)));
                            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back((char)(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: out.push_back(e);
                }
            } else out.push_back(c);
        }
        ok = false; return Json();
    }
    Json num() {
        size_t start = i;
        bool dbl = false;
        if (s[i] == '-') ++i;
        while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i]=='.'||s[i]=='e'||s[i]=='E'||s[i]=='+'||s[i]=='-')) {
            if (s[i]=='.'||s[i]=='e'||s[i]=='E') dbl = true;
            ++i;
        }
        std::string tok = s.substr(start, i - start);
        try {
            if (dbl) return Json(std::stod(tok));
            return Json((int64_t)std::stoll(tok));
        } catch (...) { ok = false; return Json(); }
    }
};

Json P::value() {
    ws();
    if (i >= s.size()) { ok = false; return Json(); }
    char c = s[i];
    if (c == '"') return str();
    if (c == '{') {
        Json o = Json::object(); ++i; ws();
        if (i < s.size() && s[i] == '}') { ++i; return o; }
        while (ok && i < s.size()) {
            ws();
            if (s[i] != '"') { ok = false; break; }
            Json key = str(); ws();
            if (i >= s.size() || s[i] != ':') { ok = false; break; }
            ++i;
            o[key.as_string()] = value(); ws();
            if (i < s.size() && s[i] == ',') { ++i; continue; }
            if (i < s.size() && s[i] == '}') { ++i; break; }
            ok = false; break;
        }
        return o;
    }
    if (c == '[') {
        Json a = Json::array(); ++i; ws();
        if (i < s.size() && s[i] == ']') { ++i; return a; }
        while (ok && i < s.size()) {
            a.push_back(value()); ws();
            if (i < s.size() && s[i] == ',') { ++i; continue; }
            if (i < s.size() && s[i] == ']') { ++i; break; }
            ok = false; break;
        }
        return a;
    }
    if (c == 't') { if (s.compare(i,4,"true")==0){i+=4;return Json(true);} ok=false;return Json(); }
    if (c == 'f') { if (s.compare(i,5,"false")==0){i+=5;return Json(false);} ok=false;return Json(); }
    if (c == 'n') { if (s.compare(i,4,"null")==0){i+=4;return Json(nullptr);} ok=false;return Json(); }
    if (c == '-' || std::isdigit((unsigned char)c)) return num();
    ok = false; return Json();
}
} // namespace

std::optional<Json> Json::parse(const std::string& text) {
    P p(text);
    Json v = p.value();
    p.ws();
    if (!p.ok) return std::nullopt;
    return v;
}

} // namespace dlu::util
