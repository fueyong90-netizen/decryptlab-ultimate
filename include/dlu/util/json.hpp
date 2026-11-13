#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <variant>
#include <optional>
#include <cstdint>
#include <initializer_list>

namespace dlu::util {

// A small, dependency-free JSON value. Preserves insertion order for objects
// so generated configs are stable and readable. Not a full RFC 8259 validator
// but handles the subset needed by DecryptLab (configs, reports, API payloads).
class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Json() : type_(Type::Null) {}
    Json(std::nullptr_t) : type_(Type::Null) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(int i) : type_(Type::Int), int_(i) {}
    Json(int64_t i) : type_(Type::Int), int_(i) {}
    Json(size_t i) : type_(Type::Int), int_((int64_t)i) {}
    Json(double d) : type_(Type::Double), dbl_(d) {}
    Json(const char* s) : type_(Type::String), str_(s) {}
    Json(const std::string& s) : type_(Type::String), str_(s) {}
    Json(std::string&& s) : type_(Type::String), str_(std::move(s)) {}

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_null() const { return type_ == Type::Null; }

    // Object access (creates key if missing).
    Json& operator[](const std::string& key);
    const Json* find(const std::string& key) const;

    // Array push.
    void push_back(Json v);
    const std::vector<Json>& items() const { return arr_; }
    std::vector<Json>& items() { return arr_; }

    // Typed getters with defaults.
    std::string as_string(const std::string& def = "") const;
    int64_t as_int(int64_t def = 0) const;
    double as_double(double def = 0.0) const;
    bool as_bool(bool def = false) const;

    const std::vector<std::pair<std::string, Json>>& members() const { return obj_; }

    std::string dump(int indent = 2) const;

    static std::optional<Json> parse(const std::string& text);

private:
    Type type_;
    bool bool_ = false;
    int64_t int_ = 0;
    double dbl_ = 0.0;
    std::string str_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;

    void dump_to(std::string& out, int indent, int depth) const;
    static void escape(const std::string& s, std::string& out);
};

} // namespace dlu::util
