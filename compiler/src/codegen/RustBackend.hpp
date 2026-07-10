#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / make_synthetic_name — reused where PascalCase overlaps with Rust (see class comment)
#include <cctype>
#include <unordered_set>

namespace asn1::codegen {

// snake_case conversion shared by member_name/value_name: insert '_' before
// each uppercase letter (except the first char) and lower-case everything.
// "myMember" -> "my_member"; "MyType" -> "my_type"; "already_snake" unchanged.
inline std::string to_snake_case(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '-') { out += '_'; continue; }
        if (std::isupper(static_cast<unsigned char>(c)) && i != 0 &&
            !(out.size() && out.back() == '_'))
            out += '_';
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// SCREAMING_SNAKE_CASE conversion for Rust `const` names.
inline std::string to_screaming_snake_case(std::string_view s) {
    std::string out = to_snake_case(s);
    for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

// Escape an identifier that collides with a Rust 2021 keyword or any name in
// `extra`, using a raw identifier (`r#...`) — matches the convention rustc
// itself uses for keyword-colliding names from external sources.
inline std::string rust_escape(std::string n,
                                std::initializer_list<std::string_view> extra = {}) {
    static const std::unordered_set<std::string> kw = {
        "as","break","const","continue","crate","dyn","else","enum","extern",
        "false","fn","for","if","impl","in","let","loop","match","mod","move",
        "mut","pub","ref","return","self","Self","static","struct","super",
        "trait","true","type","unsafe","use","where","while","async","await",
        "try","union","abstract","become","box","do","final","macro","override",
        "priv","typeof","unsized","virtual","yield",
    };
    auto is_reserved = [&](const std::string& s) {
        if (kw.count(s)) return true;
        for (auto e : extra) if (s == e) return true;
        return false;
    };
    if (!is_reserved(n)) return n;
    return "r#" + n;
}

/// @brief Rust backend: the second `Backend` implementation, proving the
///        naming interface is genuinely language-agnostic and not secretly
///        C++-shaped.
///
/// Deliberately diverges from CppBackend where Rust convention differs —
/// `member_name`/`value_name` are real snake_case/SCREAMING_SNAKE_CASE
/// conversions, not a reuse of C++'s lowerCamelCase, and `escape` uses
/// Rust's own keyword list + raw-identifier escaping (`r#...`), not C++'s
/// trailing-underscore convention. `type_name`/`synthetic_name` reuse the
/// same PascalCase transform as CppBackend because ASN.1 type names and
/// Rust struct/enum names both want PascalCase — that overlap is
/// coincidental, not an assumption baked into the interface.
class RustBackend : public Backend {
public:
    std::string type_name(std::string_view asn1_name) const override {
        return to_cpp_name(asn1_name);  // PascalCase strip-hyphens — same convention as Rust structs/enums
    }

    std::string member_name(std::string_view asn1_name,
                             std::initializer_list<std::string_view> extra = {}) const override {
        return rust_escape(to_snake_case(asn1_name), extra);
    }

    std::string value_name(std::string_view asn1_name) const override {
        return to_screaming_snake_case(asn1_name);
    }

    std::string escape(std::string name,
                        std::initializer_list<std::string_view> extra = {}) const override {
        return rust_escape(std::move(name), extra);
    }

    std::string synthetic_name(const std::string& parent,
                                const std::string& member_name) const override {
        return make_synthetic_name(parent, member_name);  // same parent+CapitalizedMember strategy
    }

    std::string native_int_type(IntStorageKind kind) const override {
        switch (kind) {
            case IntStorageKind::U64:       return "u64";
            case IntStorageKind::I128:      return "i128";  // Rust has a real 128-bit type — no C++-style stub
            case IntStorageKind::ARBITRARY: return "Vec<u8>";
            default:                        return "i64";
        }
    }

    // Defined in RustBackend.cpp — real emission logic, not a one-liner
    // like the naming methods above.
    void emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const override;
    void emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const override;
    void emit_integer_hpp(const IntegerSpec& spec, std::ostream& os) const override;
    void emit_integer_cpp(const IntegerSpec& spec, std::ostream& os) const override;
};

} // namespace asn1::codegen
