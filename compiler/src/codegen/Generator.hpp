#pragma once
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <format>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"
#include "../sema/Resolver.hpp"
#include <optional>
#include <limits>

namespace asn1::codegen {

namespace fs = std::filesystem;

// Converts an ASN.1 type name to a valid C++ identifier.
// "My-Type" -> "MyType"
inline std::string to_cpp_name(std::string_view s) {
    std::string out;
    bool upper_next = false;
    for (char c : s) {
        if (c == '-') { upper_next = true; continue; }
        if (upper_next) { out += (char)std::toupper(c); upper_next = false; }
        else out += c;
    }
    return out;
}

// Converts a member (identifier) name: first letter lower-case
inline std::string to_member_name(std::string_view s) {
    auto n = to_cpp_name(s);
    if (!n.empty()) n[0] = (char)std::tolower(n[0]);
    return n;
}

// Converts a named-value (INTEGER constant) name: hyphens → underscores, matching asn1c.
inline std::string to_value_name(std::string_view s) {
    std::string out;
    for (char c : s)
        out += (c == '-') ? '_' : c;
    return out;
}

class Generator {
    fs::path          out_dir_;
    sema::Resolver&   resolver_;

public:
    Generator(fs::path out_dir, sema::Resolver& res)
        : out_dir_(std::move(out_dir)), resolver_(res) {}

    void generate(const ast::ParseResult& pr) {
        fs::create_directories(out_dir_);
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker)
                    generate_type(*def, *mod);
    }

private:
    void generate_type(const ast::TypeDef& def, const ast::Module& mod);
    void emit_hpp(const ast::TypeDef& def, const ast::Module& mod, std::ostream& os);
    void emit_cpp(const ast::TypeDef& def, std::ostream& os);

    void emit_enumerated_hpp(const ast::TypeDef& def, std::ostream& os);
    void emit_enumerated_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_integer_hpp(const ast::TypeDef& def, std::ostream& os);
    void emit_integer_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_builtin_alias_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_sequence_hpp(const ast::TypeDef& def, std::ostream& os);
    void emit_sequence_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_seq_of_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_choice_hpp(const ast::TypeDef& def, std::ostream& os);
    void emit_choice_cpp(const ast::TypeDef& def, std::ostream& os);

    std::string cpp_type_for(const ast::TypeDef& def);
    std::string tag_literal(const ast::Tag& tag, bool constructed);
    std::string natural_tag_for(const ast::TypeDef& def);
    std::optional<int64_t> resolve_int_value(const ast::Value& v) const;
    std::optional<std::pair<int64_t,int64_t>> extract_integer_range(const ast::TypeDef& def) const;
};

} // namespace asn1::codegen
