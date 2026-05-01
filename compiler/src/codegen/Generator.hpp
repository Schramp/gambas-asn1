#pragma once
#include <string>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <format>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"
#include "../ast/Tag.hpp"
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

// C++ keywords that cannot be used as identifiers — append underscore if matched.
inline std::string safe_member_name(std::string n) {
    static const std::unordered_set<std::string> kw = {
        "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool",
        "break","case","catch","char","char8_t","char16_t","char32_t","class",
        "compl","concept","const","consteval","constexpr","constinit","const_cast",
        "continue","co_await","co_return","co_yield","decltype","default","delete",
        "do","double","dynamic_cast","else","enum","explicit","export","extern",
        "false","float","for","friend","goto","if","inline","int","long","mutable",
        "namespace","new","noexcept","not","not_eq","nullptr","operator","or",
        "or_eq","private","protected","public","register","reinterpret_cast",
        "requires","return","short","signed","sizeof","static","static_assert",
        "static_cast","struct","switch","template","this","thread_local","throw",
        "true","try","typedef","typeid","typename","union","unsigned","using",
        "virtual","void","volatile","wchar_t","while","xor","xor_eq"
    };
    return kw.count(n) ? n + "_" : n;
}

// Converts a member (identifier) name: first letter lower-case, escapes keywords.
inline std::string to_member_name(std::string_view s) {
    auto n = to_cpp_name(s);
    if (!n.empty()) n[0] = (char)std::tolower(n[0]);
    return safe_member_name(std::move(n));
}

// Converts a named-value (INTEGER constant) name: hyphens → underscores, matching asn1c.
inline std::string to_value_name(std::string_view s) {
    std::string out;
    for (char c : s)
        out += (c == '-') ? '_' : c;
    return out;
}

class Generator {
    fs::path                out_dir_;
    sema::Resolver&         resolver_;
    std::set<std::string>   generated_names_;
    std::set<std::string>   referenced_names_;
    std::set<std::string>   collision_types_;   // ASN.1 type names defined in >1 module
    std::string             current_module_;    // module being generated right now
    std::string             current_type_;      // C++ name of type currently being generated

public:
    Generator(fs::path out_dir, sema::Resolver& res)
        : out_dir_(std::move(out_dir)), resolver_(res) {}

    void generate(const ast::ParseResult& pr) {
        fs::create_directories(out_dir_);

        // First pass: detect type-name collisions across modules
        std::unordered_map<std::string, std::string> first_module;
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker) {
                    auto [it, inserted] = first_module.emplace(def->name, mod->name);
                    if (!inserted && it->second != mod->name)
                        collision_types_.insert(def->name);
                }

        for (const auto& mod : pr.modules) {
            current_module_ = mod->name;
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker) {
                    generated_names_.insert(effective_cpp_name(def->name, mod->name));
                    generate_inline_types(*def, *mod);
                    generate_type(*def, *mod);
                }
        }
        emit_stubs_for_unresolved();
    }

    // Returns the C++ name to use for a type, prefixing with module when colliding.
    std::string effective_cpp_name(const std::string& asn_name,
                                   const std::string& mod_name) const {
        if (!collision_types_.count(asn_name))
            return to_cpp_name(asn_name);
        return to_cpp_name(mod_name) + to_cpp_name(asn_name);
    }

    // Returns the C++ name for a TypeRef encountered in `from_module`.
    std::string cpp_name_for_ref(const std::string& type_name,
                                 const std::string& from_module) const {
        if (!collision_types_.count(type_name))
            return to_cpp_name(type_name);
        std::string def_mod = resolver_.module_of(type_name, from_module);
        if (def_mod.empty()) return to_cpp_name(type_name);
        return to_cpp_name(def_mod) + to_cpp_name(type_name);
    }

    // Returns the C++ name for a fully qualified TypeRef.
    // When module_name is set and the type is a collision type, uses module_name
    // directly instead of resolving through from_module imports.
    std::string cpp_name_for_typeref(const ast::TypeRef& tr) const {
        if (!tr.module_name.empty() && collision_types_.count(tr.type_name))
            return effective_cpp_name(tr.type_name, tr.module_name);
        return cpp_name_for_ref(tr.type_name, current_module_);
    }

private:
    void generate_type(const ast::TypeDef& def, const ast::Module& mod);
    void generate_inline_types(const ast::TypeDef& def, const ast::Module& mod);
    void emit_stubs_for_unresolved();
    void track_include(const std::string& cname) { referenced_names_.insert(cname); }
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
    std::string type_descriptor_ref_for(const ast::TypeDef& def);
    std::string tag_literal(const ast::Tag& tag, bool constructed);
    std::string natural_tag_for(const ast::TypeDef& def);
    std::optional<int64_t> resolve_int_value(const ast::Value& v) const;
    std::optional<std::pair<int64_t,int64_t>> extract_integer_range(const ast::TypeDef& def) const;
};

} // namespace asn1::codegen
