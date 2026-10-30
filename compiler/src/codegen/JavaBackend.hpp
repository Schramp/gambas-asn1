#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / to_value_name / make_synthetic_name — the shared no-recase transliteration
#include <cctype>
#include <string>
#include <unordered_set>

namespace asn1::codegen {

/// @brief Escape an identifier that collides with a Java keyword, a
///        contextual keyword, or any name in `extra`, so a generated name
///        stays the ASN.1 name whenever Java allows it.
/// @param n     Transliterated ASN.1 name.
/// @param extra Additional reserved names to escape against.
/// @return `n` unchanged, else `n` with a trailing underscore. No
///         transliterated ASN.1 name ends in `_`, since a typereference or
///         identifier never ends in a hyphen (X.680 §11.2, §11.3), so the
///         escaped name cannot collide with another generated one.
/// @see JLS 21 §3.9 — reserved keywords, the literals `true`/`false`/`null`,
///      and the contextual keywords. The contextual ones are escaped too,
///      even where Java would accept them (a field named `record`), so one
///      rule holds for every naming surface: `var`, `yield`, `record`,
///      `sealed` and `permits` are rejected as type names.
inline std::string java_escape(std::string n,
                                std::initializer_list<std::string_view> extra = {}) {
    static const std::unordered_set<std::string> kw = {
        "abstract","assert","boolean","break","byte","case","catch","char",
        "class","const","continue","default","do","double","else","enum",
        "extends","final","finally","float","for","goto","if","implements",
        "import","instanceof","int","interface","long","native","new",
        "package","private","protected","public","return","short","static",
        "strictfp","super","switch","synchronized","this","throw","throws",
        "transient","try","void","volatile","while","_",
        "true","false","null",
        "exports","module","non-sealed","open","opens","permits","provides",
        "record","requires","sealed","to","transitive","uses","var","when",
        "with","yield",
    };
    if (kw.count(n)) return n + "_";
    for (auto e : extra) if (n == e) return n + "_";
    return n;
}

/// @brief Java backend: the third `Backend` implementation, emitting one
///        `.java` compilation unit per ASN.1 type for the table-driven
///        runtime in `java-runtime/`.
///
/// Naming is the same minimal transliteration CppBackend and RustBackend
/// use (hyphen -> underscore, first letter lowered for members, no recase);
/// only keyword escaping is Java's own (`java_escape`). Construct emitters
/// are not implemented yet and inherit Backend's throw-by-default, so a
/// schema using one fails loudly naming the missing construct.
class JavaBackend : public Backend {
public:
    /// @param package Java package every generated compilation unit
    ///                declares (`--package`); empty for the unnamed package.
    explicit JavaBackend(std::string package = {}) : package_(std::move(package)) {}

    std::string type_name(std::string_view asn1_name) const override {
        return java_escape(to_cpp_name(asn1_name));
    }

    std::string member_name(std::string_view asn1_name,
                             std::initializer_list<std::string_view> extra = {}) const override {
        auto n = to_cpp_name(asn1_name);
        if (!n.empty()) n[0] = (char)std::tolower((unsigned char)n[0]);
        return java_escape(std::move(n), extra);
    }

    std::string value_name(std::string_view asn1_name) const override {
        return java_escape(to_value_name(asn1_name));
    }

    std::string escape(std::string name,
                        std::initializer_list<std::string_view> extra = {}) const override {
        return java_escape(std::move(name), extra);
    }

    std::string synthetic_name(const std::string& parent,
                                const std::string& member_name) const override {
        return make_synthetic_name(parent, member_name);
    }

    std::string member_descriptor_base_name(const std::string& parent_cname,
                                              const std::string& mname) const override {
        return parent_cname + "_" + mname;
    }

    std::string format_tag_literal(const TypeTagSpec& tag_spec) const override;

    void emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const override;
    void emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const override;
    void emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const override;
    void emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const override;
    void emit_type_reference(const std::string& type_name, const std::string& filename,
                             TypeOutputSession& session) const override;
    std::string native_int_type(IntStorageKind kind) const override;
    std::string native_builtin_type(ast::BuiltinType bt) const override;
    void emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const override;
    void emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const override;

    /// A compilation unit holds one top-level class (JLS §7.6), so
    /// declaration and definition share one `.java` file.
    std::string declaration_extension() const override { return "java"; }
    std::string definition_extension() const override { return "java"; }

    /// @brief Whether `pkg` is a valid `--package` value: dot-separated
    ///        Java identifiers, none of them a keyword (JLS §7.4.1).
    static bool valid_package(std::string_view pkg);

private:
    std::string package_;

    /// @brief The `BER_FRAMING` constant of a type assignment whose own
    ///        tag is not its builtin's universal tag (X.680 §31.2).
    /// @return The field declaration, or "" when the builtin's own tag applies.
    std::string ber_framing_field(const TaggedTypeSpec& spec) const;

    /// @brief The `berFraming()` override returning `BER_FRAMING`, or "" when
    ///        `ber_framing_field` emitted none.
    std::string ber_framing_method(const TaggedTypeSpec& spec) const;
};

} // namespace asn1::codegen
