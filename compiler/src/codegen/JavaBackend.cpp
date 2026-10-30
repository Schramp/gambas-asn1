#include "JavaBackend.hpp"
#include <format>
#include <stdexcept>

namespace asn1::codegen {

// Generated code names every runtime and java.lang type by its fully
// qualified name, so a generated type called String, Override or
// Asn1Boolean in the same package cannot shadow it.
static constexpr const char* kWire = "io.github.schramp.gambasasn1.wire";

/// @brief The runtime wrapper class for a builtin a type assignment
///        aliases, fully qualified.
/// @param bt The aliased builtin.
/// @return The wrapper's class name, or "" for a builtin this backend
///         does not emit yet.
static std::string java_builtin_class(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Boolean: return std::format("{}.types.Asn1Boolean", kWire);
    case BT::Null:    return std::format("{}.types.Asn1Null", kWire);
    default:          return "";
    }
}

/// @brief Format a resolved tag as a runtime `Tag` constructor call.
/// @param tag_spec Tag class, number and constructed bit.
/// @return A `new ...ber.Tag(TagClass.X, n, constructed)` expression.
/// @see X.690 §8.1.2 — identifier octets.
std::string JavaBackend::format_tag_literal(const TypeTagSpec& tag_spec) const {
    static constexpr const char* kClass[4] = {"UNIVERSAL", "APPLICATION", "PRIVATE", "CONTEXT"};
    return std::format("new {0}.ber.Tag({0}.ber.TagClass.{1}, {2}, {3})", kWire,
                       kClass[tag_class_index(tag_spec.cls)], tag_spec.number,
                       tag_spec.constructed ? "true" : "false");
}

/// @brief Emit a builtin type assignment (`Flag ::= BOOLEAN`, X.680 §16.1)
///        as a class holding the runtime's builtin wrapper. Its tables are
///        the `AsMemberRef` answers: the wrapped builtin for every codec
///        walker, the alias's own XER name, and its own BER framing when
///        its tag is not the builtin's universal tag (X.680 §31.2).
/// @param spec    Resolved, backend-agnostic decision (see BuiltinAliasSpec).
/// @param session Per-type output session; writes the `.java` buffer.
/// @throws std::logic_error for a builtin this backend does not emit yet.
void JavaBackend::emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const {
    std::string cls = java_builtin_class(spec.builtin_type);
    if (cls.empty())
        throw std::logic_error(std::format("emit_builtin_alias: {} is not implemented for this backend",
                                           spec.asn1_name.empty() ? spec.type_name : spec.asn1_name));
    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public final class {} implements {}.spec.AsMemberRef {{\n", spec.type_name, kWire);
    os << std::format("    public static final {0}.spec.Constraints CONSTRAINTS = {0}.spec.Constraints.UNCONSTRAINED;\n", kWire);
    bool own_framing = spec.tag && (spec.is_explicit || spec.tag->cls != ast::TagClass::Universal);
    if (own_framing)
        os << std::format("    private static final {0}.spec.BerTagging BER_FRAMING = new {0}.spec.BerTagging.{1}({2});\n",
                          kWire, spec.is_explicit ? "Explicit" : "Implicit", format_tag_literal(*spec.tag));
    os << "\n";
    os << std::format("    public final {0} value = new {0}();\n\n", cls);
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef asMemberRef() {{\n", kWire);
    os << std::format("        return new {}.spec.MemberRef.Primitive(value);\n", kWire);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public java.lang.String ownElementXerName() {\n";
    os << std::format("        return \"{}\";\n", spec.xer_name);
    os << "    }\n";
    if (own_framing) {
        os << "\n    @java.lang.Override\n";
        os << std::format("    public {}.spec.BerTagging berFraming() {{\n", kWire);
        os << "        return BER_FRAMING;\n";
        os << "    }\n";
    }
    os << "}\n";
}

/// @brief Emit a generated compilation unit's header: a comment naming
///        the ASN.1 module, then the `package` declaration (JLS §7.4).
/// @param module_comment ASN.1 module name, with its OID when it has one.
/// @param session        Per-type output session; writes the `.java` buffer.
void JavaBackend::emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const {
    auto& os = session.buffer(declaration_extension());
    os << "// Module: " << module_comment << "\n\n";
    if (!package_.empty()) os << "package " << package_ << ";\n\n";
}

/// @brief Emit the implementation-half preamble: nothing, since the
///        declaration and definition share one `.java` file whose header
///        `emit_declaration_preamble` already wrote.
/// @param declaration_filename Unused.
/// @param session              Unused.
void JavaBackend::emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const {
    (void)declaration_filename;
    (void)session;
}

/// @brief Check a `--package` value against the Java package-name grammar.
/// @param pkg Candidate package name.
/// @return True when every dot-separated part is a Java identifier that
///         `java_escape` leaves unchanged.
/// @see JLS §6.5.3, §7.4.1 — package names.
bool JavaBackend::valid_package(std::string_view pkg) {
    if (pkg.empty()) return false;
    std::size_t start = 0;
    while (true) {
        auto dot = pkg.find('.', start);
        auto part = pkg.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (part.empty()) return false;
        if (!std::isalpha((unsigned char)part[0]) && part[0] != '_' && part[0] != '$') return false;
        for (char c : part)
            if (!std::isalnum((unsigned char)c) && c != '_' && c != '$') return false;
        if (java_escape(std::string(part)) != part) return false;
        if (dot == std::string_view::npos) return true;
        start = dot + 1;
    }
}

} // namespace asn1::codegen
