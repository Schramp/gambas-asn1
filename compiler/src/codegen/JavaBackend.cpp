#include "JavaBackend.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <format>
#include <limits>
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
    case BT::OctetString: return std::format("{}.types.Asn1OctetString", kWire);
    case BT::BitString:   return std::format("{}.types.Asn1BitString", kWire);
    case BT::Utf8String:       return std::format("{}.types.Asn1Utf8String", kWire);
    case BT::NumericString:    return std::format("{}.types.Asn1NumericString", kWire);
    case BT::PrintableString:  return std::format("{}.types.Asn1PrintableString", kWire);
    case BT::T61String:        return std::format("{}.types.Asn1T61String", kWire);
    case BT::VideotexString:   return std::format("{}.types.Asn1VideotexString", kWire);
    case BT::Ia5String:        return std::format("{}.types.Asn1Ia5String", kWire);
    case BT::GraphicString:    return std::format("{}.types.Asn1GraphicString", kWire);
    case BT::VisibleString:    return std::format("{}.types.Asn1VisibleString", kWire);
    case BT::GeneralString:    return std::format("{}.types.Asn1GeneralString", kWire);
    case BT::ObjectDescriptor: return std::format("{}.types.Asn1ObjectDescriptor", kWire);
    case BT::BmpString:        return std::format("{}.types.Asn1BmpString", kWire);
    case BT::UniversalString:  return std::format("{}.types.Asn1UniversalString", kWire);
    case BT::ObjectIdentifier: return std::format("{}.types.Asn1ObjectIdentifier", kWire);
    case BT::RelativeOid:      return std::format("{}.types.Asn1RelativeOid", kWire);
    case BT::UtcTime:          return std::format("{}.types.Asn1UtcTime", kWire);
    case BT::GeneralizedTime:  return std::format("{}.types.Asn1GeneralizedTime", kWire);
    default:          return "";
    }
}

/// @brief Whether `bt` is a restricted character string kind (X.680 §41),
///        held by an `Asn1CharString` subclass.
static bool java_char_string(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Utf8String: case BT::NumericString: case BT::PrintableString: case BT::T61String:
    case BT::VideotexString: case BT::Ia5String: case BT::GraphicString: case BT::VisibleString:
    case BT::GeneralString: case BT::ObjectDescriptor: case BT::BmpString: case BT::UniversalString:
        return true;
    default:
        return false;
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

/// @brief Whether a type assignment's own tag replaces or wraps its
///        builtin's universal tag, so the type must carry its own framing.
static bool has_own_framing(const TaggedTypeSpec& spec) {
    return spec.tag && (spec.is_explicit || spec.tag->cls != ast::TagClass::Universal);
}

std::string JavaBackend::ber_framing_field(const TaggedTypeSpec& spec) const {
    if (!has_own_framing(spec)) return "";
    return std::format("    private static final {0}.spec.BerTagging BER_FRAMING = new {0}.spec.BerTagging.{1}({2});\n",
                       kWire, spec.is_explicit ? "Explicit" : "Implicit", format_tag_literal(*spec.tag));
}

std::string JavaBackend::ber_framing_method(const TaggedTypeSpec& spec) const {
    if (!has_own_framing(spec)) return "";
    return std::format("\n    @java.lang.Override\n"
                       "    public {}.spec.BerTagging berFraming() {{\n"
                       "        return BER_FRAMING;\n"
                       "    }}\n", kWire);
}

/// @brief A `long` literal; Java accepts `-9223372036854775808L` as the one
///        literal whose magnitude alone would not fit.
static std::string java_long(int64_t v) {
    return std::format("{}L", v);
}

/// @brief A runtime `Constraints` constructor call for an INTEGER value
///        range (X.680 §51.5): flags, PER range width (X.691 §10.5) and
///        signed bounds; the remaining fields are unused by INTEGER.
static std::string java_int_constraints(int flags, int range_bits, int64_t lower, int64_t upper) {
    return std::format("new {}.spec.Constraints({}, {}, {}, {}, 0L, 0L, 0, 0L, 0L, null, 0, null, 0, null, 0.0, 0.0)",
                       kWire, flags, range_bits, java_long(lower), java_long(upper));
}

/// @brief A runtime `Constraints` constructor call for a SIZE constraint
///        (X.680 §51.5): flags (SIZE_CONSTRAINED, EXTENSIBLE, NAMED_BITS),
///        PER length width (X.691 §11.9) and bounds. An unbounded upper
///        SIZE is stored as `Long.MAX_VALUE`, as in the other runtimes.
static std::string java_size_constraints(const BuiltinAliasSpec& spec) {
    int flags = (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
              | (spec.has_size_constraint && spec.extensible ? asn1::Constraints::EXTENSIBLE : 0)
              | (spec.named_bits ? asn1::Constraints::NAMED_BITS : 0);
    int64_t upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
    return std::format("new {}.spec.Constraints({}, 0, 0L, 0L, 0L, 0L, {}, {}, {}, null, 0, null, 0, null, 0.0, 0.0)",
                       kWire, flags, spec.size_range_bits, java_long(spec.size_lower), java_long(upper));
}

/// @brief The `xerInstruction()` override for a type with an X.693 §21
///        BASE64 or UTF8 ENCODING-CONTROL instruction, or "" without one.
static std::string java_xer_instruction(ast::XerEncoding enc) {
    const char* name = enc == ast::XerEncoding::Base64 ? "BASE64" : enc == ast::XerEncoding::Utf8 ? "UTF8" : nullptr;
    if (!name) return "";
    return std::format("\n    @java.lang.Override\n"
                       "    public {0}.spec.XerInstruction xerInstruction() {{\n"
                       "        return {0}.spec.XerInstruction.{1};\n"
                       "    }}\n", kWire, name);
}

/// @brief Emit the members every value-holding generated class shares:
///        the `AsMemberRef` answers for a builtin wrapped in `value`.
/// @param os       The `.java` buffer.
/// @param cls      Fully qualified runtime wrapper class.
/// @param xer_name The type's own XER element name (X.693 §12).
/// @param framing  `ber_framing_method`'s text.
static void emit_primitive_holder(std::ostream& os, const std::string& cls, const std::string& xer_name,
                                  const std::string& framing) {
    os << std::format("    public final {0} value = new {0}();\n\n", cls);
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef asMemberRef() {{\n", kWire);
    os << std::format("        return new {}.spec.MemberRef.Primitive(value);\n", kWire);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public java.lang.String ownElementXerName() {\n";
    os << std::format("        return \"{}\";\n", xer_name);
    os << "    }\n";
    os << framing;
    os << "}\n";
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
    using BT = ast::BuiltinType;
    // SIZE applies to the string kinds (X.680 §51.5): OCTET STRING, BIT
    // STRING and every restricted character string.
    bool sizeable = spec.builtin_type == BT::OctetString || spec.builtin_type == BT::BitString
                 || java_char_string(spec.builtin_type);
    os << std::format("    public static final {0}.spec.Constraints CONSTRAINTS = {1};\n", kWire,
                      sizeable ? java_size_constraints(spec) : std::format("{}.spec.Constraints.UNCONSTRAINED", kWire));
    os << ber_framing_field(spec) << "\n";
    emit_primitive_holder(os, cls, spec.xer_name, java_xer_instruction(spec.xer_encoding) + ber_framing_method(spec));
}

/// @brief Emit an INTEGER type assignment (X.680 §19) as a class holding
///        the runtime's `Asn1Integer`, with its value-range `CONSTRAINTS`
///        table and one `long` constant per named number (X.680 §19.1).
/// @param spec    Resolved storage, named numbers, range and tag.
/// @param session Per-type output session; writes the `.java` buffer.
/// @throws std::logic_error for storage wider than signed 64 bits.
void JavaBackend::emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const {
    if (spec.storage_kind != IntStorageKind::S64)
        throw std::logic_error(std::format("emit_integer: {} storage beyond signed 64 bits is not implemented for this backend",
                                           spec.asn1_name.empty() ? spec.type_name : spec.asn1_name));
    bool semi = spec.semi_constrained || spec.hi_is_large;
    int flags = (spec.has_constraint ? (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED) : 0)
              | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public final class {} implements {}.spec.AsMemberRef {{\n", spec.type_name, kWire);
    os << std::format("    public static final {}.spec.Constraints CONSTRAINTS = {};\n", kWire,
                      java_int_constraints(flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64));
    os << ber_framing_field(spec);
    for (const auto& nv : spec.named_values) {
        os << std::format("    /** ASN.1: {{@code {}}} */\n", nv.asn1_name);
        os << std::format("    public static final long {} = {};\n",
                          escape(value_name(nv.asn1_name), {"value", "CONSTRAINTS", "BER_FRAMING"}), java_long(nv.value));
    }
    os << "\n";
    emit_primitive_holder(os, std::format("{}.types.Asn1Integer", kWire), spec.xer_name, ber_framing_method(spec));
}

/// @brief Emit an ENUMERATED type assignment (X.680 §20) as a class whose
///        nested Java enum names the items in declaration order, with the
///        `ENUM_SPEC` table (items sorted by value, X.691 §11.4) and the
///        `EnumSlot` mapping between items and their values.
/// @param spec    Resolved items, extensibility and tag.
/// @param session Per-type output session; writes the `.java` buffer.
void JavaBackend::emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const {
    if (spec.values.empty())
        throw std::logic_error(std::format("emit_enumerated: {} has no items", spec.type_name));
    const std::string& t = spec.type_name;
    // A member type may not share its enclosing class's simple name (JLS §8.1).
    std::string item_type = escape("Value", {t});
    size_t root_count = spec.root_count > 0 ? static_cast<size_t>(spec.root_count) : spec.sorted_values.size();
    unsigned root_bits = 0;
    for (size_t r = root_count > 1 ? root_count - 1 : 0; r > 0; r >>= 1) ++root_bits;

    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public final class {} implements {}.spec.AsMemberRef, {}.spec.EnumSlot {{\n", t, kWire, kWire);
    os << std::format("    public static final {0}.spec.EnumSpec ENUM_SPEC = new {0}.spec.EnumSpec(\"{1}\", java.util.List.of(\n",
                      kWire, spec.xer_name);
    for (size_t i = 0; i < spec.sorted_values.size(); ++i) {
        const auto& v = spec.sorted_values[i];
        os << std::format("            new {}.spec.EnumEntry({}, \"{}\"){}\n", kWire, java_long(v.value), v.asn1_name,
                          i + 1 < spec.sorted_values.size() ? "," : "),");
    }
    os << std::format("            {}, {}, {});\n", spec.extensible ? "true" : "false", root_count, root_bits);
    os << ber_framing_field(spec) << "\n";

    os << "    /** The items, in declaration order. */\n";
    os << std::format("    public enum {} {{\n", item_type);
    for (size_t i = 0; i < spec.values.size(); ++i) {
        os << std::format("        /** ASN.1: {{@code {}}} */\n", spec.values[i].asn1_name);
        os << std::format("        {}{}\n", escape(value_name(spec.values[i].asn1_name)), i + 1 < spec.values.size() ? "," : "");
    }
    os << "    }\n\n";
    os << std::format("    private static final {0}[] ITEMS = {0}.values();\n", item_type);
    os << "    private static final long[] CODES = {";
    for (size_t i = 0; i < spec.values.size(); ++i) os << (i ? ", " : "") << java_long(spec.values[i].value);
    os << "};\n\n";
    os << std::format("    private {0} value = {0}.{1};\n\n", item_type, escape(value_name(spec.values.front().asn1_name)));
    os << std::format("    public {} get() {{\n        return value;\n    }}\n\n", item_type);
    os << std::format("    public void set({} item) {{\n        value = java.util.Objects.requireNonNull(item);\n    }}\n\n", item_type);
    os << "    @java.lang.Override\n";
    os << "    public long enumGet() {\n        return CODES[value.ordinal()];\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public boolean enumSet(long code) {\n";
    os << "        for (int i = 0; i < CODES.length; i++) {\n";
    os << "            if (CODES[i] == code) {\n";
    os << "                value = ITEMS[i];\n";
    os << "                return true;\n";
    os << "            }\n";
    os << "        }\n";
    os << "        return false;\n";
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef asMemberRef() {{\n", kWire);
    os << std::format("        return new {}.spec.MemberRef.Enumerated(this, ENUM_SPEC);\n", kWire);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public java.lang.String ownElementXerName() {\n";
    os << std::format("        return \"{}\";\n", spec.xer_name);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public boolean equals(java.lang.Object o) {\n";
    os << std::format("        return o instanceof {} other && other.value == value;\n", t);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public int hashCode() {\n        return value.hashCode();\n    }\n";
    os << ber_framing_method(spec);
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
