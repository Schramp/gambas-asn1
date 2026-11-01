#include "JavaBackend.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
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
    case BT::Real:             return std::format("{}.types.Asn1Real", kWire);
    case BT::Any:              return std::format("{}.types.Asn1Any", kWire);
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
    return std::format("    public static final {0}.spec.BerTagging BER_FRAMING = new {0}.spec.BerTagging.{1}({2});\n",
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
static std::string java_int_constraints(int flags, int range_bits, int64_t lower, int64_t upper,
                                       uint64_t lower_u64 = 0, uint64_t upper_u64 = 0) {
    return std::format("new {}.spec.Constraints({}, {}, {}, {}, {}, {}, 0, 0L, 0L, null, 0, null, 0, null, 0.0, 0.0)",
                       kWire, flags, range_bits, java_long(lower), java_long(upper),
                       java_long(static_cast<int64_t>(lower_u64)), java_long(static_cast<int64_t>(upper_u64)));
}

/// @brief A `double` literal: shortest round-trip digits, or the infinity
///        constants of `java.lang.Double`.
/// @param d Finite or infinite value (never NaN).
static std::string java_double(double d) {
    if (std::isinf(d)) return d > 0 ? "java.lang.Double.POSITIVE_INFINITY" : "java.lang.Double.NEGATIVE_INFINITY";
    std::string f = std::format("{}", d);
    if (f.find_first_of(".e") == std::string::npos) f += ".0";
    return f;
}

/// @brief A runtime `Constraints` constructor call for a REAL: its value
///        range (X.680 §47.4) and whether its JER-visible base constraint
///        admits only base 10 (X.697 §23.1.4); the other fields are unused
///        by REAL.
static std::string java_real_constraints(const RealRangeSpec& r) {
    int flags = (r.present ? asn1::Constraints::REAL_RANGE : 0)
              | (r.base10_only ? asn1::Constraints::REAL_BASE_10 : 0)
              | (r.lower_open ? asn1::Constraints::REAL_LOWER_OPEN : 0)
              | (r.upper_open ? asn1::Constraints::REAL_UPPER_OPEN : 0)
              | (r.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    return std::format("new {}.spec.Constraints({}, 0, 0L, 0L, 0L, 0L, 0, 0L, 0L, null, 0, null, 0, null, {}, {})",
                       kWire, flags, java_double(r.lower), java_double(r.upper));
}

/// @brief A runtime `Constraints` constructor call for a SIZE constraint
///        (X.680 §51.5): flags (SIZE_CONSTRAINED, EXTENSIBLE, NAMED_BITS),
///        PER length width (X.691 §11.9) and bounds. An unbounded upper
///        SIZE is stored as `Long.MAX_VALUE`, as in the other runtimes.
///        A permitted alphabet (X.680 §51.7) adds its sorted characters
///        and their PER width (X.691 §30.5.2), from which the runtime
///        builds the character-to-index table.
template <class S>
static std::string java_size_constraints(const S& spec) {
    int flags = (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
              | (spec.has_size_constraint && spec.extensible ? asn1::Constraints::EXTENSIBLE : 0)
              | (spec.named_bits ? asn1::Constraints::NAMED_BITS : 0);
    int64_t upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
    std::string c = std::format("new {}.spec.Constraints({}, 0, 0L, 0L, 0L, 0L, {}, {}, {}, null, 0, null, 0, null, 0.0, 0.0)",
                                kWire, flags, spec.size_range_bits, java_long(spec.size_lower), java_long(upper));
    if (spec.alphabet.empty()) return c;
    std::string chars;
    for (std::size_t i = 0; i < spec.alphabet.size(); ++i)
        chars += std::format("{}(byte) 0x{:02X}", i ? ", " : "", spec.alphabet[i]);
    return std::format("{0}.spec.Constraints.withAlphabet({1}, {2}, new byte[] {{{3}}})", kWire, c,
                       Backend::alphabet_bits_for(static_cast<int>(spec.alphabet.size())), chars);
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

/// @brief The `XerInstruction` constant of a SEQUENCE/SET member or CHOICE
///        alternative row: the X.693 §21 BASE64/UTF8 instruction on its own
///        OCTET STRING, or on the named OCTET STRING type it references.
static std::string java_member_xer_instruction(const TaggedMemberSpec& m) {
    ast::XerEncoding enc = ast::XerEncoding::Default;
    if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::OctetString) enc = m.xer_encoding;
    else if (!m.mbuiltin && m.ref_builtin_alias && *m.ref_builtin_alias == ast::BuiltinType::OctetString)
        enc = m.ref_xer_encoding;
    const char* name = enc == ast::XerEncoding::Base64 ? "BASE64" : enc == ast::XerEncoding::Utf8 ? "UTF8" : "DEFAULT";
    return std::format("{}.spec.XerInstruction.{}", kWire, name);
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
///        its tag is not the builtin's universal tag (X.680 §31.2). Its
///        `CONSTRAINTS` holds the SIZE of a string kind or the value range
///        and JER base constraint of a REAL.
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
    os << std::format("public class {} implements {}.spec.AsMemberRef {{\n", spec.type_name, kWire);
    using BT = ast::BuiltinType;
    // SIZE applies to the string kinds (X.680 §51.5): OCTET STRING, BIT
    // STRING and every restricted character string.
    bool sizeable = spec.builtin_type == BT::OctetString || spec.builtin_type == BT::BitString
                 || java_char_string(spec.builtin_type);
    std::string constraints = std::format("{}.spec.Constraints.UNCONSTRAINED", kWire);
    if (sizeable) constraints = java_size_constraints(spec);
    else if (spec.builtin_type == BT::Real) constraints = java_real_constraints(spec.real_range);
    os << std::format("    public static final {0}.spec.Constraints CONSTRAINTS = {1};\n", kWire, constraints);
    os << ber_framing_field(spec) << "\n";
    emit_primitive_holder(os, cls, spec.xer_name, java_xer_instruction(spec.xer_encoding) + ber_framing_method(spec));
}

/// @brief Emit an INTEGER type assignment (X.680 §19) as a class holding
///        the runtime's `Asn1Integer` (signed 64-bit storage) or
///        `Asn1UInteger` (unsigned 64-bit storage), with its value-range
///        `CONSTRAINTS` table and one `long` constant per named number
///        (X.680 §19.1). Unsigned storage also fills the table's unsigned
///        bounds, upper `UINT64_MAX` when semi-constrained.
/// @param spec    Resolved storage, named numbers, range and tag.
/// @param session Per-type output session; writes the `.java` buffer.
/// @throws std::logic_error for storage wider than 64 bits.
void JavaBackend::emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const {
    bool u64 = spec.storage_kind == IntStorageKind::U64;
    if (spec.storage_kind != IntStorageKind::S64 && !u64)
        throw std::logic_error(std::format("emit_integer: {} storage beyond 64 bits is not implemented for this backend",
                                           spec.asn1_name.empty() ? spec.type_name : spec.asn1_name));
    int flags = (spec.has_constraint ? (spec.semi_constrained ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED) : 0)
              | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    uint64_t upper_u64 = spec.semi_constrained ? std::numeric_limits<uint64_t>::max() : spec.upper_u64;
    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public class {} implements {}.spec.AsMemberRef {{\n", spec.type_name, kWire);
    os << std::format("    public static final {}.spec.Constraints CONSTRAINTS = {};\n", kWire,
                      java_int_constraints(flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64,
                                           u64 ? spec.lower_u64 : 0, u64 ? upper_u64 : 0));
    os << ber_framing_field(spec);
    for (const auto& nv : spec.named_values) {
        os << std::format("    /** ASN.1: {{@code {}}} */\n", nv.asn1_name);
        os << std::format("    public static final long {} = {};\n",
                          escape(value_name(nv.asn1_name), {"value", "CONSTRAINTS", "BER_FRAMING"}), java_long(nv.value));
    }
    os << "\n";
    emit_primitive_holder(os, std::format("{}.types.{}", kWire, u64 ? "Asn1UInteger" : "Asn1Integer"), spec.xer_name,
                          ber_framing_method(spec));
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
    os << std::format("public class {} implements {}.spec.AsMemberRef, {}.spec.EnumSlot {{\n", t, kWire, kWire);
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

/// @brief The runtime class holding an INTEGER member or alternative:
///        `Asn1Integer` for signed, `Asn1UInteger` for unsigned 64-bit
///        storage, fully qualified.
/// @param kind Storage chosen by Generator's constraint analysis.
/// @throws std::logic_error for storage wider than 64 bits.
std::string JavaBackend::native_int_type(IntStorageKind kind) const {
    if (kind == IntStorageKind::S64) return std::format("{}.types.Asn1Integer", kWire);
    if (kind == IntStorageKind::U64) return std::format("{}.types.Asn1UInteger", kWire);
    throw std::logic_error("native_int_type: INTEGER storage beyond 64 bits is not implemented for this backend");
}

/// @brief The runtime wrapper class holding a builtin member or
///        alternative, fully qualified (see `java_builtin_class`).
/// @param bt The member's builtin type.
/// @throws std::logic_error for a builtin this backend does not hold yet.
std::string JavaBackend::native_builtin_type(ast::BuiltinType bt) const {
    std::string cls = java_builtin_class(bt);
    if (cls.empty()) throw std::logic_error("native_builtin_type: builtin not implemented for this backend");
    return cls;
}

/// @brief The Java type of a SEQUENCE OF / SET OF member, level by level
///        from its ElemShape: `SeqOf` or `SetOf` (X.680 §25, §27) around
///        the element type.
/// @param kind  The collection kind at this level.
/// @param elem  The element's shape.
static std::string java_collection_type(SeqOfKind kind, const ElemShape& elem) {
    std::string inner = elem.kind == SeqOfKind::None ? elem.leaf_native_type
                                                     : java_collection_type(elem.kind, *elem.nested);
    return std::format("{}.spec.{}<{}>", kWire, kind == SeqOfKind::SetOf ? "SetOf" : "SeqOf", inner);
}

/// @brief A new, empty collection of a SEQUENCE OF / SET OF member, with
///        the factory of its elements (nested collections included).
static std::string java_collection_new(SeqOfKind kind, const ElemShape& elem) {
    std::string factory = elem.kind == SeqOfKind::None ? elem.leaf_native_type + "::new"
                                                       : "() -> " + java_collection_new(elem.kind, *elem.nested);
    return std::format("new {}.spec.{}<>({})", kWire, kind == SeqOfKind::SetOf ? "SetOf" : "SeqOf", factory);
}

/// @brief Emit a CHOICE type assignment (X.680 §28) as a class holding the
///        selected alternative's index and value, and the `SPEC` table:
///        one `AltMeta` row per alternative in Generator's canonical
///        order, the `berTags` dispatch sorted by (class, number) (an
///        untagged CHOICE alternative contributes its own alternatives'
///        tags, X.690 §8.13), the type's own tag (always EXPLICIT, X.680
///        §31.2.7), `extAt` and `rangeBits` (X.691 §23.6). Each
///        alternative gets a getter (its value, or null when another is
///        selected) and a setter that selects it, both named after the
///        alternative.
/// @param spec    Resolved alternatives, tags and dispatch table.
/// @param session Per-type output session; writes the `.java` buffer.
/// @throws std::logic_error for an alternative shape this backend does
///         not emit yet.
void JavaBackend::emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const {
    const std::string& t = spec.type_name;
    // Row framing (X.690 §8.14), as in the other backends: a tag of the
    // alternative's own wraps (EXPLICIT) or replaces (IMPLICIT) the
    // value's; a reference to a CHOICE, tagged or not, frames itself; a
    // reference to an EXPLICIT-tagged builtin or ENUMERATED type
    // assignment points at that type's framing (X.680 §31.2); otherwise
    // the resolved tag is the value's own.
    auto framing = [&](const ChoiceAlternativeSpec& a) {
        bool is_choice_ref = !a.mbuiltin && a.ref_kind == TaggedMemberSpec::RefTargetKind::Other
                          && !a.ref_builtin_alias && !a.ref_is_sequence_or_set && !a.ref_is_seq_of;
        const auto& rt = a.resolved_tag;
        if (rt && rt->tag_is_override)
            return std::format("new {}.spec.BerTagging.{}({})", kWire, a.is_explicit ? "Explicit" : "Implicit",
                               format_tag_literal(*rt));
        if (is_choice_ref || !rt || (!a.mbuiltin && a.ref_is_sequence_or_set)) return std::format("{}.spec.BerTagging.DELEGATE", kWire);
        if (a.seq_of_kind != SeqOfKind::None) return std::format("new {}.spec.BerTagging.Implicit({})", kWire, format_tag_literal(*rt));
        if (a.is_explicit)
            return std::format("new {0}.spec.BerTagging.OfType({1}.BER_FRAMING)", kWire,
                               a.contained ? a.contained_base : a.mtype);
        return std::format("new {}.spec.BerTagging.Implicit({})", kWire, format_tag_literal(*rt));
    };
    // An inline constraint is the alternative's own table, emitted by
    // emit_member_type_descriptor; a reference uses its type's table.
    auto constraints = [&](const ChoiceAlternativeSpec& a) {
        if (!a.tdref.empty()) return a.tdref + ".CONSTRAINTS";
        if (a.contained) return a.contained_base + ".CONSTRAINTS";
        if (a.seq_of_kind != SeqOfKind::None)
            return std::format("{}.CONSTRAINTS", escape(synthetic_name(spec.type_name, a.asn1_name)));
        if (!a.mbuiltin && a.ref_is_seq_of) return std::format("{}.CONSTRAINTS", a.mtype);
        if (!a.mbuiltin && (a.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias || a.ref_builtin_alias))
            return std::format("{}.CONSTRAINTS", a.ref_constraints_owner.empty() ? a.mtype : a.ref_constraints_owner);
        return std::format("{}.spec.Constraints.UNCONSTRAINED", kWire);
    };

    struct Row { int rank; int64_t number; std::string tag; int alt; };
    std::vector<Row> dispatch;
    if (!spec.ber_tags.empty()) {
        for (const auto& e : spec.ber_tags) dispatch.push_back({ber_tag_class_rank(e.cls), e.number, e.tag_literal, e.alt_index});
    } else {
        // AUTOMATIC tags: Generator builds no table when every alternative
        // has its own distinct tag, so it is built from the rows.
        for (size_t i = 0; i < spec.alternatives.size(); ++i)
            if (const auto& rt = spec.alternatives[i].resolved_tag)
                dispatch.push_back({ber_tag_class_rank(rt->cls), rt->number, format_tag_literal(*rt), static_cast<int>(i)});
    }
    std::sort(dispatch.begin(), dispatch.end(), [](const Row& a, const Row& b) {
        return std::pair(a.rank, a.number) < std::pair(b.rank, b.number);
    });

    std::vector<std::string> reserved = {t, "SPEC", "FACTORIES", "spec", "activeIndex", "getActive", "select",
        "setUnknownExtension", "unknownExtension", "asMemberRef", "ownElementXerName", "xerInstruction", "berFraming",
        "pduConstraints", "equals", "hashCode", "toString", "getClass", "notify", "notifyAll", "wait", "clone", "finalize"};
    auto accessor = [&](const ChoiceAlternativeSpec& a) {
        std::string n = member_name(a.asn1_name);
        while (std::find(reserved.begin(), reserved.end(), n) != reserved.end()) n += "_";
        return n;
    };
    bool extensible = spec.ext_at >= 0;
    // An inline collection alternative's SeqOf/SetOf type and factory
    // come from its ElemShape, as for a SEQUENCE member.
    auto alt_type = [&](const ChoiceAlternativeSpec& a) {
        return a.seq_of_kind != SeqOfKind::None ? java_collection_type(a.seq_of_kind, a.elem_shape) : a.mtype;
    };
    auto alt_factory = [&](const ChoiceAlternativeSpec& a) {
        if (a.contained)
            return std::format("() -> new {}({}::new, {}.CONTAINED)", a.mtype, a.contained_inner, a.contained_base);
        return a.seq_of_kind != SeqOfKind::None ? "() -> " + java_collection_new(a.seq_of_kind, a.elem_shape)
                                                : a.mtype + "::new";
    };

    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public class {0} implements {1}.spec.Asn1Choice, {1}.spec.Asn1Pdu {{\n", t, kWire);
    os << std::format("    public static final {0}.spec.ChoiceSpec SPEC = new {0}.spec.ChoiceSpec(\"{1}\", java.util.List.of(\n",
                      kWire, spec.xer_name);
    for (size_t i = 0; i < spec.alternatives.size(); ++i) {
        const auto& a = spec.alternatives[i];
        os << std::format("            new {}.spec.AltMeta(\"{}\", {}, {}, {}, {}){}\n", kWire, a.asn1_name, framing(a),
                          constraints(a), java_member_xer_instruction(a), a.contained ? a.contained_base + ".CONTAINED" : "null",
                          i + 1 < spec.alternatives.size() ? "," : "),");
    }
    os << "            java.util.List.of(";
    for (size_t i = 0; i < dispatch.size(); ++i)
        os << std::format("{}\n                    new {}.spec.BerDispatch({}, {})", i ? "," : "", kWire, dispatch[i].tag, dispatch[i].alt);
    os << "),\n";
    bool has_contained = std::any_of(spec.alternatives.begin(), spec.alternatives.end(),
                                     [](const ChoiceAlternativeSpec& a) { return a.contained != nullptr; });
    os << std::format("            {}, {}, {}, {});\n\n", spec.tag ? format_tag_literal(*spec.tag) : "null",
                      spec.ext_at, spec.range_bits, has_contained ? "true" : "false");
    os << std::format("    private static final java.util.List<java.util.function.Supplier<{}.spec.AsMemberRef>> FACTORIES = java.util.List.of(\n", kWire);
    for (size_t i = 0; i < spec.alternatives.size(); ++i)
        os << std::format("            {}{}\n", alt_factory(spec.alternatives[i]), i + 1 < spec.alternatives.size() ? "," : ");");
    os << "\n";
    os << "    private int index = 0;\n";
    os << std::format("    private {}.spec.AsMemberRef value = FACTORIES.get(0).get();\n", kWire);
    if (extensible) os << std::format("    private {}.spec.Asn1Choice.UnknownExtension unknown;\n", kWire);
    os << "\n";

    for (size_t i = 0; i < spec.alternatives.size(); ++i) {
        const auto& a = spec.alternatives[i];
        std::string n = accessor(a);
        os << std::format("    /** ASN.1: {{@code {}}}; null when another alternative is selected. */\n", a.asn1_name);
        // An inline collection or contained value has a generic type, so the cast from the
        // stored Object is unchecked (JLS §5.1.6.1); select() keeps it sound.
        if (a.seq_of_kind != SeqOfKind::None || a.contained) os << "    @java.lang.SuppressWarnings(\"unchecked\")\n";
        os << std::format("    public {} {}() {{\n", alt_type(a), n);
        os << std::format("        return index == {} ? ({}) value : null;\n", i, alt_type(a));
        os << "    }\n\n";
        os << std::format("    /** Selects {{@code {}}} with value {{@code v}}. */\n", a.asn1_name);
        os << std::format("    public void {}({} v) {{\n", n, alt_type(a));
        os << std::format("        index = {};\n", i);
        os << "        value = java.util.Objects.requireNonNull(v);\n";
        if (extensible) os << "        unknown = null;\n";
        os << "    }\n\n";
    }

    os << "    @java.lang.Override\n";
    os << std::format("    public {}.spec.ChoiceSpec spec() {{\n        return SPEC;\n    }}\n\n", kWire);
    os << "    @java.lang.Override\n";
    os << "    public int activeIndex() {\n        return index;\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef getActive() {{\n", kWire);
    os << std::format("        return index < 0 ? new {}.spec.MemberRef.Unsupported(\"CHOICE {}: no alternative selected\") : value.asMemberRef();\n",
                      kWire, spec.xer_name);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef select(int i) {{\n", kWire);
    os << "        index = i;\n";
    os << "        value = FACTORIES.get(i).get();\n";
    if (extensible) os << "        unknown = null;\n";
    os << "        return value.asMemberRef();\n";
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public void setUnknownExtension({}.spec.Asn1Choice.UnknownExtension ext) {{\n", kWire);
    if (extensible) {
        os << "        index = -1;\n";
        os << "        value = null;\n";
        os << "        unknown = java.util.Objects.requireNonNull(ext);\n";
    } else {
        os << std::format("        throw new java.lang.IllegalStateException(\"CHOICE {} is not extensible\");\n", spec.xer_name);
    }
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {}.spec.Asn1Choice.UnknownExtension unknownExtension() {{\n", kWire);
    os << std::format("        return {};\n", extensible ? "unknown" : "null");
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef asMemberRef() {{\n", kWire);
    os << std::format("        return new {}.spec.MemberRef.Choice(this);\n", kWire);
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public java.lang.String ownElementXerName() {\n";
    os << std::format("        return \"{}\";\n", spec.xer_name);
    os << "    }\n\n";
    // Equality is by the selected alternative's value, seen through its
    // MemberRef so a builtin alias compares by the builtin it holds.
    os << "    @java.lang.Override\n";
    os << "    public boolean equals(java.lang.Object o) {\n";
    os << std::format("        if (!(o instanceof {} other) || other.index != index) {{\n", t);
    os << "            return false;\n";
    os << "        }\n";
    if (extensible) {
        os << "        if (index < 0) {\n";
        os << "            return unknown == null ? other.unknown == null\n";
        os << "                    : other.unknown != null && unknown.tag().equals(other.unknown.tag())\n";
        os << "                            && java.util.Arrays.equals(unknown.bytes(), other.unknown.bytes());\n";
        os << "        }\n";
    }
    os << "        return value.asMemberRef().equals(other.value.asMemberRef());\n";
    os << "    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public int hashCode() {\n";
    os << "        return index < 0 ? -1 : 31 * index + value.asMemberRef().hashCode();\n";
    os << "    }\n";
    os << "}\n";
}

/// @brief The name of the class holding a member's DEFAULT value.
static std::string default_class(const std::string& base) {
    return base + "_DEFAULT";
}

/// @brief Emit one SEQUENCE or SET type as a Java class: its `SequenceSpec`
///        table, one field per member (an OPTIONAL member is null when
///        absent), accessors, and the `Asn1Seq` reflection the BER walker
///        (`BerObject`) reads. The class holds no codec code.
/// @param spec    Resolved, backend-agnostic decision (see SequenceSpec).
/// @param session Per-type output session.
/// @see X.680 §25 (SEQUENCE), §27 (SET; members in canonical tag order,
///      X.680 §8.6), X.690 §8.9 / §8.11 (their BER encoding).
void JavaBackend::emit_sequence(const SequenceSpec& spec, TypeOutputSession& session) const {
    const std::string& t = spec.type_name;
    const std::string asn1 = spec.asn1_name.empty() ? t : spec.asn1_name;
    auto unsupported = [&](const std::string& what) {
        throw std::logic_error(std::format("emit_sequence: {} {}, not implemented for this backend", asn1, what));
    };
    for (const auto& m : spec.members)
        if (m.has_default && !m.has_default_setter)
            unsupported(std::format("member '{}' is a DEFAULT value of this kind", m.asn1_name));

    // Row framing (X.690 §8.14), as in emit_choice. `tag` is the tag the
    // member starts with on the wire, which decides whether an OPTIONAL
    // member is present; an untagged CHOICE has none (X.680 §31.2.7) and
    // an OPTIONAL one is present when the next tag is one of its
    // alternatives' (DelegateChoice).
    struct Framing { std::string tag, ber; };
    auto framing = [&](const SequenceMemberSpec& m) -> Framing {
        bool is_choice_ref = !m.mbuiltin && m.ref_kind == TaggedMemberSpec::RefTargetKind::Other
                          && !m.ref_builtin_alias && !m.ref_is_sequence_or_set && !m.ref_is_seq_of;
        const auto& rt = m.resolved_tag;
        if (!rt) {
            if (m.optional)
                return {"null", std::format("new {}.spec.BerTagging.DelegateChoice(() -> {}.SPEC.berTags())", kWire, m.mtype)};
            return {"null", std::format("{}.spec.BerTagging.DELEGATE", kWire)};
        }
        std::string tag = format_tag_literal(*rt);
        if (rt->tag_is_override)
            return {tag, std::format("new {}.spec.BerTagging.{}({})", kWire, m.is_explicit ? "Explicit" : "Implicit", tag)};
        if (is_choice_ref || m.ref_is_sequence_or_set) return {tag, std::format("{}.spec.BerTagging.DELEGATE", kWire)};
        if (m.seq_of_kind != SeqOfKind::None) return {tag, std::format("new {}.spec.BerTagging.Implicit({})", kWire, tag)};
        if (m.is_explicit)
            return {tag, std::format("new {0}.spec.BerTagging.OfType({1}.BER_FRAMING)", kWire,
                                     m.contained ? m.contained_base : m.mtype)};
        return {tag, std::format("new {}.spec.BerTagging.Implicit({})", kWire, tag)};
    };
    // A collection's SIZE (X.680 §51.5) lives on its named type: the
    // referenced one, or the synthetic type an inline collection member
    // is promoted to.
    auto constraints = [&](const SequenceMemberSpec& m) {
        if (!m.tdref.empty()) return m.tdref + ".CONSTRAINTS";
        if (m.contained) {
            if (!m.mbuiltin && m.ref_builtin_alias && !m.ref_constraints_owner.empty())
                return m.ref_constraints_owner + ".CONSTRAINTS";
            return m.contained_base + ".CONSTRAINTS";
        }
        if (m.seq_of_kind != SeqOfKind::None)
            return std::format("{}.CONSTRAINTS", escape(synthetic_name(spec.type_name, m.asn1_name)));
        if (!m.mbuiltin && m.ref_is_seq_of) return std::format("{}.CONSTRAINTS", m.mtype);
        if (!m.mbuiltin && (m.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias || m.ref_builtin_alias))
            return std::format("{}.CONSTRAINTS", m.ref_constraints_owner.empty() ? m.mtype : m.ref_constraints_owner);
        return std::format("{}.spec.Constraints.UNCONSTRAINED", kWire);
    };

    std::vector<std::string> reserved = {t, "SPEC", "spec", "getMember", "presentMember", "setDefault",
        "isDefaultEqual", "validate", "asMemberRef", "ownElementXerName", "xerInstruction", "berFraming",
        "pduConstraints", "equals", "hashCode", "toString", "getClass", "notify", "notifyAll", "wait", "clone", "finalize"};
    auto accessor = [&](const SequenceMemberSpec& m) {
        std::string n = member_name(m.asn1_name);
        while (std::find(reserved.begin(), reserved.end(), n) != reserved.end()) n += "_";
        return n;
    };
    std::vector<std::string> names, types, news;
    for (const auto& m : spec.members) {
        names.push_back(accessor(m));
        bool coll = m.seq_of_kind != SeqOfKind::None;
        types.push_back(coll ? java_collection_type(m.seq_of_kind, m.elem_shape) : m.mtype);
        news.push_back(coll ? java_collection_new(m.seq_of_kind, m.elem_shape)
                            : m.contained ? std::format("new {}({}::new, {}.CONTAINED)", m.mtype, m.contained_inner, m.contained_base)
                            : m.has_default_setter ? std::format("{}.make()", default_class(member_descriptor_base_name(t, m.mname)))
                            : std::format("new {}()", m.mtype));
    }

    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public class {0} implements {1}.spec.Asn1Seq, {1}.spec.Asn1Pdu {{\n", t, kWire);
    os << std::format("    public static final {0}.spec.SequenceSpec SPEC = new {0}.spec.SequenceSpec(\"{1}\", {2}, java.util.List.of(",
                      kWire, spec.xer_name,
                      spec.tag ? format_tag_literal(*spec.tag)
                               : std::format("{}.ber.Tag.universal({}, true)", kWire, spec.is_set ? 17 : 16));
    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        auto f = framing(m);
        os << std::format("{}\n            new {}.spec.MemberMeta(\"{}\", {}, {}, {}, {}, {}, {})",
                          i ? "," : "", kWire, m.asn1_name, f.tag, m.optional ? "true" : "false", f.ber, constraints(m),
                          java_member_xer_instruction(m), m.contained ? m.contained_base + ".CONTAINED" : "null");
    }
    // PER extension additions (X.691 §18.9); BER reads neither list.
    std::string units, group_optional;
    for (size_t u = 0; u < spec.ext_unit_ends.size(); ++u)
        units += std::format("{}new {}.spec.ExtUnit({}, {})", u ? ", " : "", kWire, spec.ext_unit_ends[u],
                             spec.ext_unit_is_group[u] ? "true" : "false");
    for (size_t i = 0; i < spec.member_group_optional.size(); ++i)
        group_optional += std::format("{}{}", i ? ", " : "", spec.member_group_optional[i] ? "true" : "false");
    // Contained members are decoded after the others, so a `when` condition sees its sibling.
    std::string contained;
    for (size_t i = 0; i < spec.members.size(); ++i)
        if (spec.members[i].contained) contained += std::format("{}{}", contained.empty() ? "" : ", ", i);
    os << std::format("),\n            {}, {}, {}, java.util.List.of({}), java.util.List.of({}), java.util.List.of({}));\n\n",
                      spec.ext_at, spec.roms_count, spec.is_set ? "true" : "false", units, group_optional, contained);

    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        if (m.optional && !m.has_default_setter) os << std::format("    private {} {};\n", types[i], names[i]);
        else os << std::format("    private {} {} = {};\n", types[i], names[i], news[i]);
    }
    os << "\n";

    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        const std::string& n = names[i];
        os << std::format("    /** ASN.1: {{@code {}}}{}. */\n", m.asn1_name,
                          m.has_default_setter ? "; its DEFAULT unless set" : m.optional ? "; null when absent" : "");
        os << std::format("    public {} {}() {{\n        return this.{};\n    }}\n\n", types[i], n, n);
        os << std::format("    /** Sets {{@code {}}}{}. */\n", m.asn1_name,
                          m.has_default_setter ? "; null means its DEFAULT" : m.optional ? "; null makes it absent" : "");
        os << std::format("    public void {}({} v) {{\n", n, types[i]);
        os << std::format("        this.{} = {};\n    }}\n\n", n,
                          m.has_default_setter ? std::format("v == null ? {} : v", news[i])
                          : m.optional ? "v" : "java.util.Objects.requireNonNull(v)");
    }

    os << "    @java.lang.Override\n";
    os << std::format("    public {}.spec.SequenceSpec spec() {{\n        return SPEC;\n    }}\n\n", kWire);
    os << "    @java.lang.Override\n";
    // A switch expression needs at least one arm with a result (JLS
    // §15.28.1), which an empty SEQUENCE (`SEQUENCE {}`) has none of.
    const char* open_switch = spec.members.empty() ? "" : "        return switch (i) {\n";
    const char* close_switch = spec.members.empty()
        ? "        throw new java.lang.IndexOutOfBoundsException(i);\n    }\n\n"
        : "            default -> throw new java.lang.IndexOutOfBoundsException(i);\n        };\n    }\n\n";
    os << std::format("    public {}.spec.MemberRef getMember(int i) {{\n", kWire);
    os << open_switch;
    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& n = names[i];
        if (spec.members[i].optional)
            os << std::format("            case {} -> this.{} == null ? {}.spec.MemberRef.ABSENT : this.{}.asMemberRef();\n", i, n, kWire, n);
        else
            os << std::format("            case {} -> this.{}.asMemberRef();\n", i, n);
    }
    os << close_switch;
    os << "    @java.lang.Override\n";
    os << std::format("    public {}.spec.MemberRef presentMember(int i) {{\n", kWire);
    os << open_switch;
    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        const auto& n = names[i];
        if (m.optional)
            os << std::format("            case {0} -> {{\n                if (this.{1} == null) {{\n                    this.{1} = {2};\n"
                              "                }}\n                yield this.{1}.asMemberRef();\n            }}\n", i, n, news[i]);
        else
            os << std::format("            case {} -> this.{}.asMemberRef();\n", i, n);
    }
    os << close_switch;
    os << "    @java.lang.Override\n";
    os << "    public void setDefault(int i) {\n";
    os << "        switch (i) {\n";
    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        os << std::format("            case {} -> this.{} = {};\n", i, names[i], m.optional && !m.has_default_setter ? "null" : news[i]);
    }
    os << "            default -> throw new java.lang.IndexOutOfBoundsException(i);\n        }\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public boolean isDefaultEqual(int i) {\n        return switch (i) {\n";
    for (size_t i = 0; i < spec.members.size(); ++i) {
        const auto& m = spec.members[i];
        if (!m.has_default_setter) continue;
        os << std::format("            case {0} -> this.{1}.asMemberRef().equals({2}.make().asMemberRef());\n",
                          i, names[i], default_class(member_descriptor_base_name(t, m.mname)));
    }
    os << "            default -> false;\n        };\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public long validate(int i) {\n        return 0;\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.MemberRef asMemberRef() {{\n        return new {0}.spec.MemberRef.Composite(this);\n    }}\n\n", kWire);
    os << "    @java.lang.Override\n";
    os << std::format("    public java.lang.String ownElementXerName() {{\n        return \"{}\";\n    }}\n\n", spec.xer_name);
    // Equality is member by member, seen through each member's MemberRef
    // so a builtin alias compares by the builtin it holds.
    os << "    @java.lang.Override\n";
    os << "    public boolean equals(java.lang.Object o) {\n";
    os << std::format("        if (!(o instanceof {} other)) {{\n            return false;\n        }}\n", t);
    os << "        for (int i = 0; i < SPEC.members().size(); i++) {\n";
    os << "            if (!getMember(i).equals(other.getMember(i))) {\n                return false;\n            }\n";
    os << "        }\n        return true;\n    }\n\n";
    os << "    @java.lang.Override\n";
    os << "    public int hashCode() {\n        int h = 1;\n";
    os << "        for (int i = 0; i < SPEC.members().size(); i++) {\n            h = 31 * h + getMember(i).hashCode();\n        }\n";
    os << "        return h;\n    }\n";
    os << "}\n";
}

/// @brief Emit the constraint table of one member, alternative or element
///        with an inline constraint (X.680 §51): a package-private class
///        beside the type's public one, named by member_descriptor_base_name
///        and holding `CONSTRAINTS`, which the member's row references.
///        INTEGER value ranges, SIZE constraints and REAL value ranges and
///        base constraints and a FROM alphabet are carried.
/// @param spec    The member's resolved constraint (see MemberTypeDescriptorSpec).
/// @param session Per-type output session.
///        A contained field (X.682 §11) also gets `CONTAINED`, its
///        ContainedSpec row, which its `Containing<T>` value carries.
/// @throws std::logic_error for INTEGER storage beyond 64 bits.
void JavaBackend::emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const {
    using Kind = MemberTypeDescriptorSpec::Kind;
    std::string name = member_descriptor_base_name(spec.parent_cname, spec.mname);
    std::string constraints = std::format("{}.spec.Constraints.UNCONSTRAINED", kWire);
    if (spec.kind == Kind::Integer) {
        bool u64 = spec.storage_kind == IntStorageKind::U64;
        if (spec.storage_kind != IntStorageKind::S64 && !u64)
            throw std::logic_error(std::format("emit_member_type_descriptor: {} storage beyond 64 bits is not implemented for this backend", name));
        // An upper bound above INT64_MAX in signed storage is checked as
        // semi-constrained, as in the other runtimes.
        bool semi = spec.semi_constrained || (!u64 && spec.hi_is_large);
        int flags = (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED)
                  | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
        uint64_t upper_u64 = spec.semi_constrained ? std::numeric_limits<uint64_t>::max() : spec.upper_u64;
        constraints = java_int_constraints(flags, std::max(spec.range_bits, 0), u64 ? 0 : spec.lower_s64,
                                           u64 ? 0 : spec.upper_s64, u64 ? spec.lower_u64 : 0, u64 ? upper_u64 : 0);
    } else if (spec.kind == Kind::Sizeable) {
        constraints = java_size_constraints(spec);
    } else if (spec.kind == Kind::Real) {
        constraints = java_real_constraints(spec.real_range);
    }
    auto& os = session.buffer(declaration_extension());
    if (spec.contained)
        os << std::format("/** Contained value of {{@code {}.{}}} (X.682 §11). */\n", spec.parent_cname, spec.mname);
    else
        os << std::format("/** Inline constraint of {{@code {}.{}}} (X.680 §51). */\n", spec.parent_cname, spec.mname);
    os << std::format("final class {} {{\n", name);
    os << std::format("    static final {}.spec.Constraints CONSTRAINTS = {};\n\n", kWire, constraints);
    if (const auto* f = spec.contained) {
        auto enc = [](sema::ContentsEncoding e) {
            switch (e) {
            case sema::ContentsEncoding::Ber:          return "BER";
            case sema::ContentsEncoding::Cer:          return "CER";
            case sema::ContentsEncoding::Der:          return "DER";
            case sema::ContentsEncoding::PerAligned:   return "PER_ALIGNED";
            case sema::ContentsEncoding::PerUnaligned: return "PER_UNALIGNED";
            default:                                   return "OUTER";
            }
        };
        auto text = [](sema::ContainedText x) {
            switch (x) {
            case sema::ContainedText::Inline:    return "INLINE";
            case sema::ContainedText::InlineRaw: return "INLINE_RAW";
            default:                             return "HEX";
            }
        };
        os << std::format("    static final {0}.spec.ContainedSpec CONTAINED = new {0}.spec.ContainedSpec("
                          "{0}.spec.ContainedEncoding.{1}, {2}, \"{3}\", {4}, {5}L, {6}, {0}.spec.ContainedText.{7}, "
                          "{0}.spec.ContainedText.{8}, {9});\n\n",
                          kWire, enc(f->encoding), f->decode == sema::ContainedDecode::Eager ? "true" : "false",
                          escape_string_literal(f->decoder), spec.contained_when_index, f->when ? f->when->value : 0,
                          f->on_error == sema::ContainedOnError::Fail ? "true" : "false", text(f->xer), text(f->jer),
                          sema::builtin_decoder_index(f->decoder));
        // A field whose type is a tagged type assignment carries that
        // assignment's framing (X.680 §31.2); its row refers to it here,
        // since the field's own class is the generic Containing<T>.
        if (spec.contained_tag)
            os << std::format("    static final {0}.spec.BerTagging BER_FRAMING = new {0}.spec.BerTagging.{1}({2});\n\n",
                              kWire, spec.contained_is_explicit ? "Explicit" : "Implicit",
                              format_tag_literal(*spec.contained_tag));
    }
    os << std::format("    private {}() {{\n    }}\n}}\n\n", name);
}

/// @brief Emit a member's DEFAULT value (X.680 §25.6) as a package-private
///        class beside the type's public one, named
///        `<member_descriptor_base_name>_DEFAULT`, whose `make()` returns a
///        new value equal to the default. The value is set through the
///        member's MemberRef, so a builtin and a builtin alias are filled
///        the same way. The SEQUENCE starts the member at this value,
///        refills it when decode finds the member absent, and compares with
///        it to leave it out of DER (X.690 §11.5).
/// @param spec        The DEFAULT value.
/// @param type_name   The member's Java type.
/// @param parent_name The enclosing type's name.
/// @param member_name The member's name.
/// @param session     Per-type output session.
void JavaBackend::emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                                      const std::string& parent_name, const std::string& member_name,
                                      TypeOutputSession& session) const {
    using Kind = DefaultValueSpec::Kind;
    auto prim = [&](const std::string& cls) {
        return std::format("(({}.types.{}) (({}.spec.MemberRef.Primitive) v.asMemberRef()).value())", kWire, cls, kWire);
    };
    std::string set;
    switch (spec.kind) {
    case Kind::Bool:
        set = std::format("{}.set({})", prim("Asn1Boolean"), spec.bool_val ? "true" : "false");
        break;
    case Kind::Int:
        if (spec.int_storage_kind != IntStorageKind::S64 && spec.int_storage_kind != IntStorageKind::U64)
            throw std::logic_error(std::format("emit_default_setter: {}.{} storage beyond 64 bits is not implemented for this backend",
                                               parent_name, member_name));
        set = std::format("{}.set({})", prim(spec.int_storage_kind == IntStorageKind::U64 ? "Asn1UInteger" : "Asn1Integer"),
                          java_long(spec.int_val));
        break;
    case Kind::String:
        set = std::format("{}.set(\"{}\")", prim("Asn1CharString"), escape_string_literal(spec.string_val));
        break;
    case Kind::EnumRef:
        set = std::format("v.set({}.{}.{})", type_name, escape("Value", {type_name}), escape(value_name(spec.enum_name)));
        break;
    case Kind::Real: {
        // The exact bits, so infinities and -0 (X.680 §21) need no literal form.
        uint64_t bits;
        std::memcpy(&bits, &spec.real_val, sizeof bits);
        set = std::format("{}.set(java.lang.Double.longBitsToDouble(0x{:016x}L))", prim("Asn1Real"), bits);
        break;
    }
    case Kind::None:
        return;
    }
    std::string cls = default_class(member_descriptor_base_name(parent_name, member_name));
    auto& os = session.buffer(declaration_extension());
    os << std::format("/** DEFAULT of {{@code {}.{}}} (X.680 §25.6). */\n", parent_name, member_name);
    os << std::format("final class {} {{\n", cls);
    os << std::format("    static {} make() {{\n        {} v = new {}();\n        {};\n        return v;\n    }}\n\n",
                      type_name, type_name, type_name, set);
    os << std::format("    private {}() {{\n    }}\n}}\n\n", cls);
}

/// @brief Emit one named SEQUENCE OF / SET OF type as a Java class that
///        extends the runtime's `SeqOf` / `SetOf` collection: its own XER
///        names (X.693 §12), its SIZE constraint (X.680 §51.5) and its
///        BER framing when the type assignment has a tag of its own
///        (X.680 §31.2). The class holds no codec code.
/// @param spec    Resolved, backend-agnostic decision (see SeqOfSpec).
/// @param session Per-type output session.
void JavaBackend::emit_seq_of(const SeqOfSpec& spec, TypeOutputSession& session) const {
    const std::string& t = spec.type_name;
    std::string base = std::format("{}.spec.{}<{}>", kWire, spec.is_set_of ? "SetOf" : "SeqOf", spec.elem_type);
    std::string constraints = std::format("{}.spec.Constraints.UNCONSTRAINED", kWire);
    if (spec.has_size_constraint) {
        int flags = (spec.size_upper ? asn1::Constraints::SIZE_CONSTRAINED : 0)
                  | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
        constraints = std::format("new {}.spec.Constraints({}, 0, 0L, 0L, 0L, 0L, {}, {}, {}, null, 0, null, 0, null, 0.0, 0.0)",
                                  kWire, flags, spec.range_bits, java_long(spec.size_lower),
                                  java_long(spec.size_upper.value_or(std::numeric_limits<int64_t>::max())));
    }
    // Each element is encoded under its own constraints (X.691 §20.3): an
    // inline element constraint's table, or the referenced type's own.
    std::string element;
    if (!spec.elem_ref.empty())
        element = spec.elem_ref + ".CONSTRAINTS";
    else if (spec.elem_tdref.kind == TypeDescriptorRefKind::FreeStanding)
        element = spec.elem_tdref.name + ".CONSTRAINTS";
    if (!element.empty())
        constraints = std::format("{0}.spec.Constraints.withElement({1}, {2})", kWire, constraints, element);

    auto& os = session.buffer(declaration_extension());
    if (!spec.asn1_name.empty()) os << std::format("/** ASN.1: {{@code {}}} */\n", spec.asn1_name);
    os << std::format("public class {} extends {} implements {}.spec.Asn1Pdu {{\n", t, base, kWire);
    os << std::format("    public static final {}.spec.Constraints CONSTRAINTS = {};\n", kWire, constraints);
    os << ber_framing_field(spec);
    os << "\n";
    os << std::format("    public {}() {{\n        super({}::new);\n    }}\n\n", t, spec.elem_type);
    os << "    @java.lang.Override\n";
    os << std::format("    public java.lang.String ownXerName() {{\n        return \"{}\";\n    }}\n\n", spec.xer_name);
    if (spec.elem_xer_name) {
        os << "    @java.lang.Override\n";
        os << std::format("    public java.lang.String elemXerName() {{\n        return \"{}\";\n    }}\n\n", *spec.elem_xer_name);
    }
    os << "    @java.lang.Override\n";
    os << std::format("    public {0}.spec.Constraints pduConstraints() {{\n        return CONSTRAINTS;\n    }}\n", kWire);
    os << ber_framing_method(spec);
    os << "}\n";
}

/// @brief Emit a type assignment that only references another type
///        (`A ::= B`, X.680 §16.1) as `public class A extends B {}`. Java has
///        no type alias, so a subclass keeps the ASN.1 name while every
///        table (`SPEC`, `CONSTRAINTS`, framing) is B's, as with the C++
///        alias; generated classes are not final for this reason.
/// @param type_name   The alias's class name.
/// @param target_type The referenced type's class name.
/// @param session     Per-type output session; writes the `.java` buffer.
void JavaBackend::emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                                 TypeOutputSession& session) const {
    auto& os = session.buffer(declaration_extension());
    os << std::format("/** ASN.1: {{@code {} ::= {}}} */\n", type_name, target_type);
    os << std::format("public class {} extends {} {{\n}}\n", type_name, target_type);
}

/// @brief Emit a reference to another generated type: nothing, since every
///        generated class of a run shares one package (JLS §7.4) and is
///        visible by its simple name.
/// @param type_name Unused.
/// @param filename  Unused.
/// @param session   Unused.
void JavaBackend::emit_type_reference(const std::string& type_name, const std::string& filename,
                                      TypeOutputSession& session) const {
    (void)type_name;
    (void)filename;
    (void)session;
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
