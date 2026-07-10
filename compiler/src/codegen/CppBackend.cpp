#include "CppBackend.hpp"
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <array>
#include <limits>

namespace asn1::codegen {

// Moved from Generator.cpp (was `static`, file-local). No behavior change.
std::string format_tag_literal(const TagSpec& tag_spec) {
    std::string tag_class_literal;
    switch (tag_spec.cls) {
    case ast::TagClass::Universal:   tag_class_literal = "asn1::TagClass::Universal";   break;
    case ast::TagClass::Application: tag_class_literal = "asn1::TagClass::Application"; break;
    case ast::TagClass::Private:     tag_class_literal = "asn1::TagClass::Private";     break;
    default:                         tag_class_literal = "asn1::TagClass::Context";     break;
    }
    return std::format("asn1::Tag{{{}, {}, {}}}", tag_class_literal, tag_spec.number,
                        tag_spec.constructed ? "true" : "false");
}

/// @brief Returns ceil(log2(n)) clamped to [1,∞) — bits per character for an n-symbol alphabet.
static int compute_alphabet_bits(int n) {
    int bits = 0;
    for (int r = n - 1; r > 0; r >>= 1) ++bits;
    return (bits == 0) ? 1 : bits;
}

// Moved from Generator.cpp (was `static`, file-local). No behavior change.
// Declared (not `static`) in CppBackend.hpp: Generator.cpp's
// emit_member_type_descriptor still calls it directly.
const char* builtin_def_name(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::NumericString:   return "asn_DEF_NumericString";
    case BT::PrintableString: return "asn_DEF_PrintableString";
    case BT::Ia5String:       return "asn_DEF_Ia5String";
    case BT::VisibleString:   return "asn_DEF_VisibleString";
    default:                  return nullptr;
    }
}

/// @brief Generate the three alphabet constraint fields that reference a built-in descriptor.
///
/// Produces a comma-prefixed fragment suitable for insertion into a Constraints initializer:
/// `.alphabet_bits`, `.alphabet`/`.alphabet_size` (decode table), and `.encode_table`.
/// Returns an empty string for types without a fixed alphabet (UTF8String, etc.).
///
/// @param bt  Built-in type whose global `asn_DEF_*` descriptor carries the alphabet tables.
/// @return Constraint fragment, e.g. `", .alphabet_bits=…, .alphabet=…, …"`, or `""`.
/// @see X.691 §26.5 — known-multiplier character string PER canonical index.
static std::string builtin_alphabet_refs(ast::BuiltinType bt) {
    const char* def_name = builtin_def_name(bt);
    if (!def_name) return "";
    return std::format(
        ", .alphabet_bits=asn1::{0}.constraints.alphabet_bits"
        ", .alphabet=asn1::{0}.constraints.alphabet"
        ", .alphabet_size=asn1::{0}.constraints.alphabet_size"
        ", .encode_table=asn1::{0}.constraints.encode_table",
        def_name);
}

// Moved from Generator.cpp (was `static`, file-local). No behavior change.
void emit_from_alphabet_arrays(std::ostream& os, const std::string& prefix,
                                const std::vector<uint8_t>& alphabet) {
    // Decode table: alphabet[constrained_idx] → char value (sorted, same as input).
    os << std::format("static const uint8_t {}_alpha[{}] = {{", prefix, alphabet.size());
    for (int i = 0; i < static_cast<int>(alphabet.size()); ++i) {
        if (i) os << ", ";
        os << static_cast<int>(alphabet[i]);
    }
    os << "};\n";
    // Encode table: encode_table[char_value] → constrained_idx, or 0xFFFF if not in alphabet.
    std::array<uint16_t, 256> enc;
    enc.fill(0xFFFFu);
    for (int i = 0; i < static_cast<int>(alphabet.size()); ++i)
        enc[alphabet[i]] = static_cast<uint16_t>(i);
    os << std::format("static const uint16_t {}_enc[256] = {{\n", prefix);
    for (int i = 0; i < 256; ++i) {
        if (i % 16 == 0) os << "  ";
        if (enc[i] == 0xFFFFu) os << "0xFFFFu";
        else                   os << enc[i];
        if (i < 255) os << (i % 16 == 15 ? ",\n" : ", ");
    }
    os << "\n};\n";
}

// Moved from Generator.cpp (was `static`, file-local). No behavior change.
std::string make_string_constraints_init(
    int flags, int sc_range_bits, int64_t sc_lower, int64_t sc_upper,
    const std::vector<uint8_t>& alphabet,
    const std::string& alpha_prefix,
    std::optional<ast::BuiltinType> builtin_bt) {
    int val_lb      = alphabet.empty() ? 0 : static_cast<int>(alphabet[0]);
    int val_ub      = alphabet.empty() ? 0 : static_cast<int>(alphabet.back());
    int alpha_bits  = alphabet.empty() ? 0
        : compute_alphabet_bits(static_cast<int>(alphabet.size()));
    // When builtin_bt is set, alphabet_bits comes from builtin_alphabet_refs — omit here
    // to avoid emitting the designator twice (which is a C++ error even when values match).
    std::string s;
    if (builtin_bt) {
        s = std::format(
            "{{ .flags={}, .lower_bound={}, .upper_bound={}, "
            ".size_range_bits={}, .size_lower={}, .size_upper={}",
            flags, val_lb, val_ub, sc_range_bits, sc_lower, sc_upper);
    } else {
        s = std::format(
            "{{ .flags={}, .lower_bound={}, .upper_bound={}, "
            ".size_range_bits={}, .size_lower={}, .size_upper={}, .alphabet_bits={}",
            flags, val_lb, val_ub, sc_range_bits, sc_lower, sc_upper, alpha_bits);
    }
    if (!alphabet.empty() && !alpha_prefix.empty()) {
        // FROM constraint: emit inline static arrays.
        s += std::format(
            ", .alphabet={0}_alpha, .alphabet_size={1}u, .encode_table={0}_enc",
            alpha_prefix, alphabet.size());
    } else if (builtin_bt) {
        // No FROM constraint but restricted type: inherit all alphabet fields from global descriptor.
        s += builtin_alphabet_refs(*builtin_bt);
    }
    s += " }";
    return s;
}

// Moved verbatim from Generator.cpp (was `static`, file-local). No
// behavior change: same parameters, same output.
void emit_type_descriptor(std::ostream& os,
                           const std::string& cname,
                           const std::string& xer_name,
                           const std::string& tag_expr,
                           bool has_enum, bool has_seq,
                           bool has_choice, bool has_seqof,
                           const std::string& kind,
                           const std::string& per_handler,
                           const std::string& ber_handler,
                           bool use_class_scope) {
    auto sp = [&](bool h) -> std::string {
        if (!h) return "nullptr";
        return use_class_scope ? std::format("&{}::asn_SPC", cname)
                               : std::format("&asn_SPC_{}", cname);
    };
    if (use_class_scope)
        os << std::format("const asn1::TypeDescriptor {}::asn_DEF = {{\n", cname);
    else
        os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", xer_name);
    os << std::format("    {},\n", tag_expr);
    os << std::format("    {}, {}, {}, {}, {{}} /* constraints */,\n",
                      sp(has_enum), sp(has_seq), sp(has_choice), sp(has_seqof));
    os << std::format("    false, {} /* kind */,\n", kind);
    os << std::format("    {} /* per_handler */,\n", per_handler);
    os << std::format("    {} /* ber_handler */,\n", ber_handler);
    os << std::format("    asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) /* lifecycle */\n", cname);
    os << "};\n\n";
}

// Moved from Generator::emit_enumerated_hpp — same output, now driven by
// the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
void CppBackend::emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // class inheriting EnumValue — plain inner enum so values leak into class scope
    os << std::format("class {} : public asn1::EnumValue {{\npublic:\n", cname);
    // Enum values are plain enum (not enum class) — they inject into class scope.
    // Reserve all generated method names so values can't clash with them.
    os << "    enum Enm : long {\n";
    for (const auto& v : spec.values) {
        os << std::format("        {} = {},\n",
            escape(type_name(v.asn1_name), {"present", "value_", "value", "set", "Enm"}),
            v.value);
    }
    if (spec.extensible)
        os << "        /* extensible */\n";
    os << "    };\n";
    os << std::format("    {}() = default;\n", cname);
    os << std::format("    {}(Enm v) {{ value_ = static_cast<long>(v); }}\n", cname);
    os << std::format("    {}& operator=(Enm v) {{ value_ = static_cast<long>(v); return *this; }}\n", cname);
    os << std::format("    Enm present() const {{ return static_cast<Enm>(value_); }}\n");
    os << std::format("    bool operator==(Enm v) const {{ return value_ == static_cast<long>(v); }}\n");
    os << std::format("    bool operator!=(Enm v) const {{ return value_ != static_cast<long>(v); }}\n");
    os << "    using asn1::EnumValue::operator==;\n";
    os << "    using asn1::EnumValue::operator!=;\n";
    os << std::format("    static const asn1::EnumEntry    asn_MAP_value2enum[{}];\n",
                       static_cast<int>(spec.values.size()));
    os << "    static const asn1::EnumSpec     asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";
}

// Moved from Generator::emit_enumerated_cpp — same output, now driven by
// the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
void CppBackend::emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // value2enum table (sorted by value for binary search)
    auto sorted = spec.values;
    std::sort(sorted.begin(), sorted.end(),
              [](const EnumeratedSpec::Value& a, const EnumeratedSpec::Value& b) {
                  return a.value < b.value;
              });

    os << std::format("const asn1::EnumEntry {}::asn_MAP_value2enum[] = {{\n", cname);
    for (const auto& v : sorted)
        os << std::format("    {{ {}, \"{}\" }},\n", v.value, v.asn1_name);
    os << "};\n\n";

    // PER: root values in definition order (ordinal -> value mapping). File-local — not in header.
    os << std::format("static const long asn_PER_{}_value_order[] = {{\n", cname);
    for (int i = 0; i < spec.root_count; ++i)
        os << std::format("    {},\n", spec.values[i].value);
    os << "};\n\n";

    // EnumSpec
    os << std::format("const asn1::EnumSpec {}::asn_SPC = {{\n", cname);
    os << std::format("    {}::asn_MAP_value2enum,\n", cname);
    os << std::format("    {},\n", static_cast<int>(sorted.size()));
    os << std::format("    {}, /* extensible */\n", spec.extensible ? "true" : "false");
    os << std::format("    {}, /* root_count */\n", spec.root_count);
    os << std::format("    asn_PER_{}_value_order\n", cname);
    os << "};\n\n";

    // TypeDescriptor
    emit_type_descriptor(os, cname, spec.xer_name,
        std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Enumerated),
        true, false, false, false, "asn1::TypeKind::Enumerated",
        "&asn1::per_enumerated_handler", "&asn1::ber_enumerated_handler",
        /*use_class_scope=*/true);
}

// Build a Constraints designated-initializer literal for an INTEGER
// constraint. Moved from Generator.cpp (was `static`, file-local).
// Declared (not `static`) in CppBackend.hpp since Generator.cpp's
// emit_member_type_descriptor still needs it for inline-constrained-member
// INTEGER handling, not yet migrated. Uses designated initializers (C++20)
// so struct field additions don't require updating every call site.
std::string make_integer_pc(int flags, int range_bits, int int_kind,
                             int64_t lower_s64, int64_t upper_s64,
                             uint64_t lower_u64, uint64_t upper_u64) {
    return std::format(
        "{{ .flags={}, .range_bits={}, .int_kind={}, "
        ".lower_bound={}, .upper_bound={}, "
        ".lower_u64={:#x}u, .upper_u64={:#x}u, "
        ".lower_hi=0, .lower_lo=0, .upper_hi=0, .upper_lo=0 }}",
        flags, range_bits, int_kind,
        lower_s64, upper_s64,
        lower_u64, upper_u64);
}

// Moved from Generator::emit_integer_hpp — same output, now driven by the
// backend-agnostic IntegerSpec instead of ast::TypeDef.
// Note: the alias storage type here (__int128/std::vector<uint8_t> for
// I128/ARBITRARY) deliberately differs from native_int_type()'s
// asn1::BigInteger/asn1::ArbitraryInteger — those wrapper classes have
// deleted constructors (stub, "not yet implemented"), so aliasing a named
// top-level type to one of them would make the alias unusable. This
// distinction is pre-existing behavior, preserved as-is, not introduced by
// this move.
void CppBackend::emit_integer_hpp(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    std::string cpp_storage;
    switch (spec.storage_kind) {
        case IntStorageKind::U64:       cpp_storage = "asn1::UInteger"; break;
        case IntStorageKind::I128:      cpp_storage = "__int128"; break;
        case IntStorageKind::ARBITRARY: cpp_storage = "std::vector<uint8_t>"; break;
        default:                        cpp_storage = "asn1::Integer"; break;
    }
    os << std::format("using {} = {};\n\n", cname, cpp_storage);

    for (const auto& v : spec.named_values)
        os << std::format("inline constexpr int64_t {}_{} = {};\n",
                           cname, value_name(v.asn1_name), v.value);
    if (!spec.named_values.empty()) os << "\n";

    os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
}

// Moved from Generator::emit_integer_cpp — same output, now driven by the
// backend-agnostic IntegerSpec instead of ast::TypeDef /
// Generator::extract_integer_range(). Hand-rolls its own TypeDescriptor
// emission (doesn't reuse emit_type_descriptor) because INTEGER's
// `.constraints` field holds a real populated Constraints value, not the
// enum/seq/choice/seqof sub-descriptor pointers emit_type_descriptor emits.
void CppBackend::emit_integer_cpp(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    int ik = (spec.storage_kind == IntStorageKind::U64)       ? asn1::Constraints::INT_U64
           : (spec.storage_kind == IntStorageKind::I128)      ? asn1::Constraints::INT_I128
           : (spec.storage_kind == IntStorageKind::ARBITRARY) ? asn1::Constraints::INT_ARBITRARY
           : asn1::Constraints::INT_S64;

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", spec.xer_name);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Integer);
    os << "    nullptr, nullptr, nullptr, nullptr,\n";
    if (spec.has_constraint) {
        if (spec.semi_constrained) {
            int flags = asn1::Constraints::SEMI_CONSTRAINED
                      | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
            os << std::format("    {} /* constraints — semi-constrained */,\n",
                make_integer_pc(flags, -1, ik, spec.lower_s64, 0,
                    spec.lower_u64, std::numeric_limits<uint64_t>::max()));
        } else if (spec.hi_is_large) {
            int flags = asn1::Constraints::CONSTRAINED
                      | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
            os << std::format("    {} /* constraints — constrained large (up to UINT64_MAX) */,\n",
                make_integer_pc(flags, spec.range_bits, ik, spec.lower_s64, spec.upper_s64,
                    spec.lower_u64, spec.upper_u64));
        } else {
            int flags = asn1::Constraints::CONSTRAINED
                      | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
            os << std::format("    {} /* constraints */,\n",
                make_integer_pc(flags, spec.range_bits, ik, spec.lower_s64, spec.upper_s64,
                    spec.lower_u64, spec.upper_u64));
        }
    } else {
        os << "    {} /* constraints — unconstrained */,\n";
    }
    const char* per_h = (ik == asn1::Constraints::INT_U64)
        ? "&asn1::per_uinteger_handler" : "&asn1::per_integer_handler";
    const char* ber_h = (ik == asn1::Constraints::INT_U64)
        ? "&asn1::ber_uinteger_handler" : "&asn1::ber_integer_handler";
    const char* cpp_t = (ik == asn1::Constraints::INT_U64)
        ? "asn1::UInteger" : "asn1::Integer";
    os << std::format("    false, asn1::TypeKind::Primitive,\n");
    os << std::format("    {} /* per_handler */,\n", per_h);
    os << std::format("    {} /* ber_handler */,\n", ber_h);
    os << std::format("    asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) /* lifecycle */\n", cpp_t);
    os << "};\n";
}

// Maps a builtin type (never SEQUENCE/CHOICE/TypeRef — BuiltinAliasSpec is
// only built for plain ast::BuiltinType bodies) to its C++ runtime type, for
// TypeLifecycleOps<T>. A small, self-contained subset of what
// Generator::cpp_type_for computes for the general case (which also handles
// SEQUENCE/CHOICE/TypeRef/SEQUENCE OF — out of scope here).
static std::string native_builtin_type(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Boolean:          return "asn1::Boolean";
    case BT::Real:             return "asn1::Real";
    case BT::Null:             return "asn1::Null";
    case BT::BitString:        return "asn1::BitString";
    case BT::OctetString:      return "asn1::OctetString";
    case BT::ObjectIdentifier: return "asn1::Oid";
    case BT::RelativeOid:      return "asn1::RelativeOid";
    case BT::Utf8String:       return "asn1::Utf8String";
    case BT::NumericString:    return "asn1::NumericString";
    case BT::PrintableString:  return "asn1::PrintableString";
    case BT::T61String:        return "asn1::T61String";
    case BT::Ia5String:        return "asn1::Ia5String";
    case BT::VisibleString:    return "asn1::VisibleString";
    case BT::GeneralString:    return "asn1::GeneralString";
    case BT::GraphicString:    return "asn1::GraphicString";
    case BT::UniversalString:  return "asn1::UniversalString";
    case BT::BmpString:        return "asn1::BmpString";
    case BT::VideotexString:   return "asn1::VideotexString";
    case BT::ObjectDescriptor: return "asn1::ObjectDescriptor";
    case BT::UtcTime:          return "asn1::UtcTime";
    case BT::GeneralizedTime:  return "asn1::GeneralizedTime";
    case BT::Any:              return "asn1::OctetString";
    default:                   return "asn1::OctetString";  // Integer/Enumerated: unreachable here
    }
}

// Moved from Generator::emit_builtin_alias_cpp — same output, now driven by
// the backend-agnostic BuiltinAliasSpec instead of ast::TypeDef.
void CppBackend::emit_builtin_alias_cpp(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // Handler LUTs indexed by ast::BuiltinType (Boolean=0 .. Any=23).
    // Integer and Enumerated are never routed here (handled by separate emit functions).
    static const char* const per_lut[] = {
        "&asn1::per_boolean_handler",    // Boolean       = 0
        "&asn1::per_integer_handler",    // Integer       = 1  (unreachable)
        "&asn1::per_bitstring_handler",  // BitString     = 2
        "&asn1::per_octetstring_handler",// OctetString   = 3
        "&asn1::per_null_handler",       // Null          = 4
        "&asn1::per_oid_handler",        // ObjectIdentifier = 5
        "&asn1::per_reloid_handler",     // RelativeOid   = 6
        "&asn1::per_real_handler",       // Real          = 7
        "&asn1::per_enumerated_handler", // Enumerated    = 8  (unreachable)
        "&asn1::per_string_handler",     // Utf8String    = 9
        "&asn1::per_string_handler",     // NumericString = 10
        "&asn1::per_string_handler",     // PrintableString=11
        "&asn1::per_string_handler",     // T61String     = 12
        "&asn1::per_string_handler",     // VideotexString= 13
        "&asn1::per_string_handler",     // Ia5String     = 14
        "&asn1::per_string_handler",     // GraphicString = 15
        "&asn1::per_string_handler",     // VisibleString = 16
        "&asn1::per_string_handler",     // GeneralString = 17
        "&asn1::per_string_handler",     // UniversalString=18
        "&asn1::per_string_handler",     // BmpString     = 19
        "&asn1::per_string_handler",     // ObjectDescriptor=20
        "&asn1::per_string_handler",     // UtcTime       = 21
        "&asn1::per_string_handler",     // GeneralizedTime=22
        "&asn1::per_any_handler",        // Any           = 23
    };
    static const char* const ber_lut[] = {
        "&asn1::ber_boolean_handler",    // Boolean       = 0
        "&asn1::ber_integer_handler",    // Integer       = 1  (unreachable)
        "&asn1::ber_bitstring_handler",  // BitString     = 2
        "&asn1::ber_octetstring_handler",// OctetString   = 3
        "&asn1::ber_null_handler",       // Null          = 4
        "&asn1::ber_oid_handler",        // ObjectIdentifier = 5
        "&asn1::ber_reloid_handler",     // RelativeOid   = 6
        "&asn1::ber_real_handler",       // Real          = 7
        "&asn1::ber_enumerated_handler", // Enumerated    = 8  (unreachable)
        "&asn1::ber_string_handler",     // Utf8String    = 9
        "&asn1::ber_string_handler",     // NumericString = 10
        "&asn1::ber_string_handler",     // PrintableString=11
        "&asn1::ber_string_handler",     // T61String     = 12
        "&asn1::ber_string_handler",     // VideotexString= 13
        "&asn1::ber_string_handler",     // Ia5String     = 14
        "&asn1::ber_string_handler",     // GraphicString = 15
        "&asn1::ber_string_handler",     // VisibleString = 16
        "&asn1::ber_string_handler",     // GeneralString = 17
        "&asn1::ber_string_handler",     // UniversalString=18
        "&asn1::ber_string_handler",     // BmpString     = 19
        "&asn1::ber_string_handler",     // ObjectDescriptor=20
        "&asn1::ber_utctime_handler",    // UtcTime       = 21
        "&asn1::ber_gentime_handler",    // GeneralizedTime=22
        "&asn1::ber_any_handler",        // Any           = 23
    };
    const char* per_h = per_lut[static_cast<int>(spec.builtin_type)];
    const char* ber_h = ber_lut[static_cast<int>(spec.builtin_type)];

    bool needs_per = !spec.alphabet.empty() || spec.has_size_constraint;

    // Emit FROM-alphabet static arrays before the TypeDescriptor so they can be
    // referenced by the Constraints initializer inside it.
    std::string alpha_prefix;
    if (!spec.alphabet.empty()) {
        alpha_prefix = std::format("asn_FROM_{}", cname);
        emit_from_alphabet_arrays(os, alpha_prefix, spec.alphabet);
    }

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", spec.xer_name);
    os << std::format("    {},\n", spec.tag ? format_tag_literal(*spec.tag) : "asn1::Tag{}");
    os << "    nullptr, nullptr, nullptr, nullptr,\n";

    if (needs_per) {
        int flags = asn1::Constraints::CONSTRAINED
                  | (spec.has_size_constraint ? asn1::Constraints::SIZE_CONSTRAINED : 0)
                  | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
        std::optional<ast::BuiltinType> bbt = spec.alphabet.empty()
            ? std::optional{spec.builtin_type} : std::nullopt;
        os << "    " << make_string_constraints_init(flags, spec.size_range_bits,
                                                      spec.size_lower, spec.size_upper,
                                                      spec.alphabet, alpha_prefix, bbt)
           << " /* constraints */,\n";
    } else {
        os << "    {} /* constraints — unconstrained */,\n";
    }
    std::string cpp_t = native_builtin_type(spec.builtin_type);
    os << std::format("    false, asn1::TypeKind::Primitive,\n");
    os << std::format("    {} /* per_handler */,\n", per_h);
    os << std::format("    {} /* ber_handler */,\n", ber_h);
    os << std::format("    asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) /* lifecycle */", cpp_t);
    if (spec.xer_base64)
        os << ",\n    asn1::XerEncoding::Base64 /* xer_encoding */\n";
    else
        os << "\n";
    os << "};\n";
}

} // namespace asn1::codegen
