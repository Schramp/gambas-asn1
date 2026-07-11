#include "CppBackend.hpp"
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <array>
#include <limits>

namespace asn1::codegen {

/// @brief Format a tag decision as a C++ `asn1::Tag{...}` literal string.
/// @param tag_spec The decision to format (class, number, encoding form).
/// @return A C++ expression string, e.g. `"asn1::Tag{asn1::TagClass::Context, 1, false}"`.
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

/// @brief Returns the name of the global `asn_DEF_*` descriptor for a
///        restricted built-in string type, or nullptr for types without a
///        fixed alphabet (UTF8String, etc.).
/// @param bt  Built-in type tag.
/// @return Pointer to a string literal such as `"asn_DEF_NumericString"`, or nullptr.
/// @see X.680 §41 — restricted character string types and their canonical alphabets.
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

/// @brief Emit static FROM-alphabet lookup tables (decode + encode arrays)
///        into a generated `.cpp` file.
/// @param os       Output stream for the generated `.cpp` file.
/// @param prefix   Name prefix used for the static arrays (e.g. `"asn_FROM_MyStr"`).
/// @param alphabet Sorted FROM-alphabet character values (non-empty).
/// @see X.691 §26.5 — known-multiplier character string PER encoding.
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

/// @brief Return a `Constraints` aggregate-initializer string for a character string type.
/// @param flags         Constraints::flags bitmask (SIZE_CONSTRAINED, EXTENSIBLE, …).
/// @param sc_range_bits Bits needed for SIZE range encoding.
/// @param sc_lower      SIZE lower bound.
/// @param sc_upper      SIZE upper bound.
/// @param alphabet      Sorted FROM-alphabet character values; empty = no FROM constraint.
/// @param alpha_prefix  Name prefix of the static arrays emitted by emit_from_alphabet_arrays;
///                      empty when alphabet is empty.
/// @param builtin_bt    Base string type whose global `asn_DEF_*` descriptor carries the
///                      alphabet tables; used to inherit alphabet_bits/alphabet/encode_table
///                      when there is a SIZE constraint but no FROM constraint. nullopt = skip.
/// @return Initializer string, e.g. `"{ .flags=8, .size_lower=6, .size_upper=6, … }"`.
/// @see X.691 §26.5 (character string PER encoding); X.691 §12 (size constraints).
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

/// @brief Map a builtin type to its C++ runtime type, for `TypeLifecycleOps<T>`.
/// @param bt Built-in type tag (never SEQUENCE/CHOICE/TypeRef/INTEGER/
///           ENUMERATED — `BuiltinAliasSpec` is only built for plain
///           `ast::BuiltinType` bodies other than those two).
/// @return C++ runtime type name, e.g. `"asn1::OctetString"`.
/// @note A small, self-contained subset of what `Generator::cpp_type_for`
///       computes for the general case (which also handles SEQUENCE/CHOICE/
///       TypeRef/SEQUENCE OF — out of scope here).
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

/// @brief Emit the `.cpp` TypeDescriptor for a builtin-alias type.
/// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
/// @param os   Output stream to write to.
/// @brief PER codec-handler LUT indexed by ast::BuiltinType (Boolean=0 ..
///        Any=23). Integer and Enumerated entries are never looked up
///        (those builtins are handled by separate emit functions) — kept
///        for direct index alignment with the enum.
/// @note Shared between emit_builtin_alias_cpp (top-level builtin-alias
///       types) and emit_member_type_descriptor (inline-constrained
///       SIZE-able members) — both need the same builtin-type -> handler
///       mapping.
static const char* per_handler_for_builtin(ast::BuiltinType bt) {
    static const char* const lut[] = {
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
    return lut[static_cast<int>(bt)];
}

/// @brief BER codec-handler LUT indexed by ast::BuiltinType. See
///        per_handler_for_builtin's note — same sharing rationale.
static const char* ber_handler_for_builtin(ast::BuiltinType bt) {
    static const char* const lut[] = {
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
    return lut[static_cast<int>(bt)];
}

void CppBackend::emit_builtin_alias_cpp(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    const char* per_h = per_handler_for_builtin(spec.builtin_type);
    const char* ber_h = ber_handler_for_builtin(spec.builtin_type);

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
                  | (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
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

/// @brief Format a DEFAULT value decision as a C++ initializer expression.
/// @param mtype C++ type name to construct/qualify.
/// @param spec  The decision to format (see Generator::default_value_spec_for).
/// @return e.g. `"MyType{true}"`, `"MyType{\"esc\\\"aped\"}"`, `"MyEnum::Foo"`,
///         or "" for `Kind::None`.
static std::string format_default_value_literal(const std::string& mtype,
                                                  const DefaultValueSpec& spec,
                                                  const Backend& backend) {
    using Kind = DefaultValueSpec::Kind;
    switch (spec.kind) {
    case Kind::Bool:
        return std::format("{}{{{}}}", mtype, spec.bool_val ? "true" : "false");
    case Kind::Int:
        return std::format("{}{{{}}}", mtype, spec.int_val);
    case Kind::String:
        return std::format("{}{{\"{}\"}}", mtype, escape_string_literal(spec.string_val));
    case Kind::EnumRef:
        return std::format("{}::{}", mtype, backend.escape(backend.type_name(spec.enum_name)));
    case Kind::None:
    default:
        return "";
    }
}

void CppBackend::emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                                      const std::string& parent_name, const std::string& member_name,
                                      std::ostream& os) const {
    std::string literal = format_default_value_literal(type_name, spec, *this);
    std::string fname  = std::format("_setdef_{}_{}", parent_name, member_name);
    std::string cname2 = std::format("_isdef_{}_{}", parent_name, member_name);
    os << std::format(
        "static void {0}(asn1::Asn1Object* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    Ops::set(p, true);\n"
        "    *static_cast<{3}*>(Ops::get(p)) = {4};\n"
        "}}\n",
        fname, parent_name, member_name, type_name, literal);
    os << std::format(
        "static bool {0}(const asn1::Asn1Object* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    if (!Ops::check(p)) return false;\n"
        "    return *static_cast<const {3}*>(Ops::get(const_cast<asn1::Asn1Object*>(p))) == ({4});\n"
        "}}\n",
        cname2, parent_name, member_name, type_name, literal);
}

void CppBackend::emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, std::ostream& os) const {
    using Kind = MemberTypeDescriptorSpec::Kind;
    std::string pc, per_h, ber_h, cpp_t, xer_tail;

    if (spec.kind == Kind::Integer) {
        // int_kind LUT indexed by IntStorageKind (S64=0, U64=1, I128=2, ARBITRARY=3).
        static const int int_kind_lut[] = {
            asn1::Constraints::INT_S64, asn1::Constraints::INT_U64,
            asn1::Constraints::INT_I128, asn1::Constraints::INT_ARBITRARY,
        };
        int ik = int_kind_lut[static_cast<int>(spec.storage_kind)];
        if (spec.semi_constrained) {
            int flags = asn1::Constraints::SEMI_CONSTRAINED
                      | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
            pc = make_integer_pc(flags, -1, ik, spec.lower_s64, 0,
                                  spec.lower_u64, std::numeric_limits<uint64_t>::max());
        } else {
            int flags = asn1::Constraints::CONSTRAINED
                      | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
            pc = make_integer_pc(flags, spec.range_bits, ik, spec.lower_s64, spec.upper_s64,
                                  spec.lower_u64, spec.upper_u64);
        }
        bool is_u64 = spec.storage_kind == IntStorageKind::U64;
        per_h = is_u64 ? "&asn1::per_uinteger_handler" : "&asn1::per_integer_handler";
        ber_h = is_u64 ? "&asn1::ber_uinteger_handler" : "&asn1::ber_integer_handler";
        cpp_t = is_u64 ? "asn1::UInteger" : "asn1::Integer";
    } else {
        if (!spec.alpha_prefix.empty())
            emit_from_alphabet_arrays(os, spec.alpha_prefix, spec.alphabet);
        int all_flags = (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
                       | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
        std::optional<ast::BuiltinType> bbt = spec.alphabet.empty()
            ? std::optional{spec.builtin_type} : std::nullopt;
        bool use_default = !spec.has_size_constraint && spec.alphabet.empty()
                          && (!bbt || !builtin_def_name(*bbt));
        pc = use_default
            ? "{}"
            : make_string_constraints_init(all_flags, spec.size_range_bits, spec.size_lower,
                                            spec.size_upper, spec.alphabet, spec.alpha_prefix, bbt);
        // Same builtin-type -> handler LUTs as emit_builtin_alias_cpp; every
        // type reachable here (string family, OctetString, BitString) maps
        // identically whether it's a top-level alias or an inline member.
        per_h = per_handler_for_builtin(spec.builtin_type);
        ber_h = ber_handler_for_builtin(spec.builtin_type);
        cpp_t = native_builtin_type(spec.builtin_type);
        xer_tail = spec.needs_xer ? ", asn1::XerEncoding::Base64" : "";
    }

    os << std::format(
        "static const asn1::TypeDescriptor {} = "
        "{{ \"{}\", asn1::Tag::universal({}, false), "
        "nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive, {}, {}, "
        "asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}){}}};\n",
        spec.tname, spec.xer_type_name, spec.universal_tag, pc,
        per_h, ber_h, cpp_t, xer_tail);
}

void CppBackend::emit_seq_of_cpp(const SeqOfSpec& spec, std::ostream& os) const {
    os << std::format("const asn1::SeqOfSpec asn_SPC_{} = {{\n", spec.type_name);
    os << std::format("    {},\n", spec.elem_ref);
    int flags = spec.size_upper ? asn1::Constraints::SIZE_CONSTRAINED : 0;
    os << std::format("    {{ .flags={}, .size_range_bits={}, .size_lower={}, .size_upper={} }},\n",
                      flags, spec.range_bits, spec.size_lower, spec.size_upper.value_or(0));
    if (spec.elem_xer_name)
        os << std::format("    \"{}\",\n", *spec.elem_xer_name);
    os << "};\n\n";

    uint32_t of_tag = spec.is_set_of ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;
    emit_type_descriptor(os, spec.type_name, spec.xer_name,
        std::format("asn1::Tag::universal({}, true)", of_tag),
        false, false, false, true, "asn1::TypeKind::SeqOf",
        "&asn1::per_seqof_handler", "&asn1::ber_seqof_handler");
}

void CppBackend::emit_sequence_hpp(const SequenceSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // class — optional members use unique_ptr (forward-decl compatible, matches asn1c semantics)
    os << std::format("class {} : public asn1::SequenceBase<{}> {{\npublic:\n", cname, cname);
    if (spec.has_optional_members) {
        // All special members declared (not defaulted) so unique_ptr<T> destructor/assignment
        // has complete T in the .cpp where they are defined = default.
        // Copy ctor delegates to the default ctor (ensuring all members are constructed)
        // then calls deep_copy to reproduce the source's state field-by-field.
        os << std::format("    {0}();\n", cname);
        os << std::format("    ~{0}();\n", cname);
        os << std::format("    {0}(const {0}& o);\n", cname);
        os << std::format("    {0}& operator=(const {0}& o);\n", cname);
        os << std::format("    {0}({0}&&) noexcept;\n", cname);
        os << std::format("    {0}& operator=({0}&&) noexcept;\n", cname);
    }
    for (const auto& r : spec.members) {
        if (r.optional)
            os << std::format("    std::unique_ptr<{}> {};\n", r.mtype, r.mname);
        else
            os << std::format("    {} {}{{}};\n", r.mtype, r.mname);
    }
    // set_<member> declarations for non-optional members only
    for (const auto& r : spec.members) {
        if (r.optional || r.setter_param_type.empty()) continue;
        os << std::format("    void set_{}({} val);\n", r.mname, r.setter_param_type);
    }
    if (spec.mcount > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_members[{}];\n", spec.mcount);
        os << "    static const int s_member_count;\n";
    }
    os << "    static const asn1::SequenceSpec   asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";
}

void CppBackend::emit_sequence_cpp(const SequenceSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // Special member function definitions and Ops type aliases were already
    // emitted by Generator::emit_sequence_cpp (before this call) — both must
    // precede the member table below (emit_default_setter's generated
    // static functions reference the Ops aliases by name), and neither
    // needs any per-member decision content.

    // Member descriptor table
    if (spec.mcount > 0) {
        os << std::format("const asn1::MemberDescriptor {}::s_members[] = {{\n", cname);
        for (const auto& r : spec.members) {
            // Emit &_isdef_… reference only when the default-value helper
            // pair was actually emitted. emit_default_setter() returns
            // "nullptr" (no _setdef_/_isdef_ generated) for default-value
            // forms it doesn't understand yet — INTEGER with named values,
            // arbitrary IntegerLiteral, etc. Without this gate the member
            // table would reference an undefined _isdef_ symbol.
            std::string def_cmp = (r.has_default && r.def_setter != "nullptr")
                ? std::format("&_isdef_{}_{}", cname, r.mname)
                : "nullptr";
            os << std::format("    {{ \"{}\", {}, {}, {}, {}, {}, {}, {}, {}, {} }},\n",
                r.asn1_name, r.eff_tag,
                r.optional ? "true" : "false",
                r.has_default ? "true" : "false",
                r.offset_expr,
                r.tdref, r.ops,
                r.is_explicit ? "true" : "false",
                r.def_setter, def_cmp);
        }
        os << "};\n";
        os << std::format("const int {}::s_member_count = {};\n\n", cname, spec.mcount);
    }

    // SequenceSpec
    os << std::format("const asn1::SequenceSpec {}::asn_SPC = {{\n", cname);
    if (spec.mcount > 0)
        os << std::format("    {}::s_members,\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", spec.mcount);
    os << std::format("    {}, /* ext_at */\n", spec.ext_at);
    os << std::format("    {}, 0, nullptr /* PER: roms_count, aoms_count, oms */\n", spec.roms_count);
    os << "};\n\n";

    // TypeDescriptor
    uint32_t tag_num = spec.is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;
    emit_type_descriptor(os, cname,
        spec.xer_name,
        std::format("asn1::Tag::universal({}, true)", tag_num),
        false, true, false, false, "asn1::TypeKind::Sequence",
        "&asn1::per_sequence_handler", "&asn1::ber_sequence_handler",
        /*use_class_scope=*/true);

    // set_<member> definitions (ASN1CPP_VALIDATE_ON_SET hook)
    for (const auto& r : spec.members) {
        if (r.setter_param_type.empty()) continue;
        // tdref is "&asn_DEF_Foo" or "&asn_TYP_Parent_member"; strip leading &
        std::string tdname = (r.tdref.size() > 1 && r.tdref[0] == '&')
            ? r.tdref.substr(1) : r.tdref;
        std::string assign = r.setter_is_move
            ? std::format("{} = std::move(val);", r.mname)
            : (r.setter_is_int_alias || r.setter_is_uint_alias
                ? std::format("{} = val;", r.mname)
                : std::format("{}.set(val);", r.mname));
        std::string validate_expr = r.setter_is_int_alias
            ? std::format("asn1::Integer{{{}}}.validate({}.constraints)", r.mname, tdname)
            : r.setter_is_uint_alias
                ? std::format("asn1::UInteger{{{}}}.validate({}.constraints)", r.mname, tdname)
                : std::format("{}.validate({}.constraints)", r.mname, tdname);
        os << std::format("void {}::set_{}({} val) {{\n", cname, r.mname, r.setter_param_type);
        os << std::format("    {}\n", assign);
        os << "#if defined(ASN1CPP_VALIDATE_ON_SET) && defined(ASN1CPP_VALIDATE)\n";
        os << std::format("    if ({}) asn1::bump_validate_fail();\n", validate_expr);
        os << "#endif\n";
        os << "}\n";
    }
    if (!spec.members.empty()) os << "\n";
}

/// @brief Emit the class declaration for a CHOICE type.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
///
/// Storage strategy: raw byte buffer sized/aligned to the largest alternative.
///
/// Why not std::variant<T1, T2, ..., TN>?
///   std::variant is implemented via recursive template specialisations.
///   std::get<K> descends K levels of template recursion.  With N alternatives and
///   N different get<K> calls, GCC instantiates O(N²) templates.  For a CHOICE
///   with 198 alternatives (e.g. XIRIContents in the ETSI LI schema) this
///   consumes ~5 GB RSS and kills the build.
///
/// Why a char buffer instead of a typed union?
///   A union { T1 a; T2 b; ... } still needs per-member access syntax and doesn't
///   help with the destructor/copy dispatch problem.  A raw char[] + placement new
///   lets the ChoiceOps<T> template carry all type knowledge, keeping the header
///   O(N) in both parse and instantiation cost.
///
/// How it works:
///   alignas(max_align) char val_[max_size]   — in-place storage, no heap
///     max_size  = std::max({sizeof(T1), ..., sizeof(TN)})   — constexpr O(N) scan
///     max_align = std::max({alignof(T1), ..., alignof(TN)}) — constexpr O(N) scan
///   active_lifecycle — pointer into TypeDescriptor::lifecycle of the current alternative;
///   set by ChoiceInterface::emplace_alt. destroy/move ops reached via one pointer deref.
///   std::launder is required on every read-back after placement-new (C++17 §6.8.4).
void CppBackend::emit_choice_hpp(const ChoiceSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    os << std::format("class {} : public asn1::ChoiceInterface {{\npublic:\n", cname);
    os << "    enum class PR : int { NOTHING = 0";
    int pr_idx = 1;
    for (const auto& a : spec.alternatives)
        os << std::format(", {} = {}", a.pr_name, pr_idx++);
    os << " };\n";

    // val_storage_: raw byte buffer sized/aligned to the largest alternative.
    // val_ (in ChoiceInterface base) points here — set once in the constructor.
    os << "    alignas(std::max({";
    { bool first = true;
      for (const auto& a : spec.alternatives) {
        if (!first) os << ", ";
        os << std::format("alignof({})", a.mtype);
        first = false;
      }
      if (spec.count > 0) os << ", ";
      os << "size_t(1)})) char val_storage_[std::max({";
    }
    { bool first = true;
      for (const auto& a : spec.alternatives) {
        if (!first) os << ", ";
        os << std::format("sizeof({})", a.mtype);
        first = false;
      }
      if (spec.count > 0) os << ", ";
      os << "size_t(1)})] {};\n";
    }

    // Special members.
    // Constructor sets val_ to val_storage_ so ChoiceInterface::emplace_alt / accessors work.
    os << std::format("    {0}() {{ val_ = val_storage_; }}\n", cname);
    os << std::format(
        "    ~{0}() {{ active_lifecycle->destroy(val_); }}\n", cname);
    os << std::format("    {0}(const {0}& o);\n", cname);
    os << std::format("    {0}& operator=(const {0}& o);\n", cname);
    os << std::format(
        "    {0}({0}&& o) noexcept {{"
        " val_ = val_storage_;"
        " _present = o._present; o._present = 0;"
        " active_lifecycle = o.active_lifecycle;"
        " o.active_lifecycle = &asn1::ChoiceInterface::k_noop_lifecycle;"
        " active_lifecycle->move(val_, o.val_); }}\n", cname);
    os << std::format(
        "    {0}& operator=({0}&& o) noexcept {{"
        " if (this != &o) {{"
        " active_lifecycle->destroy(val_);"
        " _present = o._present; o._present = 0;"
        " active_lifecycle = o.active_lifecycle;"
        " o.active_lifecycle = &asn1::ChoiceInterface::k_noop_lifecycle;"
        " active_lifecycle->move(val_, o.val_);"
        " }} return *this; }}\n", cname);

    os << "    PR present() const { return static_cast<PR>(_present); }\n";
    // set_present delegates to emplace_alt (ChoiceInterface) — defined in .cpp.
    os << "    void set_present(PR p);\n";

    for (const auto& a : spec.alternatives) {
        os << std::format(
            "    {0}& {1}() {{ return *std::launder(reinterpret_cast<{0}*>(val_)); }}\n", a.mtype, a.accessor_name);
        os << std::format(
            "    const {0}& {1}() const"
            " {{ return *std::launder(reinterpret_cast<const {0}*>(val_)); }}\n", a.mtype, a.accessor_name);
    }
    if (spec.count > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_alternatives[{}];\n", spec.count);
        os << "    static const int s_alternative_count;\n";
    }
    os << "    static const asn1::ChoiceSpec     asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";
}

/// @brief Emit the implementation/definition for a CHOICE type.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
void CppBackend::emit_choice_cpp(const ChoiceSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    if (!spec.alternatives.empty()) {
        // Emit array (as class static member definition).
        os << std::format("const asn1::MemberDescriptor {}::s_alternatives[] = {{\n", cname);
        for (const auto& r : spec.alternatives) {
            os << std::format("    {{ \"{}\", {}, false, false, asn1::kInvalidMemberOffset, {}, {{}}, {}, nullptr, nullptr,\n",
                r.asn1_name, r.eff_tag, r.tdref, r.is_explicit ? "true" : "false");
            os << std::format("      &asn1::ChoiceOps<{0}>::get_mut, &asn1::ChoiceOps<{0}>::get_const }},\n",
                r.mtype);
        }
        os << "};\n";
        os << std::format("const int {}::s_alternative_count = {};\n\n", cname, spec.count);

        // set_present: resets the active alternative then activates the requested one.
        // emplace_alt (generic in ChoiceInterface) handles construction via TypeDescriptor::lifecycle.
        os << std::format(
            "void {0}::set_present(PR p) {{\n"
            "    active_lifecycle->destroy(val_);\n"
            "    active_lifecycle = &asn1::ChoiceInterface::k_noop_lifecycle;\n"
            "    _present = 0;\n"
            "    if (p == PR::NOTHING) return;\n"
            "    int idx = static_cast<int>(p) - 1;\n"
            "    if (idx >= 0 && idx < s_alternative_count)\n"
            "        emplace_alt(s_alternatives[idx]);\n"
            "    _present = static_cast<int>(p);\n"
            "}}\n\n", cname);

        // Copy constructor: initialise as NOTHING (val_ = val_storage_), then deep-copy.
        os << std::format(
            "{0}::{0}(const {0}& o) {{ val_ = val_storage_; asn1::deep_copy(asn_DEF, this, &o); }}\n", cname);
        os << std::format(
            "{0}& {0}::operator=(const {0}& o) {{ if (this != &o) asn1::deep_copy(asn_DEF, this, &o); return *this; }}\n\n",
            cname);
    }

    // O(1) context-tag dispatch table.
    if (spec.has_tag_index) {
        os << std::format("static const int16_t asn_TAGIDX_{}[] = {{", cname);
        for (std::size_t i = 0; i < spec.tag_index_table.size(); ++i)
            os << (i ? ", " : "") << spec.tag_index_table[i];
        os << "};\n\n";
    }

    // Flattened BER dispatch table.
    if (spec.has_ber_table) {
        os << std::format("static const asn1::ChoiceTagEntry asn_BER_{}[] = {{\n", cname);
        for (const auto& [tag_lit, idx] : spec.ber_tags)
            os << std::format("    {{ {}, {} }},\n", tag_lit, idx);
        os << "};\n\n";
    }

    // ChoiceSpec
    os << std::format("const asn1::ChoiceSpec {}::asn_SPC = {{\n", cname);
    if (spec.count > 0)
        os << std::format("    {}::s_alternatives,\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", spec.count);
    os << std::format("    {}, /* ext_at */\n", spec.ext_at);
    os << "    {} /* PER: constraints */\n";
    if (spec.has_ber_table)
        os << std::format("    , asn_BER_{0}, {1} /* ber_tags */\n", cname, (int)spec.ber_tags.size());
    else if (spec.has_tag_index)
        os << "    , nullptr, 0 /* ber_tags */\n";
    if (spec.has_tag_index)
        os << std::format("    , asn_TAGIDX_{0}, {1}, {2} /* tag_index */\n",
                          cname, spec.tag_index_base, (int)spec.tag_index_table.size());
    os << "};\n\n";

    // TypeDescriptor — CHOICE tag is a transparent placeholder (no fixed universal tag)
    emit_type_descriptor(os, cname, spec.xer_name,
        "asn1::Tag{asn1::TagClass::Context, 0, false}",
        false, false, true, false, "asn1::TypeKind::Choice",
        "&asn1::per_choice_handler", "&asn1::ber_choice_handler",
        /*use_class_scope=*/true);
}

} // namespace asn1::codegen
