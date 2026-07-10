#include "CppBackend.hpp"
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <limits>

namespace asn1::codegen {

// Moved verbatim from Generator.cpp (was `static`, file-local) —
// gambas-asn1#226. No behavior change: same parameters, same output.
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

// Moved from Generator::emit_enumerated_hpp (gambas-asn1#226) — same output,
// now driven by the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
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

// Moved from Generator::emit_enumerated_cpp (gambas-asn1#226) — same output,
// now driven by the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
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
// constraint. Moved from Generator.cpp (was `static`, file-local) —
// gambas-asn1#227. Declared (not `static`) in CppBackend.hpp since
// Generator.cpp's emit_member_type_descriptor still needs it for inline-
// constrained-member INTEGER handling, not yet migrated. Uses designated
// initializers (C++20) so struct field additions don't require updating
// every call site.
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

// Moved from Generator::emit_integer_hpp (gambas-asn1#227) — same output,
// now driven by the backend-agnostic IntegerSpec instead of ast::TypeDef.
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

// Moved from Generator::emit_integer_cpp (gambas-asn1#227) — same output,
// now driven by the backend-agnostic IntegerSpec instead of ast::TypeDef /
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

} // namespace asn1::codegen
