#include "Generator.hpp"
#include <algorithm>
#include <limits>
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/TypeDescriptor.hpp"
#include "asn1cpp/codec/PerConstraints.hpp"

namespace asn1::codegen {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string Generator::cpp_type_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Boolean:           return "asn1::Boolean";
        case BT::Integer:           return "asn1::Integer";
        case BT::Real:              return "asn1::Real";
        case BT::Null:              return "asn1::Null";
        case BT::BitString:         return "asn1::BitString";
        case BT::OctetString:       return "asn1::OctetString";
        case BT::ObjectIdentifier:  return "asn1::Oid";
        case BT::RelativeOid:       return "asn1::RelativeOid";
        case BT::Enumerated:        return to_cpp_name(def.name.empty() ? "Enum" : def.name);
        case BT::Utf8String:        return "asn1::Utf8String";
        case BT::NumericString:     return "asn1::NumericString";
        case BT::PrintableString:   return "asn1::PrintableString";
        case BT::T61String:         return "asn1::T61String";
        case BT::Ia5String:         return "asn1::Ia5String";
        case BT::VisibleString:     return "asn1::VisibleString";
        case BT::GeneralString:     return "asn1::GeneralString";
        case BT::GraphicString:     return "asn1::GraphicString";
        case BT::UniversalString:   return "asn1::UniversalString";
        case BT::BmpString:         return "asn1::BmpString";
        case BT::VideotexString:    return "asn1::VideotexString";
        case BT::ObjectDescriptor:  return "asn1::ObjectDescriptor";
        case BT::UtcTime:           return "asn1::UtcTime";
        case BT::GeneralizedTime:   return "asn1::GeneralizedTime";
        case BT::Any:               return "asn1::OctetString";
        }
    }
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body))
        return to_cpp_name(tr->type_name);
    if (def.is_seq_of()) {
        const auto& sof = std::get<ast::SequenceOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_sequence() || def.is_choice())
        return to_cpp_name(def.name.empty() ? "Anon" : def.name);
    return "asn1::OctetString";
}

// Returns "asn1::Tag{...}" literal for a tag override, empty string if absent.
std::string Generator::tag_literal(const ast::Tag& tag, bool constructed) {
    if (!tag.present()) return "";
    std::string cls;
    switch (tag.cls) {
    case ast::TagClass::Universal:   cls = "asn1::TagClass::Universal";   break;
    case ast::TagClass::Application: cls = "asn1::TagClass::Application"; break;
    case ast::TagClass::Private:     cls = "asn1::TagClass::Private";     break;
    default:                         cls = "asn1::TagClass::Context";     break;
    }
    return std::format("asn1::Tag{{{}, {}, {}}}", cls, tag.number,
                        constructed ? "true" : "false");
}

// Returns the natural (universal) tag for a member def's underlying type.
std::string Generator::natural_tag_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Boolean:           return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Boolean);
        case BT::Integer:           return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Integer);
        case BT::BitString:         return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::BitString);
        case BT::OctetString:       return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::OctetString);
        case BT::Null:              return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Null);
        case BT::ObjectIdentifier:  return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Oid);
        case BT::Real:              return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Real);
        case BT::Enumerated:        return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Enumerated);
        case BT::Utf8String:        return "asn1::Tag::universal(12, false)";
        case BT::NumericString:     return "asn1::Tag::universal(18, false)";
        case BT::PrintableString:   return "asn1::Tag::universal(19, false)";
        case BT::T61String:         return "asn1::Tag::universal(20, false)";
        case BT::Ia5String:         return "asn1::Tag::universal(22, false)";
        case BT::VisibleString:     return "asn1::Tag::universal(26, false)";
        case BT::GeneralString:     return "asn1::Tag::universal(27, false)";
        case BT::GraphicString:     return "asn1::Tag::universal(25, false)";
        case BT::UniversalString:   return "asn1::Tag::universal(28, false)";
        case BT::BmpString:         return "asn1::Tag::universal(30, false)";
        case BT::UtcTime:           return "asn1::Tag::universal(23, false)";
        case BT::GeneralizedTime:   return "asn1::Tag::universal(24, false)";
        default: break;
        }
    }
    if (def.is_sequence() || def.is_set())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    if (def.is_choice())
        return "";  // CHOICE has no universal tag
    if (def.is_seq_of() || def.is_set_of())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    return "asn1::Tag::universal(4, false)";  // fallback: OCTET STRING
}

// Returns the &asn_DEF_* expression for a member's type_descriptor field.
// Returns "nullptr" for types where the runtime can infer encoding from the tag alone,
// and "&asn_DEF_<Name>" for generated or named types.
static std::string type_descriptor_ref_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Integer:           return "&asn1::asn_DEF_Integer";
        case BT::Boolean:           return "&asn1::asn_DEF_Boolean";
        case BT::OctetString:       return "&asn1::asn_DEF_OctetString";
        case BT::Utf8String:        return "&asn1::asn_DEF_Utf8String";
        case BT::Ia5String:         return "&asn1::asn_DEF_Ia5String";
        default:                    return "nullptr";
        }
    }
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body))
        return std::format("&asn_DEF_{}", to_cpp_name(tr->type_name));
    if (def.is_sequence() || def.is_choice() || def.is_seq_of() || def.is_set_of() || def.is_set())
        return std::format("&asn_DEF_{}", to_cpp_name(def.name.empty() ? "Anon" : def.name));
    return "nullptr";
}

// Returns true if this is a type assignment (not a value or class assignment).
// Value assignments have a non-monostate default_value (the assigned value).
static bool is_type_assignment(const ast::TypeDef& def) {
    if (std::holds_alternative<std::monostate>(def.body)) return false;
    if (def.is_extension_marker) return false;
    // Value assignments (lowercase names) have default_value set by the grammar.
    if (!std::holds_alternative<std::monostate>(def.default_value)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Emit ENUMERATED
// ---------------------------------------------------------------------------

void Generator::emit_enumerated_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    // Count non-extension enum values
    int count = 0;
    bool extensible = false;
    for (const auto& ev : def.enum_values) {
        if (ev.name == "...") { extensible = true; continue; }
        ++count;
    }

    // enum class
    os << std::format("enum class {} : long {{\n", cname);
    long auto_val = 0;
    for (const auto& ev : def.enum_values) {
        if (ev.name == "...") { auto_val = 0; continue; }  // extension root ends
        long v = static_cast<long>(ev.number.value_or(auto_val));
        os << std::format("    {} = {},\n", to_cpp_name(ev.name), v);
        auto_val = v + 1;
    }
    if (extensible)
        os << "    /* extensible */\n";
    os << "};\n\n";

    // Extern descriptor declarations (defined in .cpp)
    os << std::format("extern const asn1::EnumEntry   asn_MAP_{}_value2enum[{}];\n", cname, count);
    os << std::format("extern const asn1::EnumSpec     asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n\n", cname);

    // BerTraits declaration
    os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
    os << "    static asn1::Tag tag();\n";
    os << std::format("    static void encode(asn1::BerWriter&, const {}&);\n", cname);
    os << std::format("    static asn1::Expected<{}, asn1::DecodeError> decode(asn1::BerReader&);\n", cname);
    os << "};\n";
}

void Generator::emit_enumerated_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    // Collect root values (before first "...")
    bool extensible = false;
    int ext_root_count = 0;
    long auto_val = 0;
    struct EV { long value; std::string name; };
    std::vector<EV> root_values;

    for (const auto& ev : def.enum_values) {
        if (ev.name == "...") { extensible = true; break; }
        long v = static_cast<long>(ev.number.value_or(auto_val));
        root_values.push_back({v, ev.name});
        auto_val = v + 1;
        ++ext_root_count;
    }
    // Also collect extension values
    bool past_ext = false;
    long auto_ext = 0;
    for (const auto& ev : def.enum_values) {
        if (!past_ext) { if (ev.name == "...") past_ext = true; continue; }
        long v = static_cast<long>(ev.number.value_or(auto_ext));
        root_values.push_back({v, ev.name});
        auto_ext = v + 1;
    }

    // value2enum table (sorted by value for binary search)
    auto sorted = root_values;
    std::sort(sorted.begin(), sorted.end(), [](const EV& a, const EV& b){ return a.value < b.value; });

    os << std::format("const asn1::EnumEntry asn_MAP_{}_value2enum[] = {{\n", cname);
    for (const auto& ev : sorted)
        os << std::format("    {{ {}, \"{}\" }},\n", ev.value, ev.name);
    os << "};\n\n";

    // PER: root values in definition order (ordinal → value mapping).
    // root_values holds root entries in definition order (before sorting).
    os << std::format("const long asn_PER_{}_value_order[] = {{\n", cname);
    for (int i = 0; i < ext_root_count; ++i)
        os << std::format("    {},\n", root_values[i].value);
    os << "};\n\n";

    // EnumSpec
    os << std::format("const asn1::EnumSpec asn_SPC_{} = {{\n", cname);
    os << std::format("    asn_MAP_{}_value2enum,\n", cname);
    os << std::format("    {},\n", (int)sorted.size());
    os << std::format("    {}, /* extensible */\n", extensible ? "true" : "false");
    os << std::format("    {}, /* root_count */\n", ext_root_count);
    os << std::format("    asn_PER_{}_value_order\n", cname);
    os << "};\n\n";

    // TypeDescriptor
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", cname);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Enumerated);
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr, nullptr, nullptr /* per_constraints */\n";
    os << "};\n\n";

    // BerTraits bodies — thin wrappers; all logic lives in BerCodec
    os << std::format("asn1::Tag asn1::BerTraits<{}>::tag() {{\n", cname);
    os << std::format("    return asn_DEF_{}.tag;\n", cname);
    os << "}\n\n";

    os << std::format("void asn1::BerTraits<{}>::encode(asn1::BerWriter& w, const {}& v) {{\n", cname, cname);
    os << "    asn1::BerEncodeStream s{w};\n";
    os << std::format("    asn1::BerCodec::instance().encode(s, asn_DEF_{}, &v);\n", cname);
    os << "}\n\n";

    os << std::format("asn1::Expected<{0}, asn1::DecodeError>\n"
                      "asn1::BerTraits<{0}>::decode(asn1::BerReader& r) {{\n", cname);
    os << std::format("    {} result{{}};\n", cname);
    os << "    asn1::BerDecodeStream s{r};\n";
    os << std::format("    auto ok = asn1::BerCodec::instance().decode(s, asn_DEF_{}, &result);\n", cname);
    os << std::format("    if (!ok) return asn1::make_unexpected<{}, asn1::DecodeError>(ok.error());\n", cname);
    os << "    return result;\n";
    os << "}\n";
}

// ---------------------------------------------------------------------------
// Emit INTEGER
// ---------------------------------------------------------------------------

void Generator::emit_integer_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    os << std::format("using {} = int64_t;\n\n", cname);

    // Named integer constants (INTEGER { foo(0), bar(1) } style)
    for (const auto& ev : def.enum_values)
        os << std::format("inline constexpr int64_t {}_{} = {};\n",
            cname, to_cpp_name(ev.name), ev.number.value_or(0));
    if (!def.enum_values.empty()) os << "\n";

    os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
}

// Try to extract a concrete int64_t from a Value, resolving NamedValueRef via resolver.
std::optional<int64_t> Generator::resolve_int_value(const ast::Value& v) const {
    if (auto* i = std::get_if<int64_t>(&v)) return *i;
    if (auto* ref = std::get_if<ast::NamedValueRef>(&v)) {
        auto def = resolver_.lookup(ref->name);
        if (def) {
            if (auto* i = std::get_if<int64_t>(&def->default_value)) return *i;
        }
    }
    return std::nullopt;
}

// Extract integer value range from constraints, if determinable.
std::optional<std::pair<int64_t,int64_t>>
Generator::extract_integer_range(const ast::TypeDef& def) const {
    for (const auto& cptr : def.constraints) {
        if (!cptr) continue;
        auto* vr = std::get_if<ast::ValueRange>(&cptr->body);
        if (!vr) continue;
        std::optional<int64_t> lo, hi;
        if (vr->lower.kind == ast::RangeEndpoint::Kind::Min)
            lo = std::numeric_limits<int64_t>::min();
        else
            lo = resolve_int_value(vr->lower.value);
        if (vr->upper.kind == ast::RangeEndpoint::Kind::Max)
            hi = std::numeric_limits<int64_t>::max();
        else
            hi = resolve_int_value(vr->upper.value);
        if (lo && hi) return std::make_pair(*lo, *hi);
    }
    return std::nullopt;
}

void Generator::emit_integer_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    auto range = extract_integer_range(def);
    std::string per_ptr = "nullptr /* unconstrained */";

    if (range) {
        int64_t lo = range->first, hi = range->second;
        int64_t range_count = hi - lo + 1;  // may overflow for very wide ranges; acceptable
        // ceil(log2(range_count))
        int rb = 0;
        if (range_count > 1) {
            for (int64_t r = range_count - 1; r > 0; r >>= 1) ++rb;
        }
        os << std::format("static const asn1::PerConstraints asn_PER_{}_constr = {{\n", cname);
        os << std::format("    asn1::PerConstraints::CONSTRAINED,\n");
        os << std::format("    {}, /* range_bits */\n", rb);
        os << std::format("    {}, /* lower_bound */\n", lo);
        os << std::format("    {}, /* upper_bound */\n", hi);
        os << "    0, 0, 0 /* size constraints unused */\n";
        os << "};\n\n";
        per_ptr = std::format("&asn_PER_{}_constr", cname);
    }

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", cname);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Integer);
    os << "    nullptr, nullptr, nullptr,\n";
    os << std::format("    {} /* per_constraints */\n", per_ptr);
    os << "};\n";
}

// ---------------------------------------------------------------------------
// Emit SEQUENCE / SET
// ---------------------------------------------------------------------------

void Generator::emit_sequence_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    // Count non-extension members
    int mcount = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = mcount; continue; }
        ++mcount;
    }

    // #include referenced types
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        if (auto* tr = std::get_if<ast::TypeRef>(&m->body))
            os << std::format("#include \"{}.hpp\"\n", to_cpp_name(tr->type_name));
    }
    if (mcount > 0) os << "\n";

    // struct
    os << std::format("struct {} {{\n", cname);
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string mtype = cpp_type_for(*m);
        std::string mname = to_member_name(m->name);
        if (m->is_optional())
            os << std::format("    std::optional<{}> {};\n", mtype, mname);
        else
            os << std::format("    {} {}{{}};\n", mtype, mname);
    }
    os << "};\n\n";

    // Extern descriptor declarations
    if (mcount > 0)
        os << std::format("extern const asn1::MemberDescriptor asn_MBR_{}[{}];\n", cname, mcount);
    os << std::format("extern const asn1::SequenceSpec     asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

    // BerTraits declaration
    os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
    os << std::format("    static asn1::Tag tag() {{ return asn1::Tag::universal({}, true); }}\n", tag_num);
    os << std::format("    static void encode(asn1::BerWriter&, const {}&);\n", cname);
    os << std::format("    static asn1::Expected<{}, asn1::DecodeError> decode(asn1::BerReader&);\n", cname);
    os << "};\n";
}

void Generator::emit_sequence_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    int mcount = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = mcount; continue; }
        ++mcount;
    }

    // Member descriptor table
    if (mcount > 0) {
        os << std::format("const asn1::MemberDescriptor asn_MBR_{}[] = {{\n", cname);
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string mname = to_member_name(m->name);
            bool optional = m->is_optional();

            // Effective tag
            std::string eff_tag;
            if (m->tag.present()) {
                bool constr = m->is_sequence() || m->is_choice() || m->is_seq_of() || m->is_set_of() || m->is_set();
                eff_tag = tag_literal(m->tag, constr);
            } else {
                eff_tag = natural_tag_for(*m);
            }

            os << std::format("    {{ \"{}\", {}, {}, false, offsetof({}, {}), {} }},\n",
                m->name, eff_tag,
                optional ? "true" : "false",
                cname, mname,
                type_descriptor_ref_for(*m));
        }
        os << "};\n\n";
    }

    // SequenceSpec
    os << std::format("const asn1::SequenceSpec asn_SPC_{} = {{\n", cname);
    if (mcount > 0)
        os << std::format("    asn_MBR_{},\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", mcount);
    os << std::format("    {}, /* ext_at */\n", ext_at);
    os << "    0, 0, nullptr /* PER: roms_count, aoms_count, oms */\n";
    os << "};\n\n";

    // TypeDescriptor
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", cname);
    os << std::format("    asn1::Tag::universal({}, true),\n", tag_num);
    os << "    nullptr,\n";
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr, nullptr /* per_constraints */\n";
    os << "};\n\n";

    // BerTraits encode
    os << std::format("void asn1::BerTraits<{}>::encode(asn1::BerWriter& w, const {}& v) {{\n", cname, cname);
    os << std::format("    w.write_constructed(asn_DEF_{}.tag, [&](asn1::BerWriter& inner) {{\n", cname);
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string fname = to_member_name(m->name);
        std::string mtype = cpp_type_for(*m);
        if (m->is_optional())
            os << std::format("        if (v.{0}) asn1::BerTraits<{1}>::encode(inner, *v.{0});\n", fname, mtype);
        else
            os << std::format("        asn1::BerTraits<{}>::encode(inner, v.{});\n", mtype, fname);
    }
    os << "    });\n}\n\n";

    // BerTraits decode
    os << std::format("asn1::Expected<{0}, asn1::DecodeError>\n"
                      "asn1::BerTraits<{0}>::decode(asn1::BerReader& r) {{\n", cname);
    os << "    auto tlv = r.read_tlv();\n";
    os << std::format("    if (!tlv) return asn1::make_unexpected<{}, asn1::DecodeError>(tlv.error());\n", cname);
    os << std::format("    {} result{{}};\n", cname);
    os << "    asn1::BerReader inner = r.sub(tlv->value);\n";
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string fname = to_member_name(m->name);
        std::string mtype = cpp_type_for(*m);
        if (m->is_optional()) {
            os << std::format("    if (!inner.at_end()) {{\n");
            os << std::format("        auto val = asn1::BerTraits<{}>::decode(inner);\n", mtype);
            os << std::format("        if (val) result.{} = std::move(*val);\n", fname);
            os << "    }\n";
        } else {
            os << "    {\n";
            os << std::format("        auto val = asn1::BerTraits<{}>::decode(inner);\n", mtype);
            os << std::format("        if (!val) return asn1::make_unexpected<{}, asn1::DecodeError>(val.error());\n", cname);
            os << std::format("        result.{} = std::move(*val);\n", fname);
            os << "    }\n";
        }
    }
    os << "    return result;\n}\n";
}

// ---------------------------------------------------------------------------
// Emit CHOICE
// ---------------------------------------------------------------------------

void Generator::emit_choice_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    int count = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = count; continue; }
        ++count;
    }

    // #include referenced alternative types
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        if (auto* tr = std::get_if<ast::TypeRef>(&m->body))
            os << std::format("#include \"{}.hpp\"\n", to_cpp_name(tr->type_name));
    }
    if (count > 0) os << "\n";

    // struct with PR enum + variant
    os << std::format("struct {} {{\n", cname);
    os << "    enum class PR {";
    os << " NOTHING";
    for (const auto& m : def.members)
        if (!m->is_extension_marker)
            os << std::format(", {}", to_cpp_name(m->name));
    os << " };\n";
    os << "    PR present{PR::NOTHING};\n";
    os << "    std::variant<std::monostate";
    for (const auto& m : def.members)
        if (!m->is_extension_marker)
            os << std::format(", {}", cpp_type_for(*m));
    os << "> choice;\n";
    os << "};\n\n";

    // Extern descriptor declarations
    if (count > 0)
        os << std::format("extern const asn1::MemberDescriptor asn_MBR_{}[{}];\n", cname, count);
    os << std::format("extern const asn1::ChoiceSpec       asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

    // BerTraits declaration (CHOICE has no universal tag — it's transparent)
    os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
    os << std::format("    static void encode(asn1::BerWriter&, const {}&);\n", cname);
    os << std::format("    static asn1::Expected<{}, asn1::DecodeError> decode(asn1::BerReader&);\n", cname);
    os << "};\n";
}

void Generator::emit_choice_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    int count = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = count; continue; }
        ++count;
    }

    // Alternative descriptor table
    if (count > 0) {
        os << std::format("const asn1::MemberDescriptor asn_MBR_{}[] = {{\n", cname);
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string mname = to_member_name(m->name);
            std::string eff_tag;
            if (m->tag.present()) {
                bool constr = m->is_sequence() || m->is_choice() || m->is_seq_of() || m->is_set_of() || m->is_set();
                eff_tag = tag_literal(m->tag, constr);
            } else {
                eff_tag = natural_tag_for(*m);
            }
            os << std::format("    {{ \"{}\", {}, false, false, 0, {} }},\n",
                m->name, eff_tag,
                type_descriptor_ref_for(*m));
        }
        os << "};\n\n";
    }

    // ChoiceSpec
    os << std::format("const asn1::ChoiceSpec asn_SPC_{} = {{\n", cname);
    if (count > 0)
        os << std::format("    asn_MBR_{},\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", count);
    os << std::format("    {}, /* ext_at */\n", ext_at);
    os << "    nullptr /* PER: per_constraints */\n";
    os << "};\n\n";

    // TypeDescriptor (CHOICE has no fixed universal tag)
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", cname);
    os << "    asn1::Tag{asn1::TagClass::Context, 0, false}, /* placeholder — CHOICE tag is transparent */\n";
    os << "    nullptr, nullptr,\n";
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr /* per_constraints */\n";
    os << "};\n\n";

    // BerTraits encode — std::visit over variant
    os << std::format("void asn1::BerTraits<{}>::encode(asn1::BerWriter& w, const {}& v) {{\n", cname, cname);
    os << "    std::visit([&](const auto& alt) {\n";
    os << "        using T = std::decay_t<decltype(alt)>;\n";
    os << "        if constexpr (!std::is_same_v<T, std::monostate>)\n";
    os << "            asn1::BerTraits<T>::encode(w, alt);\n";
    os << "    }, v.choice);\n";
    os << "}\n\n";

    // BerTraits decode — peek tag, dispatch to matching alternative
    os << std::format("asn1::Expected<{0}, asn1::DecodeError>\n"
                      "asn1::BerTraits<{0}>::decode(asn1::BerReader& r) {{\n", cname);
    os << std::format("    {} result{{}};\n", cname);

    // Emit if-chain keyed on tag
    int idx = 0;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string mtype = cpp_type_for(*m);
        std::string pr_name = to_cpp_name(m->name);
        std::string eff_tag;
        if (m->tag.present()) {
            bool constr = m->is_sequence() || m->is_choice() || m->is_seq_of() || m->is_set_of() || m->is_set();
            eff_tag = tag_literal(m->tag, constr);
        } else {
            eff_tag = natural_tag_for(*m);
        }

        if (!eff_tag.empty()) {
            os << std::format("    {} if (r.peek_tag() == {}) {{\n",
                (idx == 0 ? "" : "} else"), eff_tag);
        } else {
            // CHOICE alternative is itself a CHOICE — no fixed tag; try decode
            os << std::format("    {} {{\n", (idx == 0 ? "" : "} else"));
        }
        os << std::format("        auto val = asn1::BerTraits<{}>::decode(r);\n", mtype);
        os << std::format("        if (!val) return asn1::make_unexpected<{}, asn1::DecodeError>(val.error());\n", cname);
        os << std::format("        result.present = {}::PR::{};\n", cname, pr_name);
        os << std::format("        result.choice  = std::move(*val);\n");
        ++idx;
    }
    if (idx > 0) {
        os << "    } else {\n";
        os << std::format("        return asn1::make_unexpected<{}, asn1::DecodeError>(\n", cname);
        os << std::format("            asn1::DecodeError(\"unknown CHOICE alternative for {}\"));\n", cname);
        os << "    }\n";
    }
    os << "    return result;\n}\n";
}

// ---------------------------------------------------------------------------
// Top-level emit_hpp / emit_cpp dispatch
// ---------------------------------------------------------------------------

void Generator::emit_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);

    os << "#pragma once\n";
    os << "#include <optional>\n";
    os << "#include <variant>\n";
    os << "#include <vector>\n";
    os << "#include <span>\n";
    os << "#include <asn1cpp/asn1cpp.hpp>\n\n";

    if (def.is_sequence() || def.is_set()) {
        emit_sequence_hpp(def, os);
    } else if (def.is_choice()) {
        emit_choice_hpp(def, os);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated) {
            emit_enumerated_hpp(def, os);
        } else if (*bt == ast::BuiltinType::Integer) {
            emit_integer_hpp(def, os);
        } else {
            os << std::format("using {} = {};\n", cname, cpp_type_for(def));
        }
    } else if (def.is_seq_of() || def.is_set_of()) {
        const auto& elem = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body).element
            : std::get<ast::SetOfType>(def.body).element;
        if (auto* tr = std::get_if<ast::TypeRef>(&elem->body))
            os << std::format("#include \"{}.hpp\"\n\n", to_cpp_name(tr->type_name));
        os << std::format("using {} = std::vector<{}>;\n", cname, cpp_type_for(*elem));
    } else if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        os << std::format("#include \"{}.hpp\"\n", to_cpp_name(tr->type_name));
        os << std::format("using {} = {};\n", cname, to_cpp_name(tr->type_name));
    }
}

void Generator::emit_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    os << std::format("#include \"{}.hpp\"\n\n", cname);

    if (def.is_sequence() || def.is_set()) {
        emit_sequence_cpp(def, os);
    } else if (def.is_choice()) {
        emit_choice_cpp(def, os);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated)
            emit_enumerated_cpp(def, os);
        else if (*bt == ast::BuiltinType::Integer)
            emit_integer_cpp(def, os);
    }
}

// ---------------------------------------------------------------------------
// Per-type file writer
// ---------------------------------------------------------------------------

void Generator::generate_type(const ast::TypeDef& def, const std::string& /*module_name*/) {
    if (!is_type_assignment(def)) return;

    std::string cname = to_cpp_name(def.name);

    {
        std::ofstream hpp(out_dir_ / (cname + ".hpp"));
        emit_hpp(def, hpp);
    }

    auto bt_is = [&](ast::BuiltinType t) {
        auto* bt = std::get_if<ast::BuiltinType>(&def.body);
        return bt && *bt == t;
    };
    bool needs_cpp = def.is_sequence() || def.is_set() || def.is_choice()
        || bt_is(ast::BuiltinType::Enumerated)
        || bt_is(ast::BuiltinType::Integer);
    if (needs_cpp) {
        std::ofstream cpp(out_dir_ / (cname + ".cpp"));
        emit_cpp(def, cpp);
    }
}

} // namespace asn1::codegen
