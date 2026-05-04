#include "Generator.hpp"
#include <algorithm>
#include <functional>
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
        case BT::Enumerated: {
            auto n = to_cpp_name(def.name.empty() ? "Enum" : def.name);
            if (!n.empty()) n[0] = (char)std::toupper(n[0]);
            // Inline ENUMERATED member (has enum values, not top-level)
            if (!current_type_.empty() && !def.enum_values.empty())
                return current_type_ + n;
            return n;
        }
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
        return cpp_name_for_typeref(*tr);
    if (def.is_seq_of()) {
        const auto& sof = std::get<ast::SequenceOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_sequence() || def.is_choice() || def.is_set()) {
        auto n = to_cpp_name(def.name.empty() ? "Anon" : def.name);
        if (!n.empty()) n[0] = (char)std::toupper(n[0]);
        return current_type_ + n;
    }
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
        case BT::RelativeOid:       return std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::RelativeOid);
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
        case BT::VideotexString:    return "asn1::Tag::universal(21, false)";
        case BT::ObjectDescriptor:  return "asn1::Tag::universal(7, false)";
        case BT::UtcTime:           return "asn1::Tag::universal(23, false)";
        case BT::GeneralizedTime:   return "asn1::Tag::universal(24, false)";
        case BT::Any:               return "asn1::Tag::universal( 4, false)";
        default: break;
        }
    }
    if (def.is_sequence() || def.is_set())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    if (def.is_choice())
        return "";  // CHOICE has no universal tag
    if (def.is_seq_of() || def.is_set_of())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto base = resolver_.resolve_ref(*tr);
        if (base) return natural_tag_for(*base);
    }
    return "asn1::Tag::universal(4, false)";  // fallback: OCTET STRING
}

// Returns the &asn_DEF_* expression for a member's type_descriptor field.
// C++ keywords that may not be used as identifiers.
static bool is_cpp_keyword(const std::string& s) {
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
    return kw.count(s) > 0;
}

// Escape a C++ identifier if it collides with a keyword.
inline std::string safe_cpp_name(const std::string& s) {
    return is_cpp_keyword(s) ? s + "_" : s;
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
// type_descriptor_ref_for — Generator member (collision-aware)
// ---------------------------------------------------------------------------

std::string Generator::type_descriptor_ref_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Integer:           return "&asn1::asn_DEF_Integer";
        case BT::Boolean:           return "&asn1::asn_DEF_Boolean";
        case BT::Null:              return "&asn1::asn_DEF_Null";
        case BT::Real:              return "&asn1::asn_DEF_Real";
        case BT::BitString:         return "&asn1::asn_DEF_BitString";
        case BT::ObjectIdentifier:  return "&asn1::asn_DEF_Oid";
        case BT::RelativeOid:       return "&asn1::asn_DEF_RelativeOid";
        case BT::UtcTime:           return "&asn1::asn_DEF_UtcTime";
        case BT::GeneralizedTime:   return "&asn1::asn_DEF_GeneralizedTime";
        case BT::OctetString:       return "&asn1::asn_DEF_OctetString";
        case BT::Utf8String:        return "&asn1::asn_DEF_Utf8String";
        case BT::Ia5String:         return "&asn1::asn_DEF_Ia5String";
        case BT::NumericString:     return "&asn1::asn_DEF_NumericString";
        case BT::PrintableString:   return "&asn1::asn_DEF_PrintableString";
        case BT::T61String:         return "&asn1::asn_DEF_T61String";
        case BT::VisibleString:     return "&asn1::asn_DEF_VisibleString";
        case BT::GeneralString:     return "&asn1::asn_DEF_GeneralString";
        case BT::GraphicString:     return "&asn1::asn_DEF_GraphicString";
        case BT::UniversalString:   return "&asn1::asn_DEF_UniversalString";
        case BT::BmpString:         return "&asn1::asn_DEF_BmpString";
        case BT::VideotexString:    return "&asn1::asn_DEF_VideotexString";
        case BT::ObjectDescriptor:  return "&asn1::asn_DEF_ObjectDescriptor";
        case BT::Any:               return "&asn1::asn_DEF_Any";
        case BT::Enumerated:        break; // handled below — inline ENUMERATED needs synthetic name
        default:                    return "nullptr";
        }
    }
    // Inline ENUMERATED member — use synthetic name
    if (auto* bt2 = std::get_if<BT>(&def.body);
        bt2 && *bt2 == BT::Enumerated && !def.enum_values.empty() && !current_type_.empty()) {
        auto n = to_cpp_name(def.name.empty() ? "Enum" : def.name);
        if (!n.empty()) n[0] = (char)std::toupper(n[0]);
        return std::format("&asn_DEF_{}", current_type_ + n);
    }
    // Named type reference.
    // Pure TypeRef aliases (e.g. "LawfulInterceptionIdentifier ::= LIID") generate only a
    // C++ `using` declaration — no asn_DEF_. Follow the chain until reaching a type that
    // generates its own asn_DEF_ (BuiltinType with constraints, SEQUENCE, CHOICE, etc.).
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        // For collision types, resolve_ref uses global_ and may pick the wrong module's version.
        // Prefer the current-module's definition (local shadows global), fall back to resolve_ref.
        // Skip this logic for qualified references (module_name set) — they pin the source module.
        if (tr->module_name.empty() && collision_types_.count(to_cpp_name(tr->type_name))) {
            std::string def_mod = resolver_.module_of(tr->type_name, current_module_);
            if (!def_mod.empty()) {
                auto td = resolver_.resolve_in_module(tr->type_name, def_mod);
                if (td && std::get_if<ast::TypeRef>(&td->body))
                    return type_descriptor_ref_for(*td);  // pure alias — follow chain
                if (td)  // concrete type — use local module's asn_DEF_
                    return std::format("&asn_DEF_{}", effective_cpp_name(tr->type_name, def_mod));
            }
        }
        auto resolved = resolver_.resolve_ref(*tr);
        if (resolved && !resolved->name.empty()) {
            if (std::get_if<ast::TypeRef>(&resolved->body))
                return type_descriptor_ref_for(*resolved);  // pure alias — follow chain
            // Qualified ref: use explicit module for collision disambiguation on resolved name.
            if (!tr->module_name.empty() && collision_types_.count(to_cpp_name(resolved->name)))
                return std::format("&asn_DEF_{}", effective_cpp_name(resolved->name, tr->module_name));
            return std::format("&asn_DEF_{}", cpp_name_for_ref(resolved->name, current_module_));
        }
        return std::format("&asn_DEF_{}", cpp_name_for_typeref(*tr));
    }
    // SEQUENCE OF / SET OF — named member uses synthetic SeqOf wrapper descriptor
    if (def.is_seq_of()) {
        if (!def.name.empty()) {
            std::string sn = to_cpp_name(def.name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            return std::format("&asn_DEF_{}", current_type_ + sn);
        }
        const auto& elem = std::get<ast::SequenceOfType>(def.body).element;
        return type_descriptor_ref_for(*elem);
    }
    if (def.is_set_of()) {
        if (!def.name.empty()) {
            std::string sn = to_cpp_name(def.name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            return std::format("&asn_DEF_{}", current_type_ + sn);
        }
        const auto& elem = std::get<ast::SetOfType>(def.body).element;
        return type_descriptor_ref_for(*elem);
    }
    // Inline SEQUENCE / CHOICE / SET member — synthetic name = parent + member
    if (def.is_sequence() || def.is_choice() || def.is_set()) {
        auto n = to_cpp_name(def.name.empty() ? "Anon" : def.name);
        if (!n.empty()) n[0] = (char)std::toupper(n[0]);
        return std::format("&asn_DEF_{}", current_type_ + n);
    }
    return "nullptr";
}

// ---------------------------------------------------------------------------
// Emit ENUMERATED
// ---------------------------------------------------------------------------

void Generator::emit_enumerated_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

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
        if (ev.name == "...") { continue; }
        long v = static_cast<long>(ev.number.value_or(auto_val));
        os << std::format("    {} = {},\n", safe_cpp_name(to_cpp_name(ev.name)), v);
        auto_val = v + 1;
    }
    if (extensible)
        os << "    /* extensible */\n";
    os << "};\n\n";

    // Extern descriptor declarations (defined in .cpp)
    os << std::format("extern const asn1::EnumEntry   asn_MAP_{}_value2enum[{}];\n", cname, count);
    os << std::format("extern const asn1::EnumSpec     asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n\n", cname);

}

void Generator::emit_enumerated_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

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
    // Also collect extension values (auto-numbering continues from last root value)
    bool past_ext = false;
    for (const auto& ev : def.enum_values) {
        if (!past_ext) { if (ev.name == "...") past_ext = true; continue; }
        long v = static_cast<long>(ev.number.value_or(auto_val));
        root_values.push_back({v, ev.name});
        auto_val = v + 1;
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
    os << std::format("    \"{}\",\n", def.name);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Enumerated);
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr, nullptr, nullptr, {} /* per_constraints */\n";
    os << "};\n\n";

}

// ---------------------------------------------------------------------------
// Emit INTEGER
// ---------------------------------------------------------------------------

void Generator::emit_integer_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    os << std::format("using {} = int64_t;\n\n", cname);

    // Named integer constants (INTEGER { foo(0), bar(1) } style)
    for (const auto& ev : def.enum_values)
        os << std::format("inline constexpr int64_t {}_{} = {};\n",
            cname, to_value_name(ev.name), ev.number.value_or(0));
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

// True if any top-level constraint carries a trailing '...'.
static bool is_constraint_extensible(const ast::TypeDef& def) {
    for (const auto& cptr : def.constraints)
        if (cptr && cptr->extensible) return true;
    return false;
}

// Walk a constraint, including IntersectionConstraint operands, and call f on each body.
template<typename F>
static void walk_constraints(const ast::Constraint& c, F&& f) {
    f(c.body);
    if (auto* ic = std::get_if<ast::IntersectionConstraint>(&c.body))
        for (const auto& op : ic->operands)
            if (op) walk_constraints(*op, f);
}

// Walk all top-level constraints of def (and their IntersectionConstraint subtrees).
template<typename F>
static void walk_type_constraints(const ast::TypeDef& def, F&& f) {
    for (const auto& cptr : def.constraints)
        if (cptr) walk_constraints(*cptr, f);
}

// Extract integer value range from constraints, if determinable.
std::optional<std::pair<int64_t,int64_t>>
Generator::extract_integer_range(const ast::TypeDef& def) const {
    // Intersect all ValueRange constraints (including those nested inside
    // IntersectionConstraint): take max(lowers) and min(uppers).
    std::optional<int64_t> lo, hi;
    walk_type_constraints(def, [&](const ast::ConstraintBody& body) {
        auto* vr = std::get_if<ast::ValueRange>(&body);
        if (!vr) return;
        int64_t vlo = (vr->lower.kind == ast::RangeEndpoint::Kind::Min)
            ? std::numeric_limits<int64_t>::min()
            : resolve_int_value(vr->lower.value).value_or(std::numeric_limits<int64_t>::min());
        int64_t vhi = (vr->upper.kind == ast::RangeEndpoint::Kind::Max)
            ? std::numeric_limits<int64_t>::max()
            : resolve_int_value(vr->upper.value).value_or(std::numeric_limits<int64_t>::max());
        lo = lo ? std::max(*lo, vlo) : vlo;
        hi = hi ? std::min(*hi, vhi) : vhi;
    });
    if (lo && hi) return std::make_pair(*lo, *hi);
    return std::nullopt;
}

void Generator::emit_integer_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto range = extract_integer_range(def);

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.name);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Integer);
    os << "    nullptr, nullptr, nullptr, nullptr,\n";
    if (range) {
        int64_t lo = range->first, hi = range->second;
        bool ext = is_constraint_extensible(def);
        if (hi == std::numeric_limits<int64_t>::max()) {
            // semi-constrained: lb..MAX
            int flags = asn1::PerConstraints::SEMI_CONSTRAINED
                      | (ext ? asn1::PerConstraints::EXTENSIBLE : 0);
            os << std::format("    {{ {}, -1, {}, 0 }} /* per_constraints — semi-constrained */\n", flags, lo);
        } else {
            int64_t range_count = hi - lo + 1;
            int rb = 0;
            if (range_count > 1) {
                for (int64_t r = range_count - 1; r > 0; r >>= 1) ++rb;
            }
            int flags = asn1::PerConstraints::CONSTRAINED
                      | (ext ? asn1::PerConstraints::EXTENSIBLE : 0);
            os << std::format("    {{ {}, {}, {}, {} }} /* per_constraints */\n", flags, rb, lo, hi);
        }
    } else {
        os << "    {} /* per_constraints — unconstrained */\n";
    }
    os << "};\n";
}

// ---------------------------------------------------------------------------
// Emit SEQUENCE / SET
// ---------------------------------------------------------------------------

void Generator::emit_sequence_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    // Count non-extension members
    int mcount = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = mcount; continue; }
        ++mcount;
    }

    // Determine if a member's named type is directly a class (SEQUENCE/CHOICE/SET) and can be
    // forward-declared. Using a direct lookup (not following aliases) is essential: a type alias
    // like `TraceActivation ::= ExternalASNType` generates `using TraceActivation = ...` in C++,
    // which cannot be forward-declared as `class TraceActivation;`.
    auto is_class_type = [&](const ast::TypeDef& m) -> bool {
        if (m.is_sequence() || m.is_choice() || m.is_set()) return true;
        if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
            auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
            return direct && (direct->is_sequence() || direct->is_choice() || direct->is_set());
        }
        return false;
    };

    // Emit includes or forward declarations.
    // Optional class-typed members: forward declaration only (breaks circular includes).
    // Everything else: full include.
    bool past_ext_inc = false;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { past_ext_inc = true; continue; }
        bool optional = m->is_optional() || past_ext_inc;

        auto emit_inc = [&](const std::string& cn) {
            os << std::format("#include \"{}.hpp\"\n", cn);
            track_include(cn);
        };
        auto emit_fwd = [&](const std::string& cn) {
            os << std::format("class {};\n", cn);
            track_include(cn);
        };

        if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
            auto cn = cpp_name_for_typeref(*tr);
            optional && is_class_type(*m) ? emit_fwd(cn) : emit_inc(cn);
        } else if (m->is_seq_of() || m->is_set_of()) {
            if (!m->name.empty()) {
                // Named member — include the synthetic SeqOf wrapper header
                std::string msn = to_cpp_name(m->name);
                if (!msn.empty()) msn[0] = (char)std::toupper(msn[0]);
                emit_inc(cname + msn);
            } else {
                const auto& elem = m->is_seq_of()
                    ? std::get<ast::SequenceOfType>(m->body).element
                    : std::get<ast::SetOfType>(m->body).element;
                if (auto* tr2 = std::get_if<ast::TypeRef>(&elem->body)) {
                    emit_inc(cpp_name_for_typeref(*tr2));
                } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
                    auto esn = to_cpp_name(elem->name.empty() ? "Anon" : elem->name);
                    if (!esn.empty()) esn[0] = (char)std::toupper(esn[0]);
                    emit_inc(cname + esn);
                }
            }
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            std::string sn = to_cpp_name(m->name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            auto synth = cname + sn;
            optional ? emit_fwd(synth) : emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty()) {
                std::string sn = to_cpp_name(m->name);
                if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
                emit_inc(cname + sn);
            }
        }
    }
    if (mcount > 0) os << "\n";

    // Determine if any optional members exist — they will use unique_ptr.
    bool has_optional_members = false;
    {
        bool past = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past = true; continue; }
            if (m->is_optional() || past) { has_optional_members = true; break; }
        }
    }

    // class — optional members use unique_ptr (forward-decl compatible, matches asn1c semantics)
    os << std::format("class {} {{\npublic:\n", cname);
    if (has_optional_members) {
        // All special members declared (not defaulted) so unique_ptr<T> destructor/assignment
        // has complete T in the .cpp where they are defined = default.
        os << std::format("    {0}();\n", cname);
        os << std::format("    ~{0}();\n", cname);
        os << std::format("    {0}({0}&&) noexcept;\n", cname);
        os << std::format("    {0}& operator=({0}&&) noexcept;\n", cname);
    }
    bool past_ext_hpp = false;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { past_ext_hpp = true; continue; }
        std::string mtype = cpp_type_for(*m);
        std::string mname = to_member_name(m->name);
        if (m->is_optional() || past_ext_hpp)
            os << std::format("    std::unique_ptr<{}> {};\n", mtype, mname);
        else
            os << std::format("    {} {}{{}};\n", mtype, mname);
    }
    os << "};\n\n";

    // Extern descriptor declarations
    if (mcount > 0)
        os << std::format("extern const asn1::MemberDescriptor asn_MBR_{}[{}];\n", cname, mcount);
    os << std::format("extern const asn1::SequenceSpec     asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

}

void Generator::emit_sequence_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    int mcount = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = mcount; continue; }
        ++mcount;
    }

    // Determine if any optional members exist (same logic as emit_sequence_hpp).
    bool has_optional_members = false;
    {
        bool past = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past = true; continue; }
            if (m->is_optional() || past) { has_optional_members = true; break; }
        }
    }

    if (has_optional_members) {
        // Forward-declared types in the .hpp need full includes in the .cpp.
        auto is_class_type = [&](const ast::TypeDef& m) -> bool {
            if (m.is_sequence() || m.is_choice() || m.is_set()) return true;
            if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
                auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
                return direct && (direct->is_sequence() || direct->is_choice() || direct->is_set());
            }
            return false;
        };
        bool emitted_extra = false;
        bool past_ext = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past_ext = true; continue; }
            bool optional = m->is_optional() || past_ext;
            if (!optional) continue;
            if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
                if (is_class_type(*m)) {
                    auto cn = cpp_name_for_typeref(*tr);
                    os << std::format("#include \"{}.hpp\"\n", cn);
                    emitted_extra = true;
                }
            } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
                std::string sn = to_cpp_name(m->name);
                if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
                os << std::format("#include \"{}.hpp\"\n", cname + sn);
                emitted_extra = true;
            }
        }
        if (emitted_extra) os << "\n";

        // All special members defined here where unique_ptr<T> has complete T.
        os << std::format("{0}::{0}() = default;\n", cname);
        os << std::format("{0}::~{0}() = default;\n", cname);
        os << std::format("{0}::{0}({0}&&) noexcept = default;\n", cname);
        os << std::format("{0}& {0}::operator=({0}&&) noexcept = default;\n\n", cname);
    }

    // Count root-only optional members (for PER preamble bitmap width)
    int roms_count = 0;
    {
        bool past = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past = true; continue; }
            if (!past && m->is_optional()) ++roms_count;
        }
    }

    // Type aliases for optional member callbacks — one per optional member.
    if (roms_count > 0 || ext_at >= 0) {
        bool past = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past = true; continue; }
            if (!m->is_optional() && !past) continue;
            std::string mname = to_member_name(m->name);
            std::string mtype = cpp_type_for(*m);
            os << std::format(
                "using _Ops_{0}_{1} = asn1::UniquePtrOps<{0}, {2}, &{0}::{1}>;\n",
                cname, mname, mtype);
        }
        os << "\n";
    }

    // Member descriptor table
    if (mcount > 0) {
        os << std::format("const asn1::MemberDescriptor asn_MBR_{}[] = {{\n", cname);
        bool past_ext_mbr = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past_ext_mbr = true; continue; }
            std::string mname = to_member_name(m->name);
            bool optional = m->is_optional() || past_ext_mbr;

            // Effective tag
            std::string eff_tag;
            if (m->tag.present()) {
                bool constr = m->is_sequence() || m->is_choice() || m->is_seq_of() || m->is_set_of() || m->is_set();
                eff_tag = tag_literal(m->tag, constr);
            } else {
                eff_tag = natural_tag_for(*m);
                if (eff_tag.empty()) eff_tag = "asn1::Tag{}";  // CHOICE has no universal tag
            }

            std::string ops = optional
                ? std::format("{{ &_Ops_{0}_{1}::check, &_Ops_{0}_{1}::set, &_Ops_{0}_{1}::get }}", cname, mname)
                : "{}";
            os << std::format("    {{ \"{}\", {}, {}, false, offsetof({}, {}), {}, {} }},\n",
                m->name, eff_tag,
                optional ? "true" : "false",
                cname, mname,
                type_descriptor_ref_for(*m),
                ops);
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
    os << std::format("    {}, 0, nullptr /* PER: roms_count, aoms_count, oms */\n", roms_count);
    os << "};\n\n";

    // TypeDescriptor
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.name);
    os << std::format("    asn1::Tag::universal({}, true),\n", tag_num);
    os << "    nullptr,\n";
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr, nullptr, {} /* per_constraints */\n";
    os << "};\n\n";

}

// ---------------------------------------------------------------------------
// Emit CHOICE
// ---------------------------------------------------------------------------

void Generator::emit_choice_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    int count = 0;
    int ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = count; continue; }
        ++count;
    }

    // #include referenced alternative types and inline-type headers
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        auto emit_inc = [&](const std::string& cn) {
            os << std::format("#include \"{}.hpp\"\n", cn);
            track_include(cn);
        };
        if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
            emit_inc(cpp_name_for_typeref(*tr));
        } else if ((m->is_seq_of() || m->is_set_of()) && !m->name.empty()) {
            // Named SEQUENCE OF alternative — include the synthetic SeqOf wrapper header
            std::string msn = to_cpp_name(m->name);
            if (!msn.empty()) msn[0] = (char)std::toupper(msn[0]);
            auto cn2 = cpp_name_for_ref(cname + msn, current_module_);
            os << std::format("#include \"{}.hpp\"\n", cn2);
            track_include(cn2);
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            std::string sn = to_cpp_name(m->name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            auto synth = cname + sn;
            os << std::format("#include \"{}.hpp\"\n", synth);
            track_include(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty()) {
                std::string sn = to_cpp_name(m->name);
                if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
                auto synth = cname + sn;
                os << std::format("#include \"{}.hpp\"\n", synth);
                track_include(synth);
            }
        }
    }
    if (count > 0) os << "\n";

    // class with PR enum + one named field per alternative
    os << std::format("class {} {{\npublic:\n", cname);
    os << "    enum class PR : int { NOTHING = 0";
    int pr_idx = 1;
    for (const auto& m : def.members)
        if (!m->is_extension_marker)
            os << std::format(", {} = {}", to_cpp_name(m->name), pr_idx++);
    os << " };\n";
    os << "    PR present{PR::NOTHING};\n";
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        os << std::format("    {} {}{{}};\n", cpp_type_for(*m), to_member_name(m->name));
    }
    os << "};\n\n";

    // Extern descriptor declarations
    if (count > 0)
        os << std::format("extern const asn1::MemberDescriptor asn_MBR_{}[{}];\n", cname, count);
    os << std::format("extern const asn1::ChoiceSpec       asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

}

void Generator::emit_choice_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

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
                if (eff_tag.empty()) eff_tag = "asn1::Tag{}";  // nested CHOICE has no universal tag
            }
            os << std::format("    {{ \"{}\", {}, false, false, offsetof({}, {}), {} }},\n",
                m->name, eff_tag, cname, mname,
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
    os << "    {} /* PER: per_constraints */\n";
    os << "};\n\n";

    // TypeDescriptor (CHOICE has no fixed universal tag)
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.name);
    os << "    asn1::Tag{asn1::TagClass::Context, 0, false}, /* placeholder — CHOICE tag is transparent */\n";
    os << "    nullptr, nullptr,\n";
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    nullptr, {} /* per_constraints */\n";
    os << "};\n\n";

}

// ---------------------------------------------------------------------------
// Top-level emit_hpp / emit_cpp dispatch
// ---------------------------------------------------------------------------

void Generator::emit_hpp(const ast::TypeDef& def, const ast::Module& mod, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, mod.name);

    // Module header comment with OID if present
    os << "// Module: " << mod.name;
    if (!mod.oid.arcs.empty()) {
        os << " {";
        for (const auto& arc : mod.oid.arcs) {
            os << " ";
            if (arc.number >= 0) os << arc.number;
            else os << arc.name;
        }
        os << " }";
    }
    os << "\n";

    os << "#pragma once\n";
    os << "#include <memory>\n";
    os << "#include <optional>\n";
    os << "#include <variant>\n";
    os << "#include <vector>\n";
    os << "#include <span>\n";
    os << "#include <asn1cpp/asn1cpp.hpp>\n\n";

    if (def.is_sequence() || def.is_set()) {
        current_type_ = cname;
        emit_sequence_hpp(def, os);
    } else if (def.is_choice()) {
        current_type_ = cname;
        emit_choice_hpp(def, os);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated) {
            emit_enumerated_hpp(def, os);
        } else if (*bt == ast::BuiltinType::Integer) {
            emit_integer_hpp(def, os);
        } else {
            os << std::format("using {} = {};\n\n", cname, cpp_type_for(def));
            os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
        }
    } else if (def.is_seq_of() || def.is_set_of()) {
        current_type_ = cname;
        const auto& elem = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body).element
            : std::get<ast::SetOfType>(def.body).element;
        if (auto* tr = std::get_if<ast::TypeRef>(&elem->body)) {
            auto inc = cpp_name_for_typeref(*tr);
            os << std::format("#include \"{}.hpp\"\n\n", inc);
            track_include(inc);
        } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
            // Inline element: include the synthetic type header.
            auto sn = to_cpp_name(elem->name.empty() ? "Anon" : elem->name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            auto synth = cname + sn;
            os << std::format("#include \"{}.hpp\"\n\n", synth);
            track_include(synth);
        }
        os << std::format("using {} = std::vector<{}>;\n\n", cname, cpp_type_for(*elem));
        os << std::format("extern const asn1::SeqOfSpec     asn_SPC_{};\n", cname);
        os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
    } else if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto inc = cpp_name_for_typeref(*tr);
        os << std::format("#include \"{}.hpp\"\n", inc);
        track_include(inc);
        os << std::format("using {} = {};\n", cname, inc);
    }
}


// Extract SIZE (lb..ub) constraint. Returns {lb, ub} or nullopt if none.
// lb==ub → fixed size; ub==INT64_MAX → semi-constrained (SIZE lb..MAX).
static std::optional<std::pair<int64_t,int64_t>> extract_size_range(const ast::TypeDef& def) {
    std::optional<std::pair<int64_t,int64_t>> result;
    walk_type_constraints(def, [&](const ast::ConstraintBody& body) {
        if (result) return;
        auto* sc = std::get_if<ast::SizeConstraint>(&body);
        if (!sc || !sc->inner) return;
        if (auto* vr = std::get_if<ast::ValueRange>(&sc->inner->body)) {
            int64_t lb = 0, ub = std::numeric_limits<int64_t>::max();
            if (vr->lower.kind != ast::RangeEndpoint::Kind::Min)
                if (auto* n = std::get_if<int64_t>(&vr->lower.value)) lb = *n;
            if (vr->upper.kind == ast::RangeEndpoint::Kind::Max)
                ub = std::numeric_limits<int64_t>::max();
            else if (auto* n = std::get_if<int64_t>(&vr->upper.value)) ub = *n;
            result = {lb, ub};
        } else if (auto* sv = std::get_if<ast::Value>(&sc->inner->body)) {
            if (auto* n = std::get_if<int64_t>(sv)) result = {*n, *n};
        }
    });
    return result;
}

// Extract sorted char values from a FROM alphabet constraint.
// Returns empty vector if no FROM constraint or if chars can't be resolved.
static std::vector<uint8_t> extract_from_alphabet(const ast::TypeDef& def) {
    std::vector<uint8_t> chars;
    auto collect = [&](const ast::ConstraintBody& body) {
        if (auto* v = std::get_if<ast::Value>(&body))
            if (auto* s = std::get_if<std::string>(v))
                if (s->size() == 1)
                    chars.push_back(static_cast<uint8_t>((*s)[0]));
    };

    // Grammar builds left-recursive Union pairs: A|B|C → Union(Union(A,B),C).
    // Recurse into nested UnionConstraints to reach all leaf Values.
    std::function<void(const ast::ConstraintBody&)> recurse_union;
    recurse_union = [&](const ast::ConstraintBody& b) {
        if (auto* uc = std::get_if<ast::UnionConstraint>(&b)) {
            for (const auto& op : uc->operands)
                if (op) recurse_union(op->body);
        } else {
            collect(b);
        }
    };

    walk_type_constraints(def, [&](const ast::ConstraintBody& body) {
        auto* fc = std::get_if<ast::FromConstraint>(&body);
        if (!fc || !fc->inner) return;
        recurse_union(fc->inner->body);
    });

    if (!chars.empty()) std::sort(chars.begin(), chars.end());
    return chars;
}

void Generator::emit_builtin_alias_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto alphabet   = extract_from_alphabet(def);
    auto size_range = extract_size_range(def);

    bool needs_per = !alphabet.empty() || size_range.has_value();

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.name);
    os << std::format("    {},\n", natural_tag_for(def));
    os << "    nullptr, nullptr, nullptr, nullptr,\n";

    if (needs_per) {
        // SIZE constraint metadata
        int     size_flags = 0;
        int     size_rb    = 0;
        int64_t size_lb    = 0, size_ub = 0;
        if (size_range) {
            size_lb = size_range->first;
            size_ub = size_range->second;
            if (size_ub != std::numeric_limits<int64_t>::max()) {
                size_flags = asn1::PerConstraints::SIZE_CONSTRAINED;
                int64_t range = size_ub - size_lb + 1;
                if (range > 1)
                    for (int64_t r = range - 1; r > 0; r >>= 1) ++size_rb;
            }
        }

        // FROM alphabet metadata
        int alphabet_bits = 0;
        if (!alphabet.empty()) {
            int alphabet_size = static_cast<int>(alphabet.size());
            for (int r = alphabet_size - 1; r > 0; r >>= 1) ++alphabet_bits;
            if (alphabet_bits == 0) alphabet_bits = 1;
        }

        int flags = asn1::PerConstraints::CONSTRAINED | size_flags
                  | (is_constraint_extensible(def) ? asn1::PerConstraints::EXTENSIBLE : 0);
        int val_lb = alphabet.empty() ? 0 : static_cast<int>(alphabet[0]);
        int val_ub = alphabet.empty() ? 0 : static_cast<int>(alphabet.back());

        os << std::format("    {{ {}, 0, {}, {}, {}, {}, {}, {}",
                          flags, val_lb, val_ub, size_rb, size_lb, size_ub, alphabet_bits);
        if (!alphabet.empty()) {
            os << ", std::vector<uint8_t>{";
            for (int i = 0; i < static_cast<int>(alphabet.size()); ++i) {
                if (i) os << ", ";
                os << static_cast<int>(alphabet[i]);
            }
            os << "}";
        }
        os << " } /* per_constraints */\n";
    } else {
        os << "    {} /* per_constraints — unconstrained */\n";
    }
    os << "};\n";
}

// ---------------------------------------------------------------------------
// Emit SEQUENCE OF / SET OF
// ---------------------------------------------------------------------------

void Generator::emit_seq_of_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    const auto& elem_node = def.is_seq_of()
        ? *std::get<ast::SequenceOfType>(def.body).element
        : *std::get<ast::SetOfType>(def.body).element;

    // Type-erased collection callbacks via template alias
    os << std::format("using _VecOps_{0} = asn1::VectorOps<{0}>;\n\n", cname);

    // SIZE constraint on collection length
    auto size_range = extract_size_range(def);
    int     size_flags = 0, size_rb = 0;
    int64_t size_lb = 0, size_ub = 0;
    if (size_range) {
        size_lb = size_range->first;
        size_ub = size_range->second;
        if (size_ub != std::numeric_limits<int64_t>::max()) {
            size_flags = asn1::PerConstraints::SIZE_CONSTRAINED;
            int64_t range = size_ub - size_lb + 1;
            if (range > 1)
                for (int64_t r = range - 1; r > 0; r >>= 1) ++size_rb;
        }
    }

    // SeqOfSpec
    os << std::format("const asn1::SeqOfSpec asn_SPC_{} = {{\n", cname);
    os << std::format("    {},\n", type_descriptor_ref_for(elem_node));
    os << std::format("    {{ {}, 0, 0, 0, {}, {}, {} }},\n",
                      size_flags, size_rb, size_lb, size_ub);
    os << std::format("    &_VecOps_{0}::count, &_VecOps_{0}::get_const, &_VecOps_{0}::get_mut, &_VecOps_{0}::resize\n", cname);
    os << "};\n\n";

    // TypeDescriptor
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.name);
    os << std::format("    asn1::Tag::universal({}, true),\n", asn1::UniversalTag::Sequence);
    os << "    nullptr, nullptr, nullptr,\n";
    os << std::format("    &asn_SPC_{},\n", cname);
    os << "    {} /* per_constraints */\n";
    os << "};\n";
}

void Generator::emit_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    os << std::format("#include \"{}.hpp\"\n\n", cname);

    if (def.is_sequence() || def.is_set()) {
        current_type_ = cname;
        emit_sequence_cpp(def, os);
    } else if (def.is_choice()) {
        current_type_ = cname;
        emit_choice_cpp(def, os);
    } else if (def.is_seq_of() || def.is_set_of()) {
        current_type_ = cname;
        emit_seq_of_cpp(def, os);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated)
            emit_enumerated_cpp(def, os);
        else if (*bt == ast::BuiltinType::Integer)
            emit_integer_cpp(def, os);
        else
            emit_builtin_alias_cpp(def, os);
    }
}

// ---------------------------------------------------------------------------
// Inline type pre-generation
// Emits synthetic top-level types for anonymous SEQUENCE/CHOICE/SET members.
// Must run before the parent type so includes resolve.
// ---------------------------------------------------------------------------

void Generator::generate_inline_types(const ast::TypeDef& def, const ast::Module& mod) {
    std::string parent_cname = effective_cpp_name(def.name, mod.name);

    // Handle SEQUENCE OF / SET OF with inline anonymous element
    if (def.is_seq_of() || def.is_set_of()) {
        const auto& elem = def.is_seq_of()
            ? *std::get<ast::SequenceOfType>(def.body).element
            : *std::get<ast::SetOfType>(def.body).element;
        if (elem.is_sequence() || elem.is_choice() || elem.is_set()) {
            auto sn = to_cpp_name(elem.name.empty() ? "Anon" : elem.name);
            if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
            std::string synth_name = parent_cname + sn;
            if (!generated_names_.count(synth_name)) {
                generated_names_.insert(synth_name);
                auto synthetic = std::make_shared<ast::TypeDef>(elem);
                synthetic->name = synth_name;
                generate_inline_types(*synthetic, mod);
                current_type_ = synth_name;
                { std::ofstream hpp(out_dir_ / (synth_name + ".hpp")); emit_hpp(*synthetic, mod, hpp); }
                { std::ofstream cpp(out_dir_ / (synth_name + ".cpp")); emit_cpp(*synthetic, cpp); }
            }
        }
        return;
    }

    if (!def.is_sequence() && !def.is_choice() && !def.is_set()) return;

    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;

        // SEQUENCE OF / SET OF: generate element type (if inline) + synthetic SeqOf wrapper.
        if ((m->is_seq_of() || m->is_set_of()) && !m->name.empty()) {
            const auto& elem = m->is_seq_of()
                ? *std::get<ast::SequenceOfType>(m->body).element
                : *std::get<ast::SetOfType>(m->body).element;
            std::string elem_type_name;  // non-empty iff element was an inline complex type
            if (elem.is_sequence() || elem.is_choice() || elem.is_set()) {
                auto esn = to_cpp_name(elem.name.empty() ? "Anon" : elem.name);
                if (!esn.empty()) esn[0] = (char)std::toupper(esn[0]);
                elem_type_name = parent_cname + esn;
                if (!generated_names_.count(elem_type_name)) {
                    generated_names_.insert(elem_type_name);
                    auto synthetic = std::make_shared<ast::TypeDef>(elem);
                    synthetic->name = elem_type_name;
                    generate_inline_types(*synthetic, mod);
                    current_type_ = elem_type_name;
                    { std::ofstream hpp(out_dir_ / (elem_type_name + ".hpp")); emit_hpp(*synthetic, mod, hpp); }
                    { std::ofstream cpp(out_dir_ / (elem_type_name + ".cpp")); emit_cpp(*synthetic, cpp); }
                }
            }
            // Generate synthetic SeqOf wrapper descriptor type named parent + MemberCamel.
            // If element was anonymous inline, replace it with a TypeRef to the named element
            // type so emit_hpp uses the correct name and include path.
            std::string mbr_sn = to_cpp_name(m->name);
            if (!mbr_sn.empty()) mbr_sn[0] = (char)std::toupper(mbr_sn[0]);
            std::string seqof_name = parent_cname + mbr_sn;
            if (!generated_names_.count(seqof_name)) {
                generated_names_.insert(seqof_name);
                auto seqof_td = std::make_shared<ast::TypeDef>(*m);
                seqof_td->name = seqof_name;
                if (!elem_type_name.empty()) {
                    auto named_elem = std::make_shared<ast::TypeDef>();
                    named_elem->body = ast::TypeRef{"", elem_type_name};
                    if (m->is_seq_of())
                        seqof_td->body = ast::SequenceOfType{named_elem};
                    else
                        seqof_td->body = ast::SetOfType{named_elem};
                }
                current_type_ = seqof_name;
                { std::ofstream hpp(out_dir_ / (seqof_name + ".hpp")); emit_hpp(*seqof_td, mod, hpp); }
                { std::ofstream cpp(out_dir_ / (seqof_name + ".cpp")); emit_cpp(*seqof_td, cpp); }
            }
            continue;
        }

        auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
        bool is_inline_enum = mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty();
        if (!m->is_sequence() && !m->is_choice() && !m->is_set() && !is_inline_enum) continue;
        if (m->name.empty()) continue;

        std::string sn = to_cpp_name(m->name);
        if (!sn.empty()) sn[0] = (char)std::toupper(sn[0]);
        std::string synth_name = parent_cname + sn;

        if (generated_names_.count(synth_name)) continue;
        generated_names_.insert(synth_name);

        // Build a synthetic TypeDef with the synthetic name
        auto synthetic = std::make_shared<ast::TypeDef>(*m);
        synthetic->name = synth_name;

        // Recursively generate inline types within the synthetic type
        generate_inline_types(*synthetic, mod);

        // Generate the synthetic type file
        current_type_ = synth_name;
        {
            std::ofstream hpp(out_dir_ / (synth_name + ".hpp"));
            emit_hpp(*synthetic, mod, hpp);
        }
        {
            std::ofstream cpp(out_dir_ / (synth_name + ".cpp"));
            emit_cpp(*synthetic, cpp);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-type file writer
// ---------------------------------------------------------------------------

void Generator::generate_type(const ast::TypeDef& def, const ast::Module& mod) {
    if (!is_type_assignment(def)) return;

    std::string cname = effective_cpp_name(def.name, mod.name);

    {
        std::ofstream hpp(out_dir_ / (cname + ".hpp"));
        emit_hpp(def, mod, hpp);
    }

    auto bt_is = [&](ast::BuiltinType t) {
        auto* bt = std::get_if<ast::BuiltinType>(&def.body);
        return bt && *bt == t;
    };
    auto is_named_builtin_alias = [&]() {
        auto* bt = std::get_if<ast::BuiltinType>(&def.body);
        if (!bt) return false;
        return *bt != ast::BuiltinType::Enumerated && *bt != ast::BuiltinType::Integer;
    };
    bool needs_cpp = def.is_sequence() || def.is_set() || def.is_choice()
        || def.is_seq_of() || def.is_set_of()
        || bt_is(ast::BuiltinType::Enumerated)
        || bt_is(ast::BuiltinType::Integer)
        || is_named_builtin_alias();
    if (needs_cpp) {
        std::ofstream cpp(out_dir_ / (cname + ".cpp"));
        emit_cpp(def, cpp);
    }
}

void Generator::emit_stubs_for_unresolved() {
    for (const auto& name : referenced_names_) {
        if (generated_names_.count(name)) continue;
        auto path = out_dir_ / (name + ".hpp");
        if (fs::exists(path)) continue;
        std::ofstream os(path);
        os << "#pragma once\n";
        os << "#include <asn1cpp/asn1cpp.hpp>\n\n";
        os << "/* stub: type from missing/uncompiled module */\n";
        os << std::format("struct {} {{}};\n\n", name);
        os << std::format("inline const asn1::TypeDescriptor asn_DEF_{} = {{\n", name);
        os << std::format("    \"{}\",\n", name);
        os << "    asn1::Tag{},\n";
        os << "    nullptr, nullptr, nullptr, nullptr, {}\n";
        os << "};\n\n";
    }
}

} // namespace asn1::codegen
