#include "Generator.hpp"
#include <algorithm>
#include <functional>
#include <limits>
#include <sstream>
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/TypeDescriptor.hpp"
#include "asn1cpp/codec/Constraints.hpp"

namespace asn1::codegen {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string Generator::cpp_type_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Boolean:           return "asn1::Boolean";
        case BT::Integer: {
            auto kind = classify_integer_storage(def);
            switch (kind) {
                case IntStorageKind::U64:       return "asn1::UInteger";
                case IntStorageKind::I128:      return "asn1::BigInteger";
                case IntStorageKind::ARBITRARY: return "asn1::ArbitraryInteger";
                default:                        return "asn1::Integer";
            }
        }
        case BT::Real:              return "asn1::Real";
        case BT::Null:              return "asn1::Null";
        case BT::BitString:         return "asn1::BitString";
        case BT::OctetString:       return "asn1::OctetString";
        case BT::ObjectIdentifier:  return "asn1::Oid";
        case BT::RelativeOid:       return "asn1::RelativeOid";
        case BT::Enumerated: {
            auto n = capitalize_first(to_cpp_name(def.name.empty() ? "Enum" : def.name));
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
        return std::format("asn1::VectorSeqOf<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        return std::format("asn1::VectorSeqOf<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_sequence() || def.is_choice() || def.is_set())
        return make_synthetic_name(current_type_, def.name.empty() ? "Anon" : def.name);
    return "asn1::OctetString";
}

// Returns true if the member encodes as a constructed TLV (SEQUENCE, SET, CHOICE, OF).
// Follows one level of TypeRef so that [n] IMPLICIT ReferencedChoice is also caught.
bool Generator::member_is_constructed(const ast::TypeDef& m) const {
    if (m.is_sequence() || m.is_set() || m.is_choice() || m.is_seq_of() || m.is_set_of())
        return true;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto res = resolver_.resolve_ref(*tr);
        if (res) return res->is_sequence() || res->is_set() || res->is_choice()
                           || res->is_seq_of() || res->is_set_of();
    }
    return false;
}

// Returns true if a tagged member/alternative uses EXPLICIT tagging.
// Rules (X.680 §24.11 / §30.6):
//   - Explicitly declared [N] EXPLICIT → true
//   - Explicitly declared [N] IMPLICIT → false
//   - Default: follows module tag default; but CHOICE with no natural tag forces EXPLICIT
//     even under IMPLICIT TAGS (X.680 §30.6c).
bool Generator::member_type_is_choice(const ast::TypeDef& m) const {
    if (m.is_choice()) return true;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto res = resolver_.resolve_ref(*tr, current_module_);
        if (res) return res->is_choice();
    }
    return false;
}

bool Generator::member_type_is_any(const ast::TypeDef& m) const {
    if (auto* bt = std::get_if<ast::BuiltinType>(&m.body))
        return *bt == ast::BuiltinType::Any;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto res = resolver_.resolve_ref(*tr, current_module_);
        if (res) return member_type_is_any(*res);
    }
    return false;
}

bool Generator::member_is_explicit(const ast::Tag& tag, const ast::TypeDef& member_type) const {
    if (tag.mode == ast::TagMode::Explicit) return true;
    if (tag.mode == ast::TagMode::Implicit) return false;
    // TagMode::Default — use module-level default.
    if (current_tag_default_ == ast::TagDefault::Explicit) return true;
    // IMPLICIT or AUTOMATIC default.
    // Exception: CHOICE and ANY cannot be IMPLICIT tagged (X.680 §30.6/30.7);
    // tagging must be EXPLICIT even in an IMPLICIT TAGS module.
    return member_type_is_choice(member_type) || member_type_is_any(member_type);
}

// Returns "asn1::Tag{...}" literal for a tag override, empty string if absent.
std::string Generator::tag_literal(const ast::Tag& tag, bool constructed) const {
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
// For types with an outer [N] tag, the outer tag IS the wire-level tag.
std::string Generator::natural_tag_for(const ast::TypeDef& def) const {
    if (def.tag.present()) {
        bool is_constr = def.is_sequence() || def.is_choice() ||
                         def.is_seq_of()   || def.is_set_of() || def.is_set();
        bool is_exp = member_is_explicit(def.tag, def);
        return tag_literal(def.tag, is_exp || is_constr);
    }
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
    if (def.is_sequence())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    if (def.is_set())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Set);
    if (def.is_choice())
        return "";  // CHOICE has no universal tag
    if (def.is_seq_of())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Sequence);
    if (def.is_set_of())
        return std::format("asn1::Tag::universal({}, true)", asn1::UniversalTag::Set);
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto base = resolver_.resolve_ref(*tr);
        if (base) return natural_tag_for(*base);
    }
    return "asn1::Tag::universal(4, false)";  // fallback: OCTET STRING
}

// ---------------------------------------------------------------------------
// Shared SEQUENCE/SET/CHOICE helpers
// ---------------------------------------------------------------------------

Generator::MemberCount Generator::count_members(const ast::TypeDef& def) {
    int count = 0, ext_at = -1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { if (ext_at < 0) ext_at = count; continue; }
        ++count;
    }
    return { count, ext_at };
}

bool Generator::should_apply_auto_tags(const ast::TypeDef& def) const {
    if (current_tag_default_ != ast::TagDefault::Automatic) return false;
    for (const auto& m : def.members) {
        if (!m || m->is_extension_marker) continue;
        if (m->tag.present()) return false;
    }
    return true;
}

Generator::TagResult Generator::compute_member_tag(const ast::TypeDef& m,
                                                    bool apply_auto_tags,
                                                    int auto_tag_num) const {
    std::string eff_tag;
    bool is_explicit = false;
    if (m.tag.present()) {
        is_explicit = member_is_explicit(m.tag, m);
        // EXPLICIT wrapper is always constructed (X.690 §8.14.3); IMPLICIT inherits.
        eff_tag = tag_literal(m.tag, is_explicit || member_is_constructed(m));
    } else if (apply_auto_tags) {
        // X.680 §24.9 / §28.2: untagged CHOICE in AUTOMATIC TAGS gets EXPLICIT.
        bool is_choice = member_type_is_choice(m);
        ast::Tag auto_tag;
        auto_tag.cls    = ast::TagClass::Context;
        auto_tag.number = auto_tag_num;
        auto_tag.mode   = is_choice ? ast::TagMode::Explicit : ast::TagMode::Implicit;
        eff_tag    = tag_literal(auto_tag, is_choice || member_is_constructed(m));
        is_explicit = is_choice;
    } else {
        eff_tag = natural_tag_for(m);
        if (eff_tag.empty()) eff_tag = "asn1::Tag{}";
        // If the tag came from a referenced type's outer context tag, propagate is_explicit.
        // e.g. s4 T4 where T4 ::= [53] CHOICE — CHOICE always forces EXPLICIT.
        if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
            auto base = resolver_.resolve_ref(*tr);
            if (base && base->tag.present())
                is_explicit = member_is_explicit(base->tag, *base);
        }
    }
    return { std::move(eff_tag), is_explicit };
}

bool Generator::is_class_type(const ast::TypeDef& m) const {
    if (m.is_sequence() || m.is_choice() || m.is_set()) return true;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
        return direct && (direct->is_sequence() || direct->is_choice() || direct->is_set());
    }
    return false;
}

// Collect flattened BER dispatch tags for one CHOICE alternative (X.690 §8.13,
// X.680 §24.6). If the alternative has its own BER tag, add one entry.
// If it resolves to an untagged CHOICE (empty natural tag), recurse into its
// alternatives so the outer CHOICE can dispatch by the inner type's tags.
void Generator::collect_ber_tags_for(const ast::TypeDef& alt, int alt_idx,
                                      std::vector<std::pair<std::string,int>>& out,
                                      std::set<std::string>& visited)
{
    // Explicit outer tag: use it directly.
    if (alt.tag.present()) {
        bool constr = alt.is_sequence() || alt.is_choice() ||
                      alt.is_seq_of()  || alt.is_set_of() || alt.is_set();
        out.emplace_back(tag_literal(alt.tag, constr), alt_idx);
        return;
    }
    std::string nat = natural_tag_for(alt);
    if (!nat.empty()) {
        out.emplace_back(nat, alt_idx);
        return;
    }
    // No tag: resolve TypeRef to find the actual type.
    const ast::TypeDef* inner = &alt;
    ast::TypeDefPtr resolved;
    if (auto* tr = std::get_if<ast::TypeRef>(&alt.body)) {
        if (visited.count(tr->type_name)) return;  // cycle guard
        visited.insert(tr->type_name);
        resolved = resolver_.resolve_ref(*tr);
        if (resolved) inner = resolved.get();
    }
    // If the resolved type has its own explicit tag, use it (tagged CHOICE is not untagged).
    if (inner->tag.present()) {
        bool constr = inner->is_sequence() || inner->is_choice() ||
                      inner->is_seq_of()   || inner->is_set_of() || inner->is_set();
        out.emplace_back(tag_literal(inner->tag, constr), alt_idx);
        return;
    }
    // Truly untagged CHOICE: flatten its inner alternatives for dispatch.
    if (inner->is_choice()) {
        for (const auto& m : inner->members) {
            if (!m || m->is_extension_marker) continue;
            collect_ber_tags_for(*m, alt_idx, out, visited);
        }
    }
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
        return std::format("&asn_DEF_{}", make_synthetic_name(current_type_, def.name.empty() ? "Enum" : def.name));
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
        if (!def.name.empty())
            return std::format("&asn_DEF_{}", make_synthetic_name(current_type_, def.name));
        const auto& elem = std::get<ast::SequenceOfType>(def.body).element;
        return type_descriptor_ref_for(*elem);
    }
    if (def.is_set_of()) {
        if (!def.name.empty())
            return std::format("&asn_DEF_{}", make_synthetic_name(current_type_, def.name));
        const auto& elem = std::get<ast::SetOfType>(def.body).element;
        return type_descriptor_ref_for(*elem);
    }
    // Inline SEQUENCE / CHOICE / SET member — synthetic name = parent + member
    if (def.is_sequence() || def.is_choice() || def.is_set())
        return std::format("&asn_DEF_{}", make_synthetic_name(current_type_, def.name.empty() ? "Anon" : def.name));
    return "nullptr";
}

// ---------------------------------------------------------------------------
// Shared TypeDescriptor emitter
// ---------------------------------------------------------------------------

static void emit_type_descriptor(std::ostream& os,
                                 const std::string& cname,
                                 const std::string& xer_name,
                                 const std::string& tag_expr,
                                 bool has_enum, bool has_seq,
                                 bool has_choice, bool has_seqof,
                                 const std::string& kind) {
    auto sp = [&](bool h) -> std::string {
        return h ? std::format("&asn_SPC_{}", cname) : "nullptr";
    };
    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", xer_name);
    os << std::format("    {},\n", tag_expr);
    os << std::format("    {}, {}, {}, {}, {{}} /* constraints */,\n",
                      sp(has_enum), sp(has_seq), sp(has_choice), sp(has_seqof));
    os << std::format("    false, {} /* kind */\n", kind);
    os << "};\n\n";
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
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Enumerated),
        true, false, false, false, "asn1::TypeKind::Enumerated");

}

// ---------------------------------------------------------------------------
// Emit INTEGER
// ---------------------------------------------------------------------------

IntStorageKind Generator::classify_integer_storage(const ast::TypeDef& def) const {
    auto range = extract_integer_range(def);
    if (!range) return default_int_kind_;  // unconstrained → CLI default

    auto [lo, hi] = *range;
    // hi == INT64_MAX is the sentinel for "..MAX" (SEMI_CONSTRAINED, no upper cap)
    bool upper_is_max = (hi == std::numeric_limits<int64_t>::max());
    if (upper_is_max && lo >= 0) return IntStorageKind::U64;
    // TODO: when parser supports literals > INT64_MAX, add:
    //   if (lo >= 0 && hi > INT64_MAX) return IntStorageKind::U64;
    //   if (range exceeds int64 on either side) return IntStorageKind::I128;
    return IntStorageKind::S64;
}

void Generator::emit_integer_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto kind = classify_integer_storage(def);
    std::string cpp_storage;
    switch (kind) {
        case IntStorageKind::U64:       cpp_storage = "uint64_t"; break;
        case IntStorageKind::I128:      cpp_storage = "__int128"; break;
        case IntStorageKind::ARBITRARY: cpp_storage = "std::vector<uint8_t>"; break;
        default:                        cpp_storage = "int64_t"; break;
    }
    os << std::format("using {} = {};\n\n", cname, cpp_storage);

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

// Resolve a member's underlying TypeDef by walking TypeRef chain.
static const ast::TypeDef* resolve_underlying(const ast::TypeDef& m,
                                              const sema::Resolver& res) {
    const ast::TypeDef* cur = &m;
    for (int hop = 0; hop < 32; ++hop) {
        auto* tr = std::get_if<ast::TypeRef>(&cur->body);
        if (!tr) return cur;
        auto next = res.resolve_ref(*tr);
        if (!next) return cur;
        cur = next.get();
    }
    return cur;
}

std::string Generator::emit_default_setter(
    const ast::TypeDef& m, const std::string& parent_cname,
    const std::string& mname, std::ostream& os)
{
    if (m.marker != ast::Marker::Default) return "nullptr";
    if (std::holds_alternative<std::monostate>(m.default_value)) return "nullptr";

    std::string mtype = cpp_type_for(m);
    const ast::TypeDef* base = resolve_underlying(m, resolver_);

    std::string literal;
    if (auto* b = std::get_if<bool>(&m.default_value)) {
        literal = std::format("{}{{{}}}", mtype, *b ? "true" : "false");
    } else if (auto* i = std::get_if<int64_t>(&m.default_value)) {
        literal = std::format("{}{{{}}}", mtype, *i);
    } else if (auto* nr = std::get_if<ast::NamedValueRef>(&m.default_value)) {
        // ENUMERATED named ref → EnumType::name
        bool is_enum = base
            && std::holds_alternative<ast::BuiltinType>(base->body)
            && std::get<ast::BuiltinType>(base->body) == ast::BuiltinType::Enumerated;
        if (!is_enum) return "nullptr";
        literal = std::format("{}::{}", mtype, safe_cpp_name(to_cpp_name(nr->name)));
    } else {
        return "nullptr";
    }

    std::string fname = std::format("_setdef_{}_{}", parent_cname, mname);
    std::string cname2 = std::format("_isdef_{}_{}", parent_cname, mname);
    os << std::format(
        "static void {0}(void* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    Ops::set(p, true);\n"
        "    *static_cast<{3}*>(Ops::get(p)) = {4};\n"
        "}}\n",
        fname, parent_cname, mname, mtype, literal);
    os << std::format(
        "static bool {0}(const void* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    if (!Ops::check(p)) return false;\n"
        "    return *static_cast<const {3}*>(Ops::get(const_cast<void*>(p))) == ({4});\n"
        "}}\n",
        cname2, parent_cname, mname, mtype, literal);
    return "&" + fname;
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

// Forward decl: definition below; needed by emit_member_type_descriptor.
static std::optional<std::pair<int64_t,int64_t>> extract_size_range(const ast::TypeDef& def);

struct SizeConstraintInfo {
    int     flags      = 0;   // SIZE_CONSTRAINED | EXTENSIBLE (0 when no/semi constraint)
    int     range_bits = 0;
    int64_t lower      = 0;
    int64_t upper      = 0;   // 0 when semi-constrained (ub == INT64_MAX)
};

// Compute size constraint metadata from an optional (lb, ub) pair.
// Sets SIZE_CONSTRAINED + computes range_bits only when ub is finite.
// Pass extensible=true to OR in EXTENSIBLE.
static SizeConstraintInfo compute_size_constraint(
        std::optional<std::pair<int64_t,int64_t>> size_range,
        bool extensible = false) {
    SizeConstraintInfo r{};
    if (!size_range) return r;
    r.lower = size_range->first;
    if (size_range->second != std::numeric_limits<int64_t>::max()) {
        r.upper = size_range->second;
        r.flags = asn1::Constraints::SIZE_CONSTRAINED;
        int64_t range = r.upper - r.lower + 1;
        if (range > 1)
            for (int64_t v = range - 1; v > 0; v >>= 1) ++r.range_bits;
    }
    if (extensible) r.flags |= asn1::Constraints::EXTENSIBLE;
    return r;
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

// Build a Constraints designated-initializer literal for an INTEGER constraint.
// Uses designated initializers (C++20) so struct field additions don't require
// updating every call site.
static std::string make_integer_pc(int flags, int range_bits, int int_kind,
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

void Generator::emit_integer_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto range = extract_integer_range(def);
    auto kind  = classify_integer_storage(def);
    int  ik    = (kind == IntStorageKind::U64) ? asn1::Constraints::INT_U64
               : (kind == IntStorageKind::I128) ? asn1::Constraints::INT_I128
               : (kind == IntStorageKind::ARBITRARY) ? asn1::Constraints::INT_ARBITRARY
               : asn1::Constraints::INT_S64;

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.xer_name.empty() ? def.name : def.xer_name);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Integer);
    os << "    nullptr, nullptr, nullptr, nullptr,\n";
    if (range) {
        int64_t lo = range->first, hi = range->second;
        bool ext = is_constraint_extensible(def);
        if (hi == std::numeric_limits<int64_t>::max()) {
            int flags = asn1::Constraints::SEMI_CONSTRAINED
                      | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            // upper_u64 = UINT64_MAX (no cap for SEMI_CONSTRAINED)
            os << std::format("    {} /* constraints — semi-constrained */,\n",
                make_integer_pc(flags, -1, ik, lo, 0,
                    static_cast<uint64_t>(lo >= 0 ? lo : 0),
                    std::numeric_limits<uint64_t>::max()));
        } else {
            int64_t range_count = hi - lo + 1;
            int rb = 0;
            if (range_count > 1)
                for (int64_t r = range_count - 1; r > 0; r >>= 1) ++rb;
            int flags = asn1::Constraints::CONSTRAINED
                      | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            // u64 bounds: same as s64 for ranges that fit; lo<0 → clamp to 0
            uint64_t u_lo = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
            uint64_t u_hi = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
            os << std::format("    {} /* constraints */,\n",
                make_integer_pc(flags, rb, ik, lo, hi, u_lo, u_hi));
        }
    } else {
        os << "    {} /* constraints — unconstrained */,\n";
    }
    os << "    false, asn1::TypeKind::Primitive\n";
    os << "};\n";
}

// ---------------------------------------------------------------------------
// Inline-constrained member TypeDescriptor helpers
// ---------------------------------------------------------------------------

// If `m` is an inline builtin (INTEGER with value range, or a SIZE-constrained
// string/OctetString/BitString) emit a static per-member TypeDescriptor so
// RandomFiller's validate() and PerCodec see the constraint. Otherwise return
// type_descriptor_ref_for(m).
std::string Generator::emit_member_type_descriptor(
    const ast::TypeDef& m, const std::string& parent_cname,
    const std::string& mname, std::ostream& os)
{
    using BT = ast::BuiltinType;
    auto* bt = std::get_if<BT>(&m.body);
    if (!bt || m.constraints.empty()) return type_descriptor_ref_for(m);

    // INTEGER value range
    if (*bt == BT::Integer) {
        auto range = extract_integer_range(m);
        if (range) {
            std::string tname = std::format("asn_TYP_{}_{}", parent_cname, mname);
            int64_t lo = range->first, hi = range->second;
            bool ext = is_constraint_extensible(m);
            auto kind = classify_integer_storage(m);
            int ik = (kind == IntStorageKind::U64)       ? asn1::Constraints::INT_U64
                   : (kind == IntStorageKind::I128)      ? asn1::Constraints::INT_I128
                   : (kind == IntStorageKind::ARBITRARY) ? asn1::Constraints::INT_ARBITRARY
                   : asn1::Constraints::INT_S64;
            std::string pc;
            if (hi == std::numeric_limits<int64_t>::max()) {
                int flags = asn1::Constraints::SEMI_CONSTRAINED
                          | (ext ? asn1::Constraints::EXTENSIBLE : 0);
                pc = make_integer_pc(flags, -1, ik, lo, 0,
                    static_cast<uint64_t>(lo >= 0 ? lo : 0),
                    std::numeric_limits<uint64_t>::max());
            } else {
                int64_t rc = hi - lo + 1;
                int rb = 0;
                if (rc > 1) for (int64_t r = rc - 1; r > 0; r >>= 1) ++rb;
                int flags = asn1::Constraints::CONSTRAINED
                          | (ext ? asn1::Constraints::EXTENSIBLE : 0);
                uint64_t u_lo = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
                uint64_t u_hi = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
                pc = make_integer_pc(flags, rb, ik, lo, hi, u_lo, u_hi);
            }
            os << std::format(
                "static const asn1::TypeDescriptor {} = "
                "{{ \"INTEGER\", asn1::Tag::universal({}, false), "
                "nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive }};\n",
                tname, asn1::UniversalTag::Integer, pc);
            return "&" + tname;
        }
    }

    // SIZE-able primitives: string family, OctetString, BitString.
    auto sizeable_universal_tag = [&](BT t) -> std::optional<int> {
        switch (t) {
        case BT::OctetString:      return asn1::UniversalTag::OctetString;
        case BT::BitString:        return asn1::UniversalTag::BitString;
        case BT::Utf8String:       return asn1::UniversalTag::Utf8String;
        case BT::NumericString:    return asn1::UniversalTag::NumericString;
        case BT::PrintableString:  return asn1::UniversalTag::PrintableString;
        case BT::T61String:        return asn1::UniversalTag::T61String;
        case BT::Ia5String:        return asn1::UniversalTag::Ia5String;
        case BT::VisibleString:    return asn1::UniversalTag::VisibleString;
        case BT::GeneralString:    return asn1::UniversalTag::GeneralString;
        case BT::GraphicString:    return asn1::UniversalTag::GraphicString;
        case BT::UniversalString:  return asn1::UniversalTag::UniversalString;
        case BT::BmpString:        return asn1::UniversalTag::BmpString;
        case BT::VideotexString:   return asn1::UniversalTag::VideotexString;
        case BT::ObjectDescriptor: return asn1::UniversalTag::ObjectDescriptor;
        default:                   return std::nullopt;
        }
    };
    auto utag = sizeable_universal_tag(*bt);
    if (utag) {
        auto sr = extract_size_range(m);
        if (sr) {
            auto sc = compute_size_constraint(sr, is_constraint_extensible(m));
            std::string pc = std::format(
                "{{ .flags={}, .size_range_bits={}, .size_lower={}, .size_upper={} }}",
                sc.flags, sc.range_bits, sc.lower, sc.upper);
            // Use the matching asn_DEF_*'s public name as the XER tag name —
            // BerCodec / XerCodec consult it for primitive type names.
            const char* tn = nullptr;
            switch (*bt) {
            case BT::OctetString:      tn = "OCTET_STRING";       break;
            case BT::BitString:        tn = "BIT_STRING";         break;
            case BT::Utf8String:       tn = "UTF8String";         break;
            case BT::NumericString:    tn = "NumericString";      break;
            case BT::PrintableString:  tn = "PrintableString";    break;
            case BT::T61String:        tn = "T61String";          break;
            case BT::Ia5String:        tn = "IA5String";          break;
            case BT::VisibleString:    tn = "VisibleString";      break;
            case BT::GeneralString:    tn = "GeneralString";      break;
            case BT::GraphicString:    tn = "GraphicString";      break;
            case BT::UniversalString:  tn = "UniversalString";    break;
            case BT::BmpString:        tn = "BMPString";          break;
            case BT::VideotexString:   tn = "VideotexString";     break;
            case BT::ObjectDescriptor: tn = "ObjectDescriptor";   break;
            default: break;
            }
            std::string tname = std::format("asn_TYP_{}_{}", parent_cname, mname);
            os << std::format(
                "static const asn1::TypeDescriptor {} = "
                "{{ \"{}\", asn1::Tag::universal({}, false), "
                "nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive }};\n",
                tname, tn, *utag, pc);
            return "&" + tname;
        }
    }

    return type_descriptor_ref_for(m);
}

// ---------------------------------------------------------------------------
// classify_member_setter — determines param type + validate strategy for
// set_<member> helpers. Returns empty param_type for members that should
// not get a setter (optional, complex, non-primitive types).
// ---------------------------------------------------------------------------
Generator::MemberSetterInfo
Generator::classify_member_setter(const ast::TypeDef& m) {
    using BT = ast::BuiltinType;
    if (m.is_sequence() || m.is_set() || m.is_choice() || m.is_seq_of() || m.is_set_of())
        return {};
    auto* bt = std::get_if<BT>(&m.body);
    if (bt) {
        switch (*bt) {
        case BT::Integer: {
            auto kind = classify_integer_storage(m);
            if (kind == IntStorageKind::U64)
                return {"uint64_t", false, false, false};  // asn1::UInteger field, .set(uint64_t)
            return {"int64_t", false, false, false};        // asn1::Integer field, .set(int64_t)
        }
        case BT::OctetString:
        case BT::Any:             return {"asn1::OctetString",    false, false, true};
        case BT::BitString:       return {"asn1::BitString",      false, false, true};
        case BT::Utf8String:      return {"asn1::Utf8String",     false, false, true};
        case BT::NumericString:   return {"asn1::NumericString",  false, false, true};
        case BT::PrintableString: return {"asn1::PrintableString",false, false, true};
        case BT::T61String:       return {"asn1::T61String",      false, false, true};
        case BT::Ia5String:       return {"asn1::Ia5String",      false, false, true};
        case BT::VisibleString:   return {"asn1::VisibleString",  false, false, true};
        case BT::GeneralString:   return {"asn1::GeneralString",  false, false, true};
        case BT::GraphicString:   return {"asn1::GraphicString",  false, false, true};
        case BT::UniversalString: return {"asn1::UniversalString",false, false, true};
        case BT::BmpString:       return {"asn1::BmpString",      false, false, true};
        case BT::VideotexString:  return {"asn1::VideotexString", false, false, true};
        case BT::ObjectDescriptor:return {"asn1::ObjectDescriptor",false,false,true};
        default: return {};
        }
    }
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto resolved = resolver_.resolve_ref(*tr);
        if (!resolved) return {};
        auto* rbt = std::get_if<BT>(&resolved->body);
        if (!rbt) return {};
        std::string ct = cpp_type_for(m);
        switch (*rbt) {
        case BT::Integer: {
            // TypeRef → using T = int64_t or uint64_t; no .validate() — wrap in Integer/UInteger
            auto kind = classify_integer_storage(*resolved);
            if (kind == IntStorageKind::U64)
                return {ct, false, true, false};   // is_uint_alias=true
            return {ct, true, false, false};        // is_int_alias=true
        }
        case BT::OctetString: case BT::Any: case BT::BitString:
        case BT::Utf8String: case BT::NumericString: case BT::PrintableString:
        case BT::T61String: case BT::Ia5String: case BT::VisibleString:
        case BT::GeneralString: case BT::GraphicString: case BT::UniversalString:
        case BT::BmpString: case BT::VideotexString: case BT::ObjectDescriptor:
            // TypeRef → using T = asn1::Xxx; has .validate()
            return {ct, false, false, true};
        default: return {};
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Emit SEQUENCE / SET
// ---------------------------------------------------------------------------

void Generator::emit_sequence_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    // Count non-extension members
    auto [mcount, ext_at] = count_members(def);

    // Determine if a member's named type is directly a class (SEQUENCE/CHOICE/SET) and can be
    // forward-declared. Using a direct lookup (not following aliases) is essential: a type alias
    // like `TraceActivation ::= ExternalASNType` generates `using TraceActivation = ...` in C++,
    // which cannot be forward-declared as `class TraceActivation;`.

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
                emit_inc(make_synthetic_name(cname, m->name));
            } else {
                const auto& elem = m->is_seq_of()
                    ? std::get<ast::SequenceOfType>(m->body).element
                    : std::get<ast::SetOfType>(m->body).element;
                if (auto* tr2 = std::get_if<ast::TypeRef>(&elem->body)) {
                    emit_inc(cpp_name_for_typeref(*tr2));
                } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
                    emit_inc(make_synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name));
                }
            }
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            auto synth = make_synthetic_name(cname, m->name);
            optional ? emit_fwd(synth) : emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty())
                emit_inc(make_synthetic_name(cname, m->name));
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
    os << std::format("class {} : public asn1::Asn1Object {{\npublic:\n", cname);
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
    // set_<member> declarations for non-optional primitive members
    {
        bool past = false;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) { past = true; continue; }
            if (m->is_optional() || past) continue;
            auto si = classify_member_setter(*m);
            if (si.param_type.empty()) continue;
            std::string mname = to_member_name(m->name);
            os << std::format("    void set_{}({} val);\n", mname, si.param_type);
        }
    }
    if (mcount > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_members[{}];\n", mcount);
        os << "    static const int s_member_count;\n";
    }
    os << "};\n\n";

    // Extern descriptor declarations (s_members declared inside class; only SPC+DEF are global)
    os << std::format("extern const asn1::SequenceSpec     asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

}

void Generator::emit_sequence_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    auto [mcount, ext_at] = count_members(def);

    // Determine if any optional members exist.
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
                os << std::format("#include \"{}.hpp\"\n", make_synthetic_name(cname, m->name));
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

    // Determine if AUTOMATIC TAGS applies: module is AUTOMATIC TAGS and none of the
    // ComponentTypes in any ComponentTypeList has an explicit tag (X.680 §24.8).
    bool apply_auto_tags = should_apply_auto_tags(def);

    // Per-member row data — hoisted so setter definitions can reference it after
    // the descriptor table block.
    struct MbrRow {
        std::string name, eff_tag, mname, ops, tdref, def_setter;
        bool optional, is_explicit, has_default;
        MemberSetterInfo setter;
    };
    std::vector<MbrRow> rows;

    // Member descriptor table
    if (mcount > 0) {
        // Pass 1: collect per-row data and emit any static per-member TypeDescriptors
        // before the array opening brace (can't have declarations inside initializer lists).
        {
            bool past = false;
            int atag = 0;
            for (const auto& m : def.members) {
                if (m->is_extension_marker) { past = true; continue; }
                std::string mname = to_member_name(m->name);
                bool optional = m->is_optional() || past;
                auto [eff_tag, is_explicit] = compute_member_tag(*m, apply_auto_tags, atag);
                std::string ops = optional
                    ? std::format("{{ &_Ops_{0}_{1}::check, &_Ops_{0}_{1}::set, &_Ops_{0}_{1}::get }}", cname, mname)
                    : "{}";
                std::string tdref = emit_member_type_descriptor(*m, cname, mname, os);
                std::string def_setter = emit_default_setter(*m, cname, mname, os);
                bool has_default = (m->marker == ast::Marker::Default);
                auto setter = optional ? MemberSetterInfo{} : classify_member_setter(*m);
                rows.push_back({ m->name, eff_tag, mname, ops, tdref, def_setter,
                                 optional, is_explicit, has_default, std::move(setter) });
                ++atag;
            }
        }
        // Pass 2: emit the array (as class static member definition)
        os << std::format("const asn1::MemberDescriptor {}::s_members[] = {{\n", cname);
        for (const auto& r : rows) {
            // Emit &_isdef_… reference only when the default-value helper
            // pair was actually emitted. emit_default_setter() returns
            // "nullptr" (no _setdef_/_isdef_ generated) for default-value
            // forms it doesn't understand yet — INTEGER with named values,
            // arbitrary IntegerLiteral, etc. Without this gate the member
            // table would reference an undefined _isdef_ symbol.
            std::string def_cmp = (r.has_default && r.def_setter != "nullptr")
                ? std::format("&_isdef_{}_{}", cname, r.mname)
                : "nullptr";
            os << std::format("    {{ \"{}\", {}, {}, {}, ASN1CPP_OFFSETOF({}, {}), {}, {}, {}, {}, {} }},\n",
                r.name, r.eff_tag,
                r.optional ? "true" : "false",
                r.has_default ? "true" : "false",
                cname, r.mname,
                r.tdref, r.ops,
                r.is_explicit ? "true" : "false",
                r.def_setter, def_cmp);
        }
        os << "};\n";
        os << std::format("const int {}::s_member_count = {};\n\n", cname, mcount);
    }

    // SequenceSpec
    os << std::format("const asn1::SequenceSpec asn_SPC_{} = {{\n", cname);
    if (mcount > 0)
        os << std::format("    {}::s_members,\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", mcount);
    os << std::format("    {}, /* ext_at */\n", ext_at);
    os << std::format("    {}, 0, nullptr /* PER: roms_count, aoms_count, oms */\n", roms_count);
    os << "};\n\n";

    // TypeDescriptor
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        std::format("asn1::Tag::universal({}, true)", tag_num),
        false, true, false, false, "asn1::TypeKind::Sequence");

    // set_<member> definitions (ASN1CPP_VALIDATE_ON_SET hook)
    for (const auto& r : rows) {
            if (r.setter.param_type.empty()) continue;
            // tdref is "&asn_DEF_Foo" or "&asn_TYP_Parent_member"; strip leading &
            std::string tdname = (r.tdref.size() > 1 && r.tdref[0] == '&')
                ? r.tdref.substr(1) : r.tdref;
            std::string assign = r.setter.is_move
                ? std::format("{} = std::move(val);", r.mname)
                : (r.setter.is_int_alias || r.setter.is_uint_alias
                    ? std::format("{} = val;", r.mname)
                    : std::format("{}.set(val);", r.mname));
            std::string validate_expr = r.setter.is_int_alias
                ? std::format("asn1::Integer{{{}}}.validate({}.constraints)", r.mname, tdname)
                : r.setter.is_uint_alias
                    ? std::format("asn1::UInteger{{{}}}.validate({}.constraints)", r.mname, tdname)
                    : std::format("{}.validate({}.constraints)", r.mname, tdname);
            os << std::format("void {}::set_{}({} val) {{\n", cname, r.mname, r.setter.param_type);
            os << std::format("    {}\n", assign);
            os << "#if defined(ASN1CPP_VALIDATE_ON_SET) && defined(ASN1CPP_VALIDATE)\n";
            os << std::format("    if ({}) asn1::bump_validate_fail();\n", validate_expr);
            os << "#endif\n";
            os << "}\n";
    }
    if (!rows.empty()) os << "\n";

}

// ---------------------------------------------------------------------------
// Emit CHOICE
// ---------------------------------------------------------------------------

void Generator::emit_choice_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto [count, ext_at] = count_members(def);

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
            auto cn2 = cpp_name_for_ref(make_synthetic_name(cname, m->name), current_module_);
            os << std::format("#include \"{}.hpp\"\n", cn2);
            track_include(cn2);
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            auto synth = make_synthetic_name(cname, m->name);
            os << std::format("#include \"{}.hpp\"\n", synth);
            track_include(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty()) {
                auto synth = make_synthetic_name(cname, m->name);
                os << std::format("#include \"{}.hpp\"\n", synth);
                track_include(synth);
            }
        }
    }
    if (count > 0) os << "\n";

    // class with PR enum + std::variant storage + typed accessors
    os << std::format("#include <variant>\n");
    os << std::format("class {} : public asn1::ChoiceBase<{}> {{\npublic:\n", cname, cname);
    os << "    enum class PR : int { NOTHING = 0";
    int pr_idx = 1;
    for (const auto& m : def.members)
        if (!m->is_extension_marker)
            os << std::format(", {} = {}", to_cpp_name(m->name), pr_idx++);
    os << " };\n";
    // _present at offset 0 for codec int-write backward compat
    os << "    int _present{0};\n";
    // variant storage — only active alternative constructed
    os << "    std::variant<std::monostate";
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        os << std::format(", {}", cpp_type_for(*m));
    }
    os << "> u{};\n";
    // present() read accessor
    os << "    PR present() const { return static_cast<PR>(_present); }\n";
    // set_present: emplace the right alternative
    os << "    void set_present(PR p) {\n";
    os << "        switch (p) {\n";
    os << "        case PR::NOTHING: u.emplace<0>(); _present = 0; break;\n";
    pr_idx = 1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        os << std::format("        case PR::{}: u.emplace<{}>(); _present = {}; break;\n",
                          to_cpp_name(m->name), pr_idx, pr_idx);
        ++pr_idx;
    }
    os << "        }\n    }\n";
    // typed accessor methods
    pr_idx = 1;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string t = cpp_type_for(*m);
        std::string n = to_member_name(m->name);
        os << std::format("    {0}& {1}() {{ return std::get<{2}>(u); }}\n", t, n, pr_idx);
        os << std::format("    const {0}& {1}() const {{ return std::get<{2}>(u); }}\n", t, n, pr_idx);
        ++pr_idx;
    }
    if (count > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_alternatives[{}];\n", count);
        os << "    static const int s_alternative_count;\n";
    }
    os << "};\n\n";

    // Extern descriptor declarations (s_alternatives declared inside class; only SPC+DEF are global)
    os << std::format("extern const asn1::ChoiceSpec       asn_SPC_{};\n", cname);
    os << std::format("extern const asn1::TypeDescriptor   asn_DEF_{};\n\n", cname);

}

void Generator::emit_choice_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto [count, ext_at] = count_members(def);
    bool apply_auto_tags = should_apply_auto_tags(def);
    bool has_tag_index = false;
    int  tag_index_base = 0, tag_index_size = 0;

    // Alternative descriptor table
    if (count > 0) {
        struct AltRow {
            std::string name, eff_tag, mname, tdref;
            bool is_explicit;
            int  tag_cls_int = -1;  // -1 = not context; >=0 = Context tag number
        };
        std::vector<AltRow> rows;
        // Pass 1: collect rows + emit any static TypeDescriptors (must precede array).
        { int auto_tag_num = 0;
          for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string mname = to_member_name(m->name);
            auto [eff_tag, is_explicit] = compute_member_tag(*m, apply_auto_tags, auto_tag_num);
            std::string tdref = emit_member_type_descriptor(*m, cname, mname, os);
            int tag_ctx_num = -1;
            if (apply_auto_tags)
                tag_ctx_num = auto_tag_num;
            else if (m->tag.present() && m->tag.cls == ast::TagClass::Context)
                tag_ctx_num = m->tag.number;
            rows.push_back({ m->name, eff_tag, mname, tdref, is_explicit, tag_ctx_num });
            ++auto_tag_num;
          }
        }
        // Pass 2: emit static variant accessor functions.
        { int vi = 1;
          for (const auto& r : rows) {
            os << std::format("static void* _get_mut_{0}_{1}(void* p) {{ return &std::get<{2}>(static_cast<{0}*>(p)->u); }}\n",
                cname, r.mname, vi);
            os << std::format("static const void* _get_const_{0}_{1}(const void* p) {{ return &std::get<{2}>(static_cast<const {0}*>(p)->u); }}\n",
                cname, r.mname, vi);
            os << std::format("static void _emplace_{0}_{1}(void* p) {{ static_cast<{0}*>(p)->u.emplace<{2}>(); }}\n",
                cname, r.mname, vi);
            ++vi;
          }
          os << '\n';
        }
        // Pass 3: emit array (as class static member definition).
        os << std::format("const asn1::MemberDescriptor {}::s_alternatives[] = {{\n", cname);
        { int vi = 1;
          for (const auto& r : rows) {
            os << std::format("    {{ \"{}\", {}, false, false, 0 /* variant */, {}, {{}}, {}, nullptr, nullptr,\n",
                r.name, r.eff_tag,
                r.tdref,
                r.is_explicit ? "true" : "false");
            os << std::format("      &_emplace_{0}_{1}, &_get_mut_{0}_{1}, &_get_const_{0}_{1} }},\n",
                cname, r.mname);
            ++vi;
          }
        }
        os << "};\n";
        os << std::format("const int {}::s_alternative_count = {};\n\n", cname, count);

        // O(1) context-tag dispatch table — emit when ALL alternatives carry a context tag.
        // Density threshold: only emit if range <= 4× count (avoids huge sparse arrays).
        bool all_ctx = true;
        int min_tag = std::numeric_limits<int>::max(), max_tag = std::numeric_limits<int>::min();
        for (const auto& r : rows) {
            if (r.tag_cls_int < 0) { all_ctx = false; break; }
            min_tag = std::min(min_tag, r.tag_cls_int);
            max_tag = std::max(max_tag, r.tag_cls_int);
        }
        int range = all_ctx ? (max_tag - min_tag + 1) : 0;
        if (all_ctx && count > 1 && range <= 4 * count) {
            has_tag_index = true;
            tag_index_base = min_tag;
            tag_index_size = range;
            std::vector<int16_t> idx_table(range, -1);
            for (int i = 0; i < (int)rows.size(); ++i)
                idx_table[rows[i].tag_cls_int - min_tag] = (int16_t)i;
            os << std::format("static const int16_t asn_TAGIDX_{}[] = {{", cname);
            for (int i = 0; i < range; ++i)
                os << (i ? ", " : "") << idx_table[i];
            os << "};\n\n";
        }
    }

    // Compute flattened BER dispatch table (needed when any alternative is an untagged
    // CHOICE that contributes its inner tags for outer dispatch).
    // When AUTOMATIC TAGS is applied, all alternatives have distinct context tags — no table needed.
    std::vector<std::pair<std::string,int>> ber_tags; // {tag_literal, 0-based alt_index}
    bool needs_ber_table = false;
    if (!apply_auto_tags) {
        int ai = 0;
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            if (!m->tag.present() && natural_tag_for(*m).empty())
                needs_ber_table = true;
            std::set<std::string> visited;
            collect_ber_tags_for(*m, ai, ber_tags, visited);
            ++ai;
        }
    }
    if (needs_ber_table && !ber_tags.empty()) {
        os << std::format("static const asn1::ChoiceTagEntry asn_BER_{}[] = {{\n", cname);
        for (const auto& [tag_lit, idx] : ber_tags)
            os << std::format("    {{ {}, {} }},\n", tag_lit, idx);
        os << "};\n\n";
    }

    // ChoiceSpec
    os << std::format("const asn1::ChoiceSpec asn_SPC_{} = {{\n", cname);
    if (count > 0)
        os << std::format("    {}::s_alternatives,\n", cname);
    else
        os << "    nullptr,\n";
    os << std::format("    {},\n", count);
    os << std::format("    {}, /* ext_at */\n", ext_at);
    os << "    {} /* PER: constraints */\n";
    if (needs_ber_table && !ber_tags.empty())
        os << std::format("    , asn_BER_{0}, {1} /* ber_tags */\n", cname, (int)ber_tags.size());
    else if (has_tag_index)
        os << "    , nullptr, 0 /* ber_tags */\n";
    if (has_tag_index)
        os << std::format("    , asn_TAGIDX_{0}, {1}, {2} /* tag_index */\n",
                          cname, tag_index_base, tag_index_size);
    os << "};\n\n";

    // TypeDescriptor — CHOICE tag is a transparent placeholder (no fixed universal tag)
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        "asn1::Tag{asn1::TagClass::Context, 0, false}",
        false, false, true, false, "asn1::TypeKind::Choice");

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
            auto synth = make_synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name);
            os << std::format("#include \"{}.hpp\"\n\n", synth);
            track_include(synth);
        }
        os << std::format("using {} = asn1::VectorSeqOf<{}>;\n\n", cname, cpp_type_for(*elem));
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
    os << std::format("    \"{}\",\n", def.xer_name.empty() ? def.name : def.xer_name);
    os << std::format("    {},\n", natural_tag_for(def));
    os << "    nullptr, nullptr, nullptr, nullptr,\n";

    if (needs_per) {
        auto sc = compute_size_constraint(size_range);

        // FROM alphabet metadata
        int alphabet_bits = 0;
        if (!alphabet.empty()) {
            int alphabet_size = static_cast<int>(alphabet.size());
            for (int r = alphabet_size - 1; r > 0; r >>= 1) ++alphabet_bits;
            if (alphabet_bits == 0) alphabet_bits = 1;
        }

        int flags = asn1::Constraints::CONSTRAINED | sc.flags
                  | (is_constraint_extensible(def) ? asn1::Constraints::EXTENSIBLE : 0);
        int val_lb = alphabet.empty() ? 0 : static_cast<int>(alphabet[0]);
        int val_ub = alphabet.empty() ? 0 : static_cast<int>(alphabet.back());

        os << std::format(
            "    {{ .flags={}, .lower_bound={}, .upper_bound={}, "
            ".size_range_bits={}, .size_lower={}, .size_upper={}, .alphabet_bits={}",
            flags, val_lb, val_ub, sc.range_bits, sc.lower, sc.upper, alphabet_bits);
        if (!alphabet.empty()) {
            os << ", .alphabet=std::vector<uint8_t>{";
            for (int i = 0; i < static_cast<int>(alphabet.size()); ++i) {
                if (i) os << ", ";
                os << static_cast<int>(alphabet[i]);
            }
            os << "}";
        }
        os << " } /* constraints */,\n";
    } else {
        os << "    {} /* constraints — unconstrained */,\n";
    }
    os << "    false, asn1::TypeKind::Primitive\n";
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

    // SIZE constraint on collection length
    auto sc = compute_size_constraint(extract_size_range(def));

    // SeqOfSpec — when the element is an inline-constrained builtin (e.g.
    // SEQUENCE OF INTEGER (0..100)) emit a per-element TypeDescriptor that
    // carries the constraint, otherwise reuse the natural type descriptor.
    std::ostringstream elem_decl;
    std::string elem_ref = emit_member_type_descriptor(elem_node, cname, "elem", elem_decl);
    if (!elem_decl.str().empty()) os << elem_decl.str();
    os << std::format("const asn1::SeqOfSpec asn_SPC_{} = {{\n", cname);
    os << std::format("    {},\n", elem_ref);
    os << std::format("    {{ .flags={}, .size_range_bits={}, .size_lower={}, .size_upper={} }},\n",
                      sc.flags, sc.range_bits, sc.lower, sc.upper);
    os << "};\n\n";

    // TypeDescriptor
    uint32_t of_tag = def.is_set_of() ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        std::format("asn1::Tag::universal({}, true)", of_tag),
        false, false, false, true, "asn1::TypeKind::SeqOf");
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
            bool was_anon = elem.name.empty();
            std::string synth_name = make_synthetic_name(parent_cname, was_anon ? "Anon" : elem.name);
            if (!generated_names_.count(synth_name)) {
                generated_names_.insert(synth_name);
                auto synthetic = std::make_shared<ast::TypeDef>(elem);
                synthetic->name = synth_name;
                if (was_anon) {
                    synthetic->xer_name = elem.is_sequence() ? "SEQUENCE"
                                        : elem.is_set()      ? "SET"
                                        : "CHOICE";
                }
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
                bool was_anon = elem.name.empty();
                elem_type_name = make_synthetic_name(parent_cname, was_anon ? "Anon" : elem.name);
                if (!generated_names_.count(elem_type_name)) {
                    generated_names_.insert(elem_type_name);
                    auto synthetic = std::make_shared<ast::TypeDef>(elem);
                    synthetic->name = elem_type_name;
                    if (was_anon) {
                        synthetic->xer_name = elem.is_sequence() ? "SEQUENCE"
                                            : elem.is_set()      ? "SET"
                                            : "CHOICE";
                    }
                    generate_inline_types(*synthetic, mod);
                    current_type_ = elem_type_name;
                    { std::ofstream hpp(out_dir_ / (elem_type_name + ".hpp")); emit_hpp(*synthetic, mod, hpp); }
                    { std::ofstream cpp(out_dir_ / (elem_type_name + ".cpp")); emit_cpp(*synthetic, cpp); }
                }
            }
            // Generate synthetic SeqOf wrapper descriptor type named parent + MemberCamel.
            // If element was anonymous inline, replace it with a TypeRef to the named element
            // type so emit_hpp uses the correct name and include path.
            std::string seqof_name = make_synthetic_name(parent_cname, m->name);
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

        std::string synth_name = make_synthetic_name(parent_cname, m->name);

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

    current_tag_default_ = mod.tag_default;
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
        os << "    nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive\n";
        os << "};\n\n";
    }
}

} // namespace asn1::codegen
