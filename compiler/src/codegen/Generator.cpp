#include "Generator.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <sstream>
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/TypeDescriptor.hpp"
#include "asn1cpp/codec/Constraints.hpp"

namespace asn1::codegen {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Write content to path only if it differs from the existing file.
// Uses a .tmp sidecar: write there, compare, then rename or remove.
// Avoids bumping mtime on unchanged generated files → fewer downstream recompiles.
static void write_if_changed(const fs::path& path, const std::string& content) {
    fs::path tmp = path; tmp += ".tmp";
    { std::ofstream out(tmp, std::ios::binary); out << content; }
    if (fs::exists(path)) {
        std::ifstream existing(path, std::ios::binary);
        std::string old((std::istreambuf_iterator<char>(existing)),
                         std::istreambuf_iterator<char>());
        if (old == content) { fs::remove(tmp); return; }
    }
    fs::rename(tmp, path);
}

// Emit to a string then call write_if_changed.
template<typename EmitFn>
static void emit_file(const fs::path& path, EmitFn&& fn) {
    std::ostringstream buf;
    fn(buf);
    write_if_changed(path, buf.str());
}

// ---------------------------------------------------------------------------

// Linux NAME_MAX is 255; .hpp/.cpp extensions take 4 bytes. When cname exceeds
// 240 chars, truncate to 220 and append a deterministic FNV-1a 32-bit hash so
// the filename fits on any POSIX filesystem.
static std::string filename_for(const std::string& cname) {
    if (cname.size() <= 240) return cname;
    uint32_t h = 2166136261u;
    for (unsigned char c : cname) { h ^= c; h *= 16777619u; }
    char suffix[10];
    snprintf(suffix, sizeof(suffix), "_%08x", h);
    return cname.substr(0, 220) + suffix;
}

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
        const auto& elem = *sof.element;
        if (!def.name.empty() && (elem.is_sequence() || elem.is_choice() || elem.is_set()) && elem.name.empty())
            return std::format("asn1::VectorSeqOf<{}>",
                               make_synthetic_name(make_synthetic_name(current_type_, def.name), "Anon"));
        return std::format("asn1::VectorSeqOf<{}>", cpp_type_for(elem));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        const auto& elem = *sof.element;
        if (!def.name.empty() && (elem.is_sequence() || elem.is_choice() || elem.is_set()) && elem.name.empty())
            return std::format("asn1::VectorSeqOf<{}>",
                               make_synthetic_name(make_synthetic_name(current_type_, def.name), "Anon"));
        return std::format("asn1::VectorSeqOf<{}>", cpp_type_for(elem));
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

/// @brief Decide whether a member carries an explicit BER tag override and,
///        if so, what class/number/encoding-form applies.
/// @param tag         The member's (possibly absent) tag override.
/// @param constructed True if the encoding form is constructed, not primitive.
/// @return The tag decision as plain data, or nullopt if `tag` is absent.
/// @note Backend-agnostic: no C++ syntax. Separated from format_tag_literal()
///       so a future non-C++ backend can consume the decision directly.
std::optional<TagSpec> Generator::tag_spec_for(const ast::Tag& tag, bool constructed) const {
    if (!tag.present()) return std::nullopt;
    return TagSpec{tag.cls, tag.number, constructed};
}

/// @brief Format a tag decision as a C++ `asn1::Tag{...}` literal string.
/// @param tag_spec The decision to format (class, number, encoding form).
/// @return A C++ expression string, e.g. `"asn1::Tag{asn1::TagClass::Context, 1, false}"`.
static std::string format_tag_literal(const TagSpec& tag_spec) {
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

/// @brief Returns "asn1::Tag{...}" literal for a tag override, empty string if absent.
/// @param tag         The member's (possibly absent) tag override.
/// @param constructed True if the encoding form is constructed, not primitive.
/// @return The C++ literal string, or "" if `tag` is absent.
std::string Generator::tag_literal(const ast::Tag& tag, bool constructed) const {
    auto spec = tag_spec_for(tag, constructed);
    if (!spec) return "";
    return format_tag_literal(*spec);
}

/// @brief Decide the natural (universal) BER tag for a member def's
///        underlying type — see Generator::natural_tag_spec_for in the header
///        for the full contract. Plain data, no C++ syntax.
std::optional<TagSpec> Generator::natural_tag_spec_for(const ast::TypeDef& def) const {
    if (def.tag.present()) {
        bool is_constr = def.is_sequence() || def.is_choice() ||
                         def.is_seq_of()   || def.is_set_of() || def.is_set();
        bool is_exp = member_is_explicit(def.tag, def);
        return tag_spec_for(def.tag, is_exp || is_constr);
    }
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        if (*bt == BT::Any)
            // ANY is stored as raw BER bytes at runtime; codegen uses OCTET STRING tag.
            // sema treats ANY as tag-less (no fixed universal tag), so builtin_universal_tag returns 0.
            return TagSpec{ast::TagClass::Universal, asn1::UniversalTag::OctetString, false};
        uint32_t n = sema::builtin_universal_tag(*bt);
        if (n) return TagSpec{ast::TagClass::Universal, n, false};
    }
    if (def.is_sequence())
        return TagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set())
        return TagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (def.is_choice())
        return std::nullopt;  // CHOICE has no universal tag
    if (def.is_seq_of())
        return TagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set_of())
        return TagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto base = resolver_.resolve_ref(*tr);
        if (base) return natural_tag_spec_for(*base);
    }
    return TagSpec{ast::TagClass::Universal, 4, false};  // fallback: OCTET STRING
}

/// @brief Returns the natural (universal) tag for a member def's underlying type.
/// @param def Member or referenced type to compute the natural tag for.
/// @return C++ literal string, or "" for CHOICE (no universal tag).
std::string Generator::natural_tag_for(const ast::TypeDef& def) const {
    auto spec = natural_tag_spec_for(def);
    if (!spec) return "";
    return format_tag_literal(*spec);
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

// Escape a C++ identifier vs keywords and optional extra reserved API names.
inline std::string safe_cpp_name(const std::string& s,
                                  std::initializer_list<std::string_view> extra = {}) {
    return safe_name(s, extra);
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
    // Inline ENUMERATED member — use synthetic name (generates a class)
    if (auto* bt2 = std::get_if<BT>(&def.body);
        bt2 && *bt2 == BT::Enumerated && !def.enum_values.empty() && !current_type_.empty()) {
        auto sname = make_synthetic_name(current_type_, def.name.empty() ? "Enum" : def.name);
        return std::format("&{}::asn_DEF", sname);
    }
    // Named type reference.
    // Pure TypeRef aliases (e.g. "LawfulInterceptionIdentifier ::= LIID") generate only a
    // C++ `using` declaration — no asn_DEF_. Follow the chain until reaching a type that
    // generates its own descriptor (BuiltinType with constraints, SEQUENCE, CHOICE, etc.).
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
                if (td) {
                    auto n = effective_cpp_name(tr->type_name, def_mod);
                    if (td->is_sequence() || td->is_set() || td->is_choice() ||
                        (std::get_if<BT>(&td->body) && std::get<BT>(td->body) == BT::Enumerated))
                        return std::format("&{}::asn_DEF", n);
                    return std::format("&asn_DEF_{}", n);
                }
            }
        }
        auto resolved = resolver_.resolve_ref(*tr);
        if (resolved && !resolved->name.empty()) {
            if (std::get_if<ast::TypeRef>(&resolved->body))
                return type_descriptor_ref_for(*resolved);  // pure alias — follow chain
            bool is_class = resolved->is_sequence() || resolved->is_set() || resolved->is_choice() ||
                (std::get_if<BT>(&resolved->body) && std::get<BT>(resolved->body) == BT::Enumerated);
            // Qualified ref: use explicit module for collision disambiguation on resolved name.
            if (!tr->module_name.empty() && collision_types_.count(to_cpp_name(resolved->name))) {
                auto n = effective_cpp_name(resolved->name, tr->module_name);
                return is_class ? std::format("&{}::asn_DEF", n)
                                : std::format("&asn_DEF_{}", n);
            }
            auto n = cpp_name_for_ref(resolved->name, current_module_);
            return is_class ? std::format("&{}::asn_DEF", n)
                            : std::format("&asn_DEF_{}", n);
        }
        // Fallback: unresolved ref — synthetic types (compiler-generated SeqOf element
        // replacements) are always SEQUENCE/CHOICE/ENUM → class-scoped static member.
        return std::format("&{}::asn_DEF", cpp_name_for_typeref(*tr));
    }
    // SEQUENCE OF / SET OF — named member uses synthetic SeqOf wrapper descriptor (using alias)
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
    // Inline SEQUENCE / CHOICE / SET member — synthetic name, generates a class
    if (def.is_sequence() || def.is_choice() || def.is_set()) {
        auto sname = make_synthetic_name(current_type_, def.name.empty() ? "Anon" : def.name);
        return std::format("&{}::asn_DEF", sname);
    }
    return "nullptr";
}

// ---------------------------------------------------------------------------
// Member-list helpers
// ---------------------------------------------------------------------------

/// @brief Split def.members into (root, extension) lists, skipping extension markers.
/// Extension members are optional by definition; root members carry their own optional flag.
/// @param def  Any type definition whose members list may contain an extension marker.
/// @return Pair (root, ext): root members before the marker, extension members after.
/// @see X.680 §24.1 — ExtensionEndMarker separates root and extension component lists.
static std::pair<std::vector<const ast::TypeDef*>, std::vector<const ast::TypeDef*>>
split_members(const ast::TypeDef& def)
{
    std::vector<const ast::TypeDef*> root, ext;
    bool past = false;
    for (const auto& m : def.members) {
        if (m->is_extension_marker) { past = true; continue; }
        (past ? ext : root).push_back(m.get());
    }
    return {root, ext};
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
                                 const std::string& kind,
                                 const std::string& per_handler = "nullptr",
                                 const std::string& ber_handler = "nullptr",
                                 bool use_class_scope = false) {
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

    // class inheriting EnumValue — plain inner enum so values leak into class scope
    os << std::format("class {} : public asn1::EnumValue {{\npublic:\n", cname);
    // Enum values are plain enum (not enum class) — they inject into class scope.
    // Reserve all generated method names so values can't clash with them.
    os << "    enum Enm : long {\n";
    long auto_val = 0;
    for (const auto& ev : def.enum_values) {
        if (ev.name == "...") { continue; }
        long v = static_cast<long>(ev.number.value_or(auto_val));
        os << std::format("        {} = {},\n",
            safe_cpp_name(to_cpp_name(ev.name),
                {"present", "value_", "value", "set", "Enm"}), v);
        auto_val = v + 1;
    }
    if (extensible)
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
    os << std::format("    static const asn1::EnumEntry    asn_MAP_value2enum[{}];\n", count);
    os << "    static const asn1::EnumSpec     asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";

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

    os << std::format("const asn1::EnumEntry {}::asn_MAP_value2enum[] = {{\n", cname);
    for (const auto& ev : sorted)
        os << std::format("    {{ {}, \"{}\" }},\n", ev.value, ev.name);
    os << "};\n\n";

    // PER: root values in definition order (ordinal → value mapping). File-local — not in header.
    os << std::format("static const long asn_PER_{}_value_order[] = {{\n", cname);
    for (int i = 0; i < ext_root_count; ++i)
        os << std::format("    {},\n", root_values[i].value);
    os << "};\n\n";

    // EnumSpec
    os << std::format("const asn1::EnumSpec {}::asn_SPC = {{\n", cname);
    os << std::format("    {}::asn_MAP_value2enum,\n", cname);
    os << std::format("    {},\n", (int)sorted.size());
    os << std::format("    {}, /* extensible */\n", extensible ? "true" : "false");
    os << std::format("    {}, /* root_count */\n", ext_root_count);
    os << std::format("    asn_PER_{}_value_order\n", cname);
    os << "};\n\n";

    // TypeDescriptor
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Enumerated),
        true, false, false, false, "asn1::TypeKind::Enumerated",
        "&asn1::per_enumerated_handler", "&asn1::ber_enumerated_handler",
        /*use_class_scope=*/true);

}

// ---------------------------------------------------------------------------
// Emit INTEGER
// ---------------------------------------------------------------------------

IntStorageKind Generator::classify_integer_storage(const ast::TypeDef& def) const {
    auto r = extract_integer_range(def);
    if (!r.has_value) return default_int_kind_;  // unconstrained → CLI default
    // Semi-constrained (..MAX) with lo>=0: needs unsigned storage, no fixed upper.
    if (r.truly_max && r.lo >= 0) return IntStorageKind::U64;
    // Literal upper was TOK_number_large (> INT64_MAX): needs unsigned storage.
    if (r.hi_is_large && r.lo >= 0) return IntStorageKind::U64;
    return IntStorageKind::S64;
}

void Generator::emit_integer_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto kind = classify_integer_storage(def);
    std::string cpp_storage;
    switch (kind) {
        case IntStorageKind::U64:       cpp_storage = "asn1::UInteger"; break;
        case IntStorageKind::I128:      cpp_storage = "__int128"; break;
        case IntStorageKind::ARBITRARY: cpp_storage = "std::vector<uint8_t>"; break;
        default:                        cpp_storage = "asn1::Integer"; break;
    }
    os << std::format("using {} = {};\n\n", cname, cpp_storage);

    // Named integer constants (INTEGER { foo(0), bar(1) } style)
    for (const auto& ev : def.enum_values)
        os << std::format("inline constexpr int64_t {}_{} = {};\n",
            cname, to_value_name(ev.name), ev.number.value_or(0));
    if (!def.enum_values.empty()) os << "\n";

    os << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
}

// Walk a value reference chain until a literal is reached.
// Returns the terminal def (whose default_value is a literal), or nullptr on
// undefined ref or if the hop limit is hit.
//
// Cycles cannot occur in valid input: resolve_value_assignments() in the sema
// phase rejects them before codegen runs (see Resolver.hpp). The hop limit is
// defence-in-depth only — it guards against a future caller that skips sema
// (e.g. a test harness or tool that drives Generator directly). Without it, a
// cycle would cause an infinite loop; with it, the constraint is silently
// dropped (upper/lower bound defaults to unconstrained), which is at least safe.
//
// `cur_module` tracks the module in which the *current* node was defined so
// that unqualified references in each hop resolve against the right scope.
static ast::TypeDefPtr follow_value_chain(const ast::NamedValueRef& start,
                                          const sema::Resolver& res,
                                          const std::string& from_module,
                                          int limit = 32) {
    std::string cur_module = from_module;
    ast::TypeDefPtr cur = res.lookup_value_ref(start, cur_module);
    // Advance cur_module to the actual owning module so unqualified references
    // in subsequent hops resolve in the right scope, not the caller's module.
    if (cur) cur_module = res.module_of(start.name, cur_module);

    for (int i = 0; i < limit && cur; ++i) {
        if (!std::holds_alternative<ast::NamedValueRef>(cur->default_value)) return cur;
        const auto& nvr = std::get<ast::NamedValueRef>(cur->default_value);
        cur = res.lookup_value_ref(nvr, cur_module);
        // For qualified refs the owning module is explicit; for unqualified
        // refs use module_of() to find the actual owning module rather than
        // assuming it is cur_module (where the reference appeared).
        if (cur) cur_module = nvr.module_name.empty()
                                  ? res.module_of(nvr.name, cur_module)
                                  : nvr.module_name;
    }
    return nullptr;
}

// Try to extract a concrete int64_t from a Value, resolving NamedValueRef via resolver.
// Follows multi-hop chains (a ::= b, b ::= c, c ::= 42). Cycle-safe via hop limit.
std::optional<int64_t> Generator::resolve_int_value(const ast::Value& v) const {
    if (auto* i = std::get_if<int64_t>(&v)) return *i;
    if (auto* u = std::get_if<uint64_t>(&v)) return static_cast<int64_t>(*u);
    if (auto* ref = std::get_if<ast::NamedValueRef>(&v)) {
        auto def = follow_value_chain(*ref, resolver_, current_module_);
        if (def) {
            if (auto* i = std::get_if<int64_t>(&def->default_value)) return *i;
            if (auto* u = std::get_if<uint64_t>(&def->default_value)) return static_cast<int64_t>(*u);
        }
    }
    return std::nullopt;
}

// Try to extract a uint64_t from a Value (for large positive literals).
std::optional<uint64_t> Generator::resolve_uint_value(const ast::Value& v) const {
    if (auto* u = std::get_if<uint64_t>(&v)) return *u;
    if (auto* i = std::get_if<int64_t>(&v)) return static_cast<uint64_t>(*i);
    if (auto* ref = std::get_if<ast::NamedValueRef>(&v)) {
        auto def = follow_value_chain(*ref, resolver_, current_module_);
        if (def) {
            if (auto* u = std::get_if<uint64_t>(&def->default_value)) return *u;
            if (auto* i = std::get_if<int64_t>(&def->default_value)) return static_cast<uint64_t>(*i);
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
    } else if (auto* s = std::get_if<std::string>(&m.default_value)) {
        // String literal default (IA5String/VisibleString/PrintableString/etc.)
        // Full C escape: backslash, quote, and all control characters.
        std::string esc;
        for (unsigned char c : *s) {
            if      (c == '\\') esc += "\\\\";
            else if (c == '"')  esc += "\\\"";
            else if (c == '\n') esc += "\\n";
            else if (c == '\r') esc += "\\r";
            else if (c == '\t') esc += "\\t";
            else if (c < 0x20 || c == 0x7f)
                esc += std::format("\\x{:02x}", c);
            else
                esc += static_cast<char>(c);
        }
        literal = std::format("{}{{\"{}\"}}", mtype, esc);
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
        "static void {0}(asn1::Asn1Object* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    Ops::set(p, true);\n"
        "    *static_cast<{3}*>(Ops::get(p)) = {4};\n"
        "}}\n",
        fname, parent_cname, mname, mtype, literal);
    os << std::format(
        "static bool {0}(const asn1::Asn1Object* p) {{\n"
        "    using Ops = _Ops_{1}_{2};\n"
        "    if (!Ops::check(p)) return false;\n"
        "    return *static_cast<const {3}*>(Ops::get(const_cast<asn1::Asn1Object*>(p))) == ({4});\n"
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

// Forward decls: defined later in this file; needed by emit_member_type_descriptor.
// (Generator member fns can resolve named value references; extract_from_alphabet is free.)
static std::vector<uint8_t> extract_from_alphabet(const ast::TypeDef& def);

/// @brief Returns ceil(log2(n)) clamped to [1,∞) — bits per character for an n-symbol alphabet.
static int compute_alphabet_bits(int n) {
    int bits = 0;
    for (int r = n - 1; r > 0; r >>= 1) ++bits;
    return (bits == 0) ? 1 : bits;
}

/// @brief Returns the name of the global `asn_DEF_*` descriptor for a restricted built-in
///        string type, or nullptr for types without a fixed alphabet (UTF8String, etc.).
/// @param bt  Built-in type tag.
/// @return Pointer to a string literal such as `"asn_DEF_NumericString"`, or nullptr.
/// @see X.680 §41 — restricted character string types and their canonical alphabets.
static const char* builtin_def_name(ast::BuiltinType bt) {
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

/// @brief Emit static FROM-alphabet lookup tables into a generated `.cpp` file.
/// @param os          Output stream for the generated `.cpp` file.
/// @param prefix      Name prefix used for the static arrays (e.g. `"asn_FROM_MyStr"`).
/// @param alphabet    Sorted FROM-alphabet character values (non-empty).
/// @see X.691 §26.5 — known-multiplier character string PER encoding.
static void emit_from_alphabet_arrays(
    std::ostream& os, const std::string& prefix,
    const std::vector<uint8_t>& alphabet)
{
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
/// @param builtin_def   Result of builtin_def_name() for the base string type; used to
///                      inherit alphabet_bits/alphabet/encode_table from the global descriptor
///                      when there is a SIZE constraint but no FROM constraint.  nullptr = skip.
/// @return Initializer string, e.g. `"{ .flags=8, .size_lower=6, .size_upper=6, … }"`.
/// @see X.691 §26.5 (character string PER encoding); X.691 §12 (size constraints).
static std::string make_string_constraints_init(
    int flags, int sc_range_bits, int64_t sc_lower, int64_t sc_upper,
    const std::vector<uint8_t>& alphabet,
    const std::string& alpha_prefix = "",
    std::optional<ast::BuiltinType> builtin_bt = std::nullopt)
{
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
// Returns {lo, hi, truly_max, hi_u64} where:
//   truly_max  = true  → upper endpoint was the MAX keyword (semi-constrained)
//   hi_is_large = true → upper was TOK_number_large (positive literal > INT64_MAX);
//                        hi_u64 holds the exact unsigned value
//   otherwise         → upper was a signed literal or named ref; use hi (int64_t)
Generator::IntRange
Generator::extract_integer_range(const ast::TypeDef& def) const {
    // Intersect all ValueRange constraints (including those nested inside
    // IntersectionConstraint): take max(lowers) and min(uppers).
    std::optional<int64_t> lo;
    std::optional<int64_t> hi;
    bool truly_max = false;
    uint64_t hi_u64 = 0;
    bool hi_is_large = false;
    walk_type_constraints(def, [&](const ast::ConstraintBody& body) {
        auto* vr = std::get_if<ast::ValueRange>(&body);
        if (!vr) return;
        int64_t vlo = (vr->lower.kind == ast::RangeEndpoint::Kind::Min)
            ? std::numeric_limits<int64_t>::min()
            : resolve_int_value(vr->lower.value).value_or(std::numeric_limits<int64_t>::min());
        bool vhi_is_max = (vr->upper.kind == ast::RangeEndpoint::Kind::Max);
        int64_t vhi;
        uint64_t vhi_u64 = 0;
        bool vhi_is_large = false;
        if (vhi_is_max) {
            vhi = std::numeric_limits<int64_t>::max();
            vhi_u64 = std::numeric_limits<uint64_t>::max();
        } else if (auto* u = std::get_if<uint64_t>(&vr->upper.value)) {
            /* TOK_number_large: positive literal that does not fit in int64_t */
            vhi_u64 = *u;
            vhi = static_cast<int64_t>(vhi_u64);
            vhi_is_large = true;
        } else {
            /* TOK_number / TOK_number_negative / named ref: signed literal */
            vhi = resolve_int_value(vr->upper.value).value_or(std::numeric_limits<int64_t>::max());
        }
        lo = lo ? std::max(*lo, vlo) : vlo;
        if (!hi || vhi < *hi) {
            hi = vhi;
            truly_max = vhi_is_max;
            hi_u64 = vhi_u64;
            hi_is_large = vhi_is_large;
        }
    });
    if (lo && hi) return IntRange{true, *lo, *hi, truly_max, hi_u64, hi_is_large};
    return IntRange{false, 0, 0, false, 0, false};
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

    auto r     = extract_integer_range(def);
    auto kind  = classify_integer_storage(def);
    int  ik    = (kind == IntStorageKind::U64) ? asn1::Constraints::INT_U64
               : (kind == IntStorageKind::I128) ? asn1::Constraints::INT_I128
               : (kind == IntStorageKind::ARBITRARY) ? asn1::Constraints::INT_ARBITRARY
               : asn1::Constraints::INT_S64;

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.xer_name.empty() ? def.name : def.xer_name);
    os << std::format("    asn1::Tag::universal({}, false),\n", asn1::UniversalTag::Integer);
    os << "    nullptr, nullptr, nullptr, nullptr,\n";
    if (r.has_value) {
        int64_t lo = r.lo, hi = r.hi;
        bool ext = is_constraint_extensible(def);
        if (r.truly_max) {
            // Truly semi-constrained (..MAX keyword): no upper cap.
            int flags = asn1::Constraints::SEMI_CONSTRAINED
                      | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            os << std::format("    {} /* constraints — semi-constrained */,\n",
                make_integer_pc(flags, -1, ik, lo, 0,
                    static_cast<uint64_t>(lo >= 0 ? lo : 0),
                    std::numeric_limits<uint64_t>::max()));
        } else if (r.hi_is_large) {
            // TOK_number_large upper bound (e.g. UINT64_MAX).
            // X.691 §10.5.6 UPER: range = hi_u64 - lo + 1; compute range_bits.
            // For the full uint64 range (lo=0, hi=UINT64_MAX), range_bits=64.
            int rb = 0;
            uint64_t u_lo = static_cast<uint64_t>(lo >= 0 ? lo : 0);
            // range = hi_u64 - u_lo + 1; if it wraps (full 64-bit range), rb=64.
            uint64_t range_count_m1 = r.hi_u64 - u_lo; // range - 1 (exact even if range=2^64)
            if (range_count_m1 == std::numeric_limits<uint64_t>::max()) {
                rb = 64; // 2^64 range
            } else {
                for (uint64_t v = range_count_m1; v > 0; v >>= 1) ++rb;
            }
            int flags = asn1::Constraints::CONSTRAINED
                      | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            os << std::format("    {} /* constraints — constrained large (up to UINT64_MAX) */,\n",
                make_integer_pc(flags, rb, ik, lo, hi /* int64_t view */,
                    u_lo, r.hi_u64));
        } else {
            int64_t range_count = hi - lo + 1;
            int rb = 0;
            if (range_count > 1)
                for (int64_t v = range_count - 1; v > 0; v >>= 1) ++rb;
            int flags = asn1::Constraints::CONSTRAINED
                      | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            uint64_t u_lo = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
            uint64_t u_hi = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
            os << std::format("    {} /* constraints */,\n",
                make_integer_pc(flags, rb, ik, lo, hi, u_lo, u_hi));
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

// ---------------------------------------------------------------------------
// Inline-constrained member TypeDescriptor helpers
// ---------------------------------------------------------------------------

/// @brief Emit a static per-member TypeDescriptor when the member carries inline constraints.
/// @param m             Member type definition (may carry value-range, SIZE, or FROM constraints).
/// @param parent_cname  C++ name of the enclosing SEQUENCE/CHOICE type.
/// @param mname         Sanitised C++ member name used as the descriptor variable suffix.
/// @param os            Output stream for the generated `.cpp` file.
/// @return A C++ expression referencing the descriptor (e.g. `"&asn_TYP_Foo_bar"`).
/// @see X.691 §26.5 (character string constraints), §18.5 (SEQUENCE preamble bitmap).
std::string Generator::emit_member_type_descriptor(
    const ast::TypeDef& m, const std::string& parent_cname,
    const std::string& mname, std::ostream& os)
{
    using BT = ast::BuiltinType;
    auto* bt = std::get_if<BT>(&m.body);
    bool needs_xer = m.xer_encoding != ast::XerEncoding::Default;
    if (!bt || (m.constraints.empty() && !needs_xer)) return type_descriptor_ref_for(m);

    // INTEGER value range
    if (*bt == BT::Integer) {
        auto ir = extract_integer_range(m);
        if (ir.has_value) {
            std::string tname = std::format("asn_TYP_{}_{}", parent_cname, mname);
            int64_t lo = ir.lo, hi = ir.hi;
            bool ext = is_constraint_extensible(m);
            auto kind = classify_integer_storage(m);
            int ik = (kind == IntStorageKind::U64)       ? asn1::Constraints::INT_U64
                   : (kind == IntStorageKind::I128)      ? asn1::Constraints::INT_I128
                   : (kind == IntStorageKind::ARBITRARY) ? asn1::Constraints::INT_ARBITRARY
                   : asn1::Constraints::INT_S64;
            std::string pc;
            if (ir.truly_max) {
                // Truly semi-constrained (..MAX): no upper cap.
                int flags = asn1::Constraints::SEMI_CONSTRAINED
                          | (ext ? asn1::Constraints::EXTENSIBLE : 0);
                pc = make_integer_pc(flags, -1, ik, lo, 0,
                    static_cast<uint64_t>(lo >= 0 ? lo : 0),
                    std::numeric_limits<uint64_t>::max());
            } else if (ir.hi_is_large) {
                // TOK_number_large upper bound (e.g. UINT64_MAX).
                uint64_t u_lo = static_cast<uint64_t>(lo >= 0 ? lo : 0);
                uint64_t range_count_m1 = ir.hi_u64 - u_lo;
                int rb = (range_count_m1 == std::numeric_limits<uint64_t>::max())
                    ? 64 : 0;
                if (rb == 0) for (uint64_t v = range_count_m1; v > 0; v >>= 1) ++rb;
                int flags = asn1::Constraints::CONSTRAINED
                          | (ext ? asn1::Constraints::EXTENSIBLE : 0);
                pc = make_integer_pc(flags, rb, ik, lo, hi, u_lo, ir.hi_u64);
            } else {
                int64_t rc = hi - lo + 1;
                int rb = 0;
                if (rc > 1) for (int64_t v = rc - 1; v > 0; v >>= 1) ++rb;
                int flags = asn1::Constraints::CONSTRAINED
                          | (ext ? asn1::Constraints::EXTENSIBLE : 0);
                uint64_t u_lo = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
                uint64_t u_hi = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
                pc = make_integer_pc(flags, rb, ik, lo, hi, u_lo, u_hi);
            }
            const char* per_h = (kind == IntStorageKind::U64)
                ? "&asn1::per_uinteger_handler" : "&asn1::per_integer_handler";
            const char* ber_h = (kind == IntStorageKind::U64)
                ? "&asn1::ber_uinteger_handler" : "&asn1::ber_integer_handler";
            const char* cpp_t = (kind == IntStorageKind::U64)
                ? "asn1::UInteger" : "asn1::Integer";
            os << std::format(
                "static const asn1::TypeDescriptor {} = "
                "{{ \"INTEGER\", asn1::Tag::universal({}, false), "
                "nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive, {}, {}, "
                "asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) }};\n",
                tname, asn1::UniversalTag::Integer, pc, per_h, ber_h, cpp_t);
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
        auto sr       = extract_size_range(m);
        auto alphabet = extract_from_alphabet(m);
        // UTF8String is not a known-multiplier character string (X.691 §26.6):
        // FROM constraints on it are not enforced in PER encoding — drop alphabet.
        if (*bt == BT::Utf8String) alphabet.clear();
        if (sr || !alphabet.empty() || needs_xer) {
            // Compute SIZE constraint fields.
            int     sc_flags = 0, sc_range_bits = 0;
            int64_t sc_lower = 0, sc_upper = 0;
            if (sr) {
                auto sc = compute_size_constraint(sr, is_constraint_extensible(m));
                sc_flags = sc.flags; sc_range_bits = sc.range_bits;
                sc_lower = sc.lower; sc_upper = sc.upper;
            }
            bool ext = is_constraint_extensible(m);
            // FROM("A".."Z",...) has the extension marker inside the FromConstraint;
            // is_constraint_extensible only checks the outer Constraint::extensible.
            if (!ext && !alphabet.empty()) {
                walk_type_constraints(m, [&](const ast::ConstraintBody& body) {
                    auto* fc = std::get_if<ast::FromConstraint>(&body);
                    if (fc && fc->inner && fc->inner->extensible) ext = true;
                });
            }
            int  all_flags = sc_flags | (ext ? asn1::Constraints::EXTENSIBLE : 0);
            std::string alpha_prefix;
            if (!alphabet.empty()) {
                alpha_prefix = std::format("asn_FROM_{}_{}", parent_cname, mname);
                emit_from_alphabet_arrays(os, alpha_prefix, alphabet);
            }
            std::optional<ast::BuiltinType> bbt = alphabet.empty() ? std::optional{*bt} : std::nullopt;
            std::string pc = (!sr && alphabet.empty() && (!bbt || !builtin_def_name(*bbt)))
                ? "{}"
                : make_string_constraints_init(all_flags, sc_range_bits, sc_lower, sc_upper,
                                               alphabet, alpha_prefix, bbt);
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
            const char* per_h = "&asn1::per_string_handler";
            if (*bt == BT::BitString)   per_h = "&asn1::per_bitstring_handler";
            if (*bt == BT::OctetString) per_h = "&asn1::per_octetstring_handler";
            const char* ber_h = "&asn1::ber_string_handler";
            if (*bt == BT::BitString)   ber_h = "&asn1::ber_bitstring_handler";
            if (*bt == BT::OctetString) ber_h = "&asn1::ber_octetstring_handler";
            std::string cpp_t = cpp_type_for(m);
            std::string xer_tail = needs_xer ? ", asn1::XerEncoding::Base64" : "";
            os << std::format(
                "static const asn1::TypeDescriptor {} = "
                "{{ \"{}\", asn1::Tag::universal({}, false), "
                "nullptr, nullptr, nullptr, nullptr, {}, false, asn1::TypeKind::Primitive, {}, {}, "
                "asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}){}}};\n",
                tname, tn, *utag, pc, per_h, ber_h, cpp_t, xer_tail);
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

/// @brief Emit the `.hpp` for a SEQUENCE or SET type.
/// @param def  ASN.1 type definition (must satisfy is_sequence() or is_set()).
/// @param os   Output stream for the generated header.
/// @see X.680 §24 (SEQUENCE), §26 (SET); X.690 §8.9 (BER SEQUENCE encoding).
void Generator::emit_sequence_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    // Count non-extension members
    auto [mcount, ext_at] = count_members(def);

    // Determine if a member's named type is directly a class (SEQUENCE/CHOICE/SET) and can be
    // forward-declared. Using a direct lookup (not following aliases) is essential: a type alias
    // like `TraceActivation ::= ExternalASNType` generates `using TraceActivation = ...` in C++,
    // which cannot be forward-declared as `class TraceActivation;`.

    // Emit includes or forward declarations.
    // Optional class-typed members: forward declaration only (breaks circular includes).
    // Self-referential SEQUENCE OF members (e.g. `many SEQUENCE OF PDU` inside PDU):
    //   the synthetic SeqOf header (PDUMany.hpp) uses VectorSeqOf<PDU> which requires PDU
    //   to be complete — defer those includes to after the class definition.
    // Everything else: full include before the class.
    std::vector<std::string> post_class_includes; // deferred self-referential SeqOf includes
    auto [sm_root, sm_ext] = split_members(def);

    auto emit_inc = [&](const std::string& cn) {
        auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
        inc_os << std::format("#include \"{}.hpp\"\n", filename_for(cn));
    };
    auto emit_fwd = [&](const std::string& cn) {
        os << std::format("class {};\n", cn);
    };
    auto emit_member_include = [&](const ast::TypeDef& m, bool optional) {
        if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
            auto cn = cpp_name_for_typeref(*tr);
            optional && is_class_type(m) ? emit_fwd(cn) : emit_inc(cn);
        } else if (m.is_seq_of() || m.is_set_of()) {
            if (!m.name.empty()) {
                // Named member — check for self-referential element type.
                const auto& seqof_elem = m.is_seq_of()
                    ? std::get<ast::SequenceOfType>(m.body).element
                    : std::get<ast::SetOfType>(m.body).element;
                bool self_ref = false;
                if (auto* tr_elem = std::get_if<ast::TypeRef>(&seqof_elem->body))
                    self_ref = (to_cpp_name(tr_elem->type_name) == to_cpp_name(def.name));
                auto synth = make_synthetic_name(cname, m.name);
                if (self_ref)
                    post_class_includes.push_back(synth); // defer: needs current class complete
                else
                    emit_inc(synth);
            } else {
                const auto& elem = m.is_seq_of()
                    ? std::get<ast::SequenceOfType>(m.body).element
                    : std::get<ast::SetOfType>(m.body).element;
                if (auto* tr2 = std::get_if<ast::TypeRef>(&elem->body)) {
                    emit_inc(cpp_name_for_typeref(*tr2));
                } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
                    emit_inc(make_synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name));
                }
            }
        } else if ((m.is_sequence() || m.is_choice() || m.is_set()) && !m.name.empty()) {
            auto synth = make_synthetic_name(cname, m.name);
            optional ? emit_fwd(synth) : emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m.body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m.enum_values.empty())
                emit_inc(make_synthetic_name(cname, m.name));
        }
    };
    for (auto* m : sm_root) emit_member_include(*m, m->is_optional());
    for (auto* m : sm_ext)  emit_member_include(*m, /*optional=*/true);
    if (mcount > 0) os << "\n";

    // Determine if any optional members exist — they will use unique_ptr.
    bool has_optional_members = !sm_ext.empty() ||
        std::any_of(sm_root.begin(), sm_root.end(),
                    [](const ast::TypeDef* m){ return m->is_optional(); });

    // class — optional members use unique_ptr (forward-decl compatible, matches asn1c semantics)
    os << std::format("class {} : public asn1::SequenceBase<{}> {{\npublic:\n", cname, cname);
    if (has_optional_members) {
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
    for (auto* m : sm_root) {
        std::string mtype = cpp_type_for(*m);
        std::string mname = to_member_name(m->name);
        if (m->is_optional())
            os << std::format("    std::unique_ptr<{}> {};\n", mtype, mname);
        else
            os << std::format("    {} {}{{}};\n", mtype, mname);
    }
    for (auto* m : sm_ext) {
        os << std::format("    std::unique_ptr<{}> {};\n",
                          cpp_type_for(*m), to_member_name(m->name));
    }
    // set_<member> declarations for non-optional root members only
    for (auto* m : sm_root) {
        if (m->is_optional()) continue;
        auto si = classify_member_setter(*m);
        if (si.param_type.empty()) continue;
        os << std::format("    void set_{}({} val);\n",
                          to_member_name(m->name), si.param_type);
    }
    if (mcount > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_members[{}];\n", mcount);
        os << "    static const int s_member_count;\n";
    }
    os << "    static const asn1::SequenceSpec   asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";

    // Self-referential SeqOf includes: deferred until class is complete.
    // post_ns_os_ routes them after `} // namespace` in namespace mode.
    if (!post_class_includes.empty()) {
        auto& inc_os = post_ns_os_ ? *post_ns_os_ : os;
        for (const auto& sinc : post_class_includes) {
            inc_os << std::format("#include \"{}.hpp\"\n", filename_for(sinc));
        }
        inc_os << "\n";
    }
}

/// @brief Emit the .cpp-side definitions for a generated SEQUENCE type.
/// @param def  The SEQUENCE TypeDef from the AST.
/// @param os   Output stream for the generated .cpp source file.
/// @see X.680 §24 — SEQUENCE type.
void Generator::emit_sequence_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();
    uint32_t tag_num = is_set ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;

    auto [mcount, ext_at] = count_members(def);

    auto [sm_root, sm_ext] = split_members(def);

    // Determine if any optional members exist.
    bool has_optional_members = !sm_ext.empty() ||
        std::any_of(sm_root.begin(), sm_root.end(),
                    [](const ast::TypeDef* m){ return m->is_optional(); });

    if (has_optional_members) {
        // Forward-declared types in the .hpp need full includes in the .cpp.
        bool emitted_extra = false;
        auto emit_opt_include = [&](const ast::TypeDef& m) {
            if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
                if (is_class_type(m)) {
                    auto cn = cpp_name_for_typeref(*tr);
                    auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
                    inc_os << std::format("#include \"{}.hpp\"\n", filename_for(cn));
                    emitted_extra = true;
                }
            } else if ((m.is_sequence() || m.is_choice() || m.is_set()) && !m.name.empty()) {
                auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
                inc_os << std::format("#include \"{}.hpp\"\n",
                                      filename_for(make_synthetic_name(cname, m.name)));
                emitted_extra = true;
            }
        };
        for (auto* m : sm_root) { if (m->is_optional()) emit_opt_include(*m); }
        for (auto* m : sm_ext)  emit_opt_include(*m);
        if (emitted_extra) { auto& nl_os = pre_ns_os_ ? *pre_ns_os_ : os; nl_os << "\n"; }

        // All special members defined here where unique_ptr<T> has complete T.
        os << std::format("{0}::{0}() = default;\n", cname);
        os << std::format("{0}::~{0}() = default;\n", cname);
        os << std::format("{0}::{0}(const {0}& o) : {0}() {{ asn1::deep_copy(asn_DEF, this, &o); }}\n", cname);
        os << std::format("{0}& {0}::operator=(const {0}& o) {{ if (this != &o) asn1::deep_copy(asn_DEF, this, &o); return *this; }}\n", cname);
        os << std::format("{0}::{0}({0}&&) noexcept = default;\n", cname);
        os << std::format("{0}& {0}::operator=({0}&&) noexcept = default;\n\n", cname);
    }

    // Count root-only optional members (for PER preamble bitmap width).
    // Extension members are NOT counted — they have their own extension bitmap.
    int roms_count = static_cast<int>(
        std::count_if(sm_root.begin(), sm_root.end(),
                      [](const ast::TypeDef* m){ return m->is_optional(); }));

    // Type aliases for optional member callbacks — one per optional member.
    // Optional members: UniquePtrOps (check/set/get_ptr through unique_ptr).
    // Required members: use offsetof (no alias needed).
    for (auto* m : sm_root) {
        if (!m->is_optional()) continue;
        os << std::format("using _Ops_{0}_{1} = asn1::UniquePtrOps<{0}, {2}, &{0}::{1}>;\n",
                          cname, to_member_name(m->name), cpp_type_for(*m));
    }
    for (auto* m : sm_ext) {
        os << std::format("using _Ops_{0}_{1} = asn1::UniquePtrOps<{0}, {2}, &{0}::{1}>;\n",
                          cname, to_member_name(m->name), cpp_type_for(*m));
    }
    os << "\n";

    // Determine if AUTOMATIC TAGS applies: module is AUTOMATIC TAGS and none of the
    // ComponentTypes in any ComponentTypeList has an explicit tag (X.680 §24.8).
    bool apply_auto_tags = should_apply_auto_tags(def);

    // Per-member row data — hoisted so setter definitions can reference it after
    // the descriptor table block.
    struct MbrRow {
        std::string name, eff_tag, mname, ops, tdref, def_setter, offset_expr;
        bool optional, is_explicit, has_default;
        MemberSetterInfo setter;
    };
    std::vector<MbrRow> rows;

    // Member descriptor table
    if (mcount > 0) {
        // Pass 1: collect per-row data and emit any static per-member TypeDescriptors
        // before the array opening brace (can't have declarations inside initializer lists).
        // atag continues across root→ext so auto-tagging numbers extensions after root members.
        {
            int atag = 0;
            auto collect = [&](const ast::TypeDef& m, bool optional) {
                std::string mname = to_member_name(m.name);
                auto [eff_tag, is_explicit] = compute_member_tag(m, apply_auto_tags, atag);
                std::string ops = optional
                    ? std::format("{{ &_Ops_{0}_{1}::check, &_Ops_{0}_{1}::set, &_Ops_{0}_{1}::get }}", cname, mname)
                    : "{ nullptr, nullptr, nullptr }";
                std::string tdref = emit_member_type_descriptor(m, cname, mname, os);
                std::string def_setter = emit_default_setter(m, cname, mname, os);
                bool has_default = (m.marker == ast::Marker::Default);
                auto setter = optional ? MemberSetterInfo{} : classify_member_setter(m);
                // Required members use offset arithmetic; optional use get_ptr (offset unused).
                // Sentinel kInvalidMemberOffset for optional: accidental use crashes immediately.
                std::string offset_expr = optional ? "asn1::kInvalidMemberOffset"
                    : std::format("ASN1CPP_OFFSETOF({}, {})", cname, mname);
                rows.push_back({ m.name, eff_tag, mname, ops, tdref, def_setter, offset_expr,
                                 optional, is_explicit, has_default, std::move(setter) });
                ++atag;
            };
            for (auto* m : sm_root) collect(*m, m->is_optional());
            for (auto* m : sm_ext)  collect(*m, /*optional=*/true);
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
            os << std::format("    {{ \"{}\", {}, {}, {}, {}, {}, {}, {}, {}, {} }},\n",
                r.name, r.eff_tag,
                r.optional ? "true" : "false",
                r.has_default ? "true" : "false",
                r.offset_expr,
                r.tdref, r.ops,
                r.is_explicit ? "true" : "false",
                r.def_setter, def_cmp);
        }
        os << "};\n";
        os << std::format("const int {}::s_member_count = {};\n\n", cname, mcount);
    }

    // SequenceSpec
    os << std::format("const asn1::SequenceSpec {}::asn_SPC = {{\n", cname);
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
        false, true, false, false, "asn1::TypeKind::Sequence",
        "&asn1::per_sequence_handler", "&asn1::ber_sequence_handler",
        /*use_class_scope=*/true);

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

/// @brief Map an ASN.1 tag to a (class, number) sort key for canonical PER ordering.
/// @param tag            The tag to convert.
/// @param apply_auto_tags True when the enclosing module uses AUTOMATIC TAGS.
/// @param auto_n         Declaration-order position used as tag number when auto-tagging.
/// @return (class, number) pair; tagless alternatives return (INT_MAX, INT_MAX) to sort last.
/// @see X.691 §22.6 — CHOICE alternatives encoded in canonical tag order.
static std::pair<int,int> canonical_tag_key(const ast::Tag& tag, bool apply_auto_tags, int auto_n) {
    if (apply_auto_tags && !tag.present())
        return { static_cast<int>(ast::TagClass::Context), auto_n };
    if (tag.present())
        return { static_cast<int>(tag.cls), tag.number };
    return { INT_MAX, INT_MAX };
}

/// @brief Less-than comparator for canonical PER tag ordering of CHOICE alternatives.
/// @param a,b            Tags to compare.
/// @param apply_auto_tags True when the enclosing module uses AUTOMATIC TAGS.
/// @param auto_a,auto_b  Declaration-order positions for auto-tag resolution.
/// @return True if a sorts before b in canonical order.
static bool canonical_tag_less(const ast::Tag& a, const ast::Tag& b,
                                bool apply_auto_tags, int auto_a, int auto_b) {
    return canonical_tag_key(a, apply_auto_tags, auto_a)
         < canonical_tag_key(b, apply_auto_tags, auto_b);
}

// Returns CHOICE members (no extension markers) in canonical PER tag order.
/// @brief Build the canonical ordered alternative list for a CHOICE type.
/// @param def             The CHOICE TypeDef from the AST.
/// @param apply_auto_tags Whether AUTOMATIC TAGS mode is in effect for this module.
/// @return Root alternatives (sorted by tag unless AUTOMATIC TAGS) followed by extension
///         alternatives, with auto-generated tags applied if requested.
/// @see X.680 §28 — CHOICE type; X.680 §24.8 — AUTOMATIC TAGS.
// Root alternatives sorted by (tag_class, tag_number); extension alternatives
// sorted by (tag_class, tag_number). For AUTOMATIC TAGS schemas, root alternatives
// are Context[0],[1],[2]... — already canonical, so the sort is a no-op there.
// Extension alternatives with explicit non-sequential tags (e.g. ext1=[1],ext0=[0])
// are reordered here so the generator emits them in canonical order.
static std::vector<const ast::TypeDef*> canonical_choice_members(
    const ast::TypeDef& def, bool apply_auto_tags)
{
    auto [root_alts, ext_alts] = split_members(def);

    // Root: if not AUTOMATIC TAGS, sort by explicit tag (tagless go last).
    if (!apply_auto_tags) {
        std::vector<std::pair<const ast::TypeDef*, int>> root_with_num;
        int n = 0;
        for (auto* r : root_alts) root_with_num.push_back({ r, n++ });
        std::stable_sort(root_with_num.begin(), root_with_num.end(),
            [&](const auto& a, const auto& b) {
                return canonical_tag_less(a.first->tag, b.first->tag,
                                         /*apply_auto_tags=*/false, a.second, b.second);
            });
        root_alts.clear();
        for (auto& [m, _] : root_with_num) root_alts.push_back(m);
    }
    // Extension: sort by explicit tag (tagless go last, same comparator for consistency).
    std::stable_sort(ext_alts.begin(), ext_alts.end(),
        [](const ast::TypeDef* a, const ast::TypeDef* b) {
            return canonical_tag_less(a->tag, b->tag, /*apply_auto_tags=*/false, 0, 0);
        });

    std::vector<const ast::TypeDef*> result(root_alts);
    result.insert(result.end(), ext_alts.begin(), ext_alts.end());
    return result;
}

/// @brief Emit the `.hpp` for a CHOICE type.
/// @param def  ASN.1 type definition (must satisfy is_choice()).
/// @param os   Output stream for the generated header.
/// @see X.680 §28 (CHOICE); X.690 §8.13 (BER CHOICE encoding); X.691 §22 (PER CHOICE).
void Generator::emit_choice_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto [count, ext_at] = count_members(def);

    // #include referenced alternative types and inline-type headers
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        auto emit_inc = [&](const std::string& cn) {
            auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
            inc_os << std::format("#include \"{}.hpp\"\n", filename_for(cn));
        };
        if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
            emit_inc(cpp_name_for_typeref(*tr));
        } else if ((m->is_seq_of() || m->is_set_of()) && !m->name.empty()) {
            // Named SEQUENCE OF alternative — include the synthetic SeqOf wrapper header
            auto cn2 = cpp_name_for_ref(make_synthetic_name(cname, m->name), current_module_);
            emit_inc(cn2);
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            auto synth = make_synthetic_name(cname, m->name);
            emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty()) {
                auto synth = make_synthetic_name(cname, m->name);
                emit_inc(synth);
            }
        }
    }
    if (count > 0) os << "\n";

    // Storage strategy: raw byte buffer sized/aligned to the largest alternative.
    //
    // Why not std::variant<T1, T2, ..., TN>?
    //   std::variant is implemented via recursive template specialisations.
    //   std::get<K> descends K levels of template recursion.  With N alternatives and
    //   N different get<K> calls, GCC instantiates O(N²) templates.  For a CHOICE
    //   with 198 alternatives (e.g. XIRIContents in the ETSI LI schema) this
    //   consumes ~5 GB RSS and kills the build.
    //
    // Why a char buffer instead of a typed union?
    //   A union { T1 a; T2 b; ... } still needs per-member access syntax and doesn't
    //   help with the destructor/copy dispatch problem.  A raw char[] + placement new
    //   lets the _emplace_* functions in the .cpp carry all type knowledge, keeping
    //   the header O(N) in both parse and instantiation cost.
    //
    // How it works:
    //   alignas(max_align) char val_[max_size]   — in-place storage, no heap
    //     max_size  = std::max({sizeof(T1), ..., sizeof(TN)})   — constexpr O(N) scan
    //     max_align = std::max({alignof(T1), ..., alignof(TN)}) — constexpr O(N) scan
    //   active_lifecycle — pointer into TypeDescriptor::lifecycle of the current alternative;
    //   set by ChoiceInterface::emplace_alt. destroy/move ops reached via one pointer deref.
    //   std::launder is required on every read-back after placement-new (C++17 §6.8.4).

    os << std::format("class {} : public asn1::ChoiceInterface {{\npublic:\n", cname);
    bool apply_auto_tags_hpp = should_apply_auto_tags(def);
    auto canon_members = canonical_choice_members(def, apply_auto_tags_hpp);
    os << "    enum class PR : int { NOTHING = 0";
    int pr_idx = 1;
    for (const auto* m : canon_members)
        os << std::format(", {} = {}",
            safe_cpp_name(to_cpp_name(m->name), {"NOTHING"}), pr_idx++);
    os << " };\n";

    // val_storage_: raw byte buffer sized/aligned to the largest alternative.
    // val_ (in ChoiceInterface base) points here — set once in the constructor.
    os << "    alignas(std::max({";
    { bool first = true;
      for (const auto* m : canon_members) {
        if (!first) os << ", ";
        os << std::format("alignof({})", cpp_type_for(*m));
        first = false;
      }
      if (count > 0) os << ", ";
      os << "size_t(1)})) char val_storage_[std::max({";
    }
    { bool first = true;
      for (const auto* m : canon_members) {
        if (!first) os << ", ";
        os << std::format("sizeof({})", cpp_type_for(*m));
        first = false;
      }
      if (count > 0) os << ", ";
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

    for (const auto* m : canon_members) {
        std::string t = cpp_type_for(*m);
        std::string n = to_member_name(m->name,
            {"present", "set_present", "val_", "val_storage_", "active_lifecycle",
             "s_alternatives", "s_alternative_count"});
        os << std::format(
            "    {0}& {1}() {{ return *std::launder(reinterpret_cast<{0}*>(val_)); }}\n", t, n);
        os << std::format(
            "    const {0}& {1}() const"
            " {{ return *std::launder(reinterpret_cast<const {0}*>(val_)); }}\n", t, n);
    }
    if (count > 0) {
        os << std::format("    static const asn1::MemberDescriptor s_alternatives[{}];\n", count);
        os << "    static const int s_alternative_count;\n";
    }
    os << "    static const asn1::ChoiceSpec     asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";

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
            std::string name, eff_tag, mname, tdref, alt_type;
            bool is_explicit;
            int  tag_cls_int = -1;  // -1 = not context; >=0 = Context tag number
            ast::Tag full_tag;      // for canonical sort
        };
        std::vector<AltRow> rows;
        // Pass 1: collect rows in declaration order + emit static TypeDescriptors.
        // TypeDescriptors must be emitted before the alternatives array references them.
        { int auto_tag_num = 0;
          for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string mname = to_member_name(m->name);
            auto [eff_tag, is_explicit] = compute_member_tag(*m, apply_auto_tags, auto_tag_num);
            std::string tdref = emit_member_type_descriptor(*m, cname, mname, os);
            std::string alt_type = cpp_type_for(*m);
            int tag_ctx_num = -1;
            ast::Tag full_tag = m->tag;
            if (apply_auto_tags && !m->tag.present()) {
                tag_ctx_num = auto_tag_num;
                full_tag.cls = ast::TagClass::Context;
                full_tag.number = auto_tag_num;
            } else if (m->tag.present() && m->tag.cls == ast::TagClass::Context) {
                tag_ctx_num = m->tag.number;
            }
            rows.push_back({ m->name, eff_tag, mname, tdref, alt_type, is_explicit,
                             tag_ctx_num, full_tag });
            ++auto_tag_num;
          }
        }
        // Sort root and extension alternatives separately into canonical tag order.
        // X.691 §22.6: PER uses tag-ascending order; generator pre-sorts so runtime
        // can use the array index directly without a canonical-map lookup.
        // full_tag already incorporates auto-tags (resolved during pass 1), so sort
        // with apply_auto_tags=false here — the effective tag is already in full_tag.
        // Tagless alternatives (full_tag not present) sort last, matching
        // canonical_choice_members() so PR enum indices stay aligned with s_alternatives[].
        { int ext_start = (ext_at >= 0) ? ext_at : count;
          auto tag_cmp = [](const AltRow& a, const AltRow& b) {
              return canonical_tag_less(a.full_tag, b.full_tag,
                                       /*apply_auto_tags=*/false, 0, 0);
          };
          if (!apply_auto_tags)   // root already canonical for AUTOMATIC TAGS
              std::stable_sort(rows.begin(), rows.begin() + ext_start, tag_cmp);
          if (ext_at >= 0)
              std::stable_sort(rows.begin() + ext_at, rows.end(), tag_cmp);
          // Rebuild tag_ctx_num for the tag-index table after reorder.
          for (auto& r : rows)
              r.tag_cls_int = (r.full_tag.present() && r.full_tag.cls == ast::TagClass::Context)
                              ? r.full_tag.number : -1;
        }
        // Pass 2 removed: _get_mut_T_alt / _get_const_T_alt / _emplace_T_alt named free
        // functions replaced by ChoiceOps<AltT>::get_mut / get_const (single-type-param
        // template in ChoiceInterface.hpp) and ChoiceInterface::emplace_alt (generic).

        // Pass 3: emit array (as class static member definition).
        os << std::format("const asn1::MemberDescriptor {}::s_alternatives[] = {{\n", cname);
        { for (const auto& r : rows) {
            os << std::format("    {{ \"{}\", {}, false, false, asn1::kInvalidMemberOffset, {}, {{}}, {}, nullptr, nullptr,\n",
                r.name, r.eff_tag, r.tdref, r.is_explicit ? "true" : "false");
            os << std::format("      &asn1::ChoiceOps<{0}>::get_mut, &asn1::ChoiceOps<{0}>::get_const }},\n",
                r.alt_type);
          }
        }
        os << "};\n";
        os << std::format("const int {}::s_alternative_count = {};\n\n", cname, count);

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
    os << std::format("const asn1::ChoiceSpec {}::asn_SPC = {{\n", cname);
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
        false, false, true, false, "asn1::TypeKind::Choice",
        "&asn1::per_choice_handler", "&asn1::ber_choice_handler",
        /*use_class_scope=*/true);

}

// ---------------------------------------------------------------------------
// Top-level emit_hpp / emit_cpp dispatch
// ---------------------------------------------------------------------------

/// @brief Emit the `.hpp` file for any top-level type definition.
/// @param def  ASN.1 type definition to generate.
/// @param mod  Owning module (provides tag default and OID for the file header comment).
/// @param os   Output stream for the generated header.
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
    os << "#include <vector>\n";
    os << "#include <span>\n";
    os << "#include <asn1cpp/asn1cpp_gen.hpp>\n\n";

    // When namespace wrapping is active, cross-type #include "X.hpp" directives must land
    // BEFORE the namespace opens (each peer .hpp already wraps itself in the namespace).
    // Forward declarations (class X;) and the class body go inside the namespace.
    // Use a body stringstream; set pre_ns_os_ so emit_inc() writes to os directly.
    // Deferred self-referential includes (post_class_includes from emit_sequence_hpp)
    // must land AFTER the closing `} // namespace` brace — use post_ns_ss for that.
    std::ostringstream body_ns;
    std::ostringstream post_ns_ss;
    std::ostream& body = namespace_.empty() ? os : static_cast<std::ostream&>(body_ns);
    if (!namespace_.empty()) {
        pre_ns_os_  = &os;
        post_ns_os_ = &post_ns_ss;
    }

    if (def.is_sequence() || def.is_set()) {
        current_type_ = cname;
        emit_sequence_hpp(def, body);
    } else if (def.is_choice()) {
        current_type_ = cname;
        emit_choice_hpp(def, body);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated) {
            emit_enumerated_hpp(def, body);
        } else if (*bt == ast::BuiltinType::Integer) {
            emit_integer_hpp(def, body);
        } else {
            body << std::format("using {} = {};\n\n", cname, cpp_type_for(def));
            body << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
        }
    } else if (def.is_seq_of() || def.is_set_of()) {
        current_type_ = cname;
        const auto& elem = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body).element
            : std::get<ast::SetOfType>(def.body).element;
        // SeqOf element includes go before the namespace (each .hpp wraps itself).
        auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : body;
        if (auto* tr = std::get_if<ast::TypeRef>(&elem->body)) {
            auto inc = cpp_name_for_typeref(*tr);
            inc_os << std::format("#include \"{}.hpp\"\n\n", filename_for(inc));
        } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
            auto synth = make_synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name);
            inc_os << std::format("#include \"{}.hpp\"\n\n", filename_for(synth));
        } else if (auto* ebt = std::get_if<ast::BuiltinType>(&elem->body);
                   ebt && *ebt == ast::BuiltinType::Enumerated && !elem->enum_values.empty()) {
            auto synth = make_synthetic_name(cname, elem->name.empty() ? "Enum" : elem->name);
            inc_os << std::format("#include \"{}.hpp\"\n\n", filename_for(synth));
        }
        body << std::format("using {} = asn1::VectorSeqOf<{}>;\n\n", cname, cpp_type_for(*elem));
        body << std::format("extern const asn1::SeqOfSpec     asn_SPC_{};\n", cname);
        body << std::format("extern const asn1::TypeDescriptor asn_DEF_{};\n", cname);
    } else if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto inc = cpp_name_for_typeref(*tr);
        auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : body;
        inc_os << std::format("#include \"{}.hpp\"\n", filename_for(inc));
        body << std::format("using {} = {};\n", cname, inc);
    }

    pre_ns_os_  = nullptr;
    post_ns_os_ = nullptr;
    if (!namespace_.empty()) {
        os << "namespace " << namespace_ << " {\n\n";
        os << body_ns.str();
        os << "\n} // namespace " << namespace_ << "\n";
        auto post = post_ns_ss.str();
        if (!post.empty()) os << "\n" << post;
    }
}


// Extract SIZE (lb..ub) constraint. Returns {lb, ub} or nullopt if none.
// lb==ub → fixed size; ub==INT64_MAX → semi-constrained (SIZE lb..MAX).
std::optional<std::pair<int64_t,int64_t>> Generator::extract_size_range(const ast::TypeDef& def) const {
    std::optional<std::pair<int64_t,int64_t>> result;
    walk_type_constraints(def, [&](const ast::ConstraintBody& body) {
        if (result) return;
        auto* sc = std::get_if<ast::SizeConstraint>(&body);
        if (!sc || !sc->inner) return;
        if (auto* vr = std::get_if<ast::ValueRange>(&sc->inner->body)) {
            int64_t lb = 0, ub = std::numeric_limits<int64_t>::max();
            if (vr->lower.kind != ast::RangeEndpoint::Kind::Min)
                if (auto opt = resolve_int_value(vr->lower.value)) lb = *opt;
            if (vr->upper.kind == ast::RangeEndpoint::Kind::Max)
                ub = std::numeric_limits<int64_t>::max();
            else if (auto opt = resolve_int_value(vr->upper.value)) ub = *opt;
            result = {lb, ub};
        } else if (auto* sv = std::get_if<ast::Value>(&sc->inner->body)) {
            if (auto opt = resolve_int_value(*sv)) result = {*opt, *opt};
        }
    });
    return result;
}

/// @brief Extract the sorted character values of a FROM alphabet constraint.
/// @param def  Type definition to inspect; may carry zero or more FROM sub-constraints.
/// @return Sorted `uint8_t` vector of allowed character codes, or empty if no FROM constraint
///         is present or its values cannot be resolved to single-byte literals.
/// @see X.680 §51.6 (CharacterStringList); X.691 §26.5.2 (known-multiplier string PER encoding).
static std::vector<uint8_t> extract_from_alphabet(const ast::TypeDef& def) {
    std::vector<uint8_t> chars;

    // Collect a single char value from a leaf ConstraintBody.
    auto collect_single = [&](const ast::ConstraintBody& body) {
        if (auto* v = std::get_if<ast::Value>(&body))
            if (auto* s = std::get_if<std::string>(v))
                if (s->size() == 1)
                    chars.push_back(static_cast<uint8_t>((*s)[0]));
    };

    // Collect chars from a leaf: single value or a "lo".."hi" range.
    auto collect_leaf = [&](const ast::ConstraintBody& body) {
        if (auto* r = std::get_if<ast::ValueRange>(&body)) {
            // Expand "A".."Z" style ranges (single-byte string endpoints only).
            if (r->lower.kind == ast::RangeEndpoint::Kind::Value &&
                r->upper.kind == ast::RangeEndpoint::Kind::Value) {
                const auto* lo_s = std::get_if<std::string>(&r->lower.value);
                const auto* hi_s = std::get_if<std::string>(&r->upper.value);
                if (lo_s && hi_s && lo_s->size() == 1 && hi_s->size() == 1) {
                    // Use int to avoid uint8_t wrap when hi == 0xFF.
                    int lo = static_cast<unsigned char>((*lo_s)[0]);
                    int hi = static_cast<unsigned char>((*hi_s)[0]);
                    for (int c = lo; c <= hi; ++c) chars.push_back(static_cast<uint8_t>(c));
                }
            }
        } else {
            collect_single(body);
        }
    };

    // Grammar builds left-recursive Union pairs: A|B|C → Union(Union(A,B),C).
    // Recurse into nested UnionConstraints to reach all leaf Values and ValueRanges.
    std::function<void(const ast::ConstraintBody&)> recurse_union;
    recurse_union = [&](const ast::ConstraintBody& b) {
        if (auto* uc = std::get_if<ast::UnionConstraint>(&b)) {
            for (const auto& op : uc->operands)
                if (op) recurse_union(op->body);
        } else {
            collect_leaf(b);
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

/// @brief Emit the `.cpp` body for a top-level builtin string/octet/bit-string type alias.
/// @param def  ASN.1 type assignment that resolves to a sizeable primitive (e.g. `MyStr ::= IA5String (SIZE(1..32) FROM("A".."Z"))`).
/// @param os   Output stream for the generated `.cpp` file.
/// @see X.691 §26.5 (character string PER constraints); X.690 §8.7 (OCTET STRING BER encoding).
void Generator::emit_builtin_alias_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    // Handler LUTs indexed by ast::BuiltinType (Boolean=0 .. Any=23).
    // Integer and Enumerated are never routed here (handled by separate emit functions).
    using BT = ast::BuiltinType;
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
    auto* bt2 = std::get_if<BT>(&def.body);
    const char* per_h = bt2 ? per_lut[(int)*bt2] : "&asn1::per_string_handler";
    const char* ber_h = bt2 ? ber_lut[(int)*bt2] : "&asn1::ber_string_handler";

    auto alphabet   = extract_from_alphabet(def);
    auto size_range = extract_size_range(def);

    bool needs_per = !alphabet.empty() || size_range.has_value();

    // Emit FROM-alphabet static arrays before the TypeDescriptor so they can be
    // referenced by the Constraints initializer inside it.
    std::string alpha_prefix;
    if (!alphabet.empty()) {
        alpha_prefix = std::format("asn_FROM_{}", cname);
        emit_from_alphabet_arrays(os, alpha_prefix, alphabet);
    }

    os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", def.xer_name.empty() ? def.name : def.xer_name);
    os << std::format("    {},\n", natural_tag_for(def));
    os << "    nullptr, nullptr, nullptr, nullptr,\n";

    if (needs_per) {
        auto sc    = compute_size_constraint(size_range);
        int  flags = asn1::Constraints::CONSTRAINED | sc.flags
                   | (is_constraint_extensible(def) ? asn1::Constraints::EXTENSIBLE : 0);
        std::optional<ast::BuiltinType> bbt = (alphabet.empty() && bt2) ? std::optional{*bt2} : std::nullopt;
        os << "    " << make_string_constraints_init(flags, sc.range_bits, sc.lower, sc.upper,
                                                     alphabet, alpha_prefix, bbt)
           << " /* constraints */,\n";
    } else {
        os << "    {} /* constraints — unconstrained */,\n";
    }
    std::string cpp_t = cpp_type_for(def);
    os << std::format("    false, asn1::TypeKind::Primitive,\n");
    os << std::format("    {} /* per_handler */,\n", per_h);
    os << std::format("    {} /* ber_handler */,\n", ber_h);
    os << std::format("    asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) /* lifecycle */", cpp_t);
    if (def.xer_encoding == ast::XerEncoding::Base64)
        os << ",\n    asn1::XerEncoding::Base64 /* xer_encoding */\n";
    else
        os << "\n";
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

    // SeqOfSpec — when the element is an inline-constrained builtin emit a per-element
    // TypeDescriptor that carries the constraint; otherwise reuse the natural descriptor.
    // When the element has a declared identifier (X.693 §12), emit a renamed TypeDescriptor
    // so that XerCodec sees the right tag via edef.name without any runtime rename.
    std::ostringstream elem_decl;
    bool has_declared_name = !elem_node.name.empty();
    std::string elem_ref = emit_member_type_descriptor(elem_node, cname, "elem", elem_decl);
    // Flush any per-element constrained descriptor before the SeqOfSpec.
    if (!elem_decl.str().empty()) os << elem_decl.str();

    os << std::format("const asn1::SeqOfSpec asn_SPC_{} = {{\n", cname);
    os << std::format("    {},\n", elem_ref);
    os << std::format("    {{ .flags={}, .size_range_bits={}, .size_lower={}, .size_upper={} }},\n",
                      sc.flags, sc.range_bits, sc.lower, sc.upper);
    // X.693 §12: declared element identifier overrides the XER tag at the use site.
    // Exception: asn1c uses <NULL/> for NULL-typed elements regardless of declared name.
    // Similarly, ANY keeps is_any=true semantics and must not be renamed.
    if (has_declared_name) {
        using BT = ast::BuiltinType;
        bool is_null_or_any = false;
        if (auto* bt = std::get_if<BT>(&elem_node.body)) {
            is_null_or_any = (*bt == BT::Null || *bt == BT::Any);
        } else if (auto* tr = std::get_if<ast::TypeRef>(&elem_node.body)) {
            if (auto resolved = resolver_.resolve_ref(*tr, current_module_)) {
                if (auto* rbt = std::get_if<BT>(&resolved->body))
                    is_null_or_any = (*rbt == BT::Null || *rbt == BT::Any);
            }
        }
        if (!is_null_or_any)
            os << std::format("    \"{}\",\n", elem_node.name);
    }
    os << "};\n\n";

    // TypeDescriptor
    uint32_t of_tag = def.is_set_of() ? asn1::UniversalTag::Set : asn1::UniversalTag::Sequence;
    emit_type_descriptor(os, cname,
        def.xer_name.empty() ? def.name : def.xer_name,
        std::format("asn1::Tag::universal({}, true)", of_tag),
        false, false, false, true, "asn1::TypeKind::SeqOf",
        "&asn1::per_seqof_handler", "&asn1::ber_seqof_handler");
}

void Generator::emit_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    os << std::format("#include \"{}.hpp\"\n", filename_for(cname));
    os << "#include <asn1cpp/codec/PerHandlers.hpp>\n";
    os << "#include <asn1cpp/codec/BerHandlers.hpp>\n";
    // __builtin_offsetof is well-defined for all types without virtual functions
    // on GCC/Clang, including non-standard-layout types (conditionally supported
    // per C++ standard). Suppress the pedantic diagnostic in generated files.
    os << "#ifdef __GNUC__\n";
    os << "#pragma GCC diagnostic ignored \"-Winvalid-offsetof\"\n";
    os << "#endif\n\n";

    // When namespace wrapping is active, member-type includes (e.g. for optional members
    // that need a complete type in the .cpp) must precede the namespace opener.
    std::ostringstream body_ns_cpp;
    std::ostream& body = namespace_.empty() ? os : static_cast<std::ostream&>(body_ns_cpp);
    if (!namespace_.empty()) pre_ns_os_ = &os;

    if (def.is_sequence() || def.is_set()) {
        current_type_ = cname;
        emit_sequence_cpp(def, body);
    } else if (def.is_choice()) {
        current_type_ = cname;
        emit_choice_cpp(def, body);
    } else if (def.is_seq_of() || def.is_set_of()) {
        current_type_ = cname;
        emit_seq_of_cpp(def, body);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated)
            emit_enumerated_cpp(def, body);
        else if (*bt == ast::BuiltinType::Integer)
            emit_integer_cpp(def, body);
        else
            emit_builtin_alias_cpp(def, body);
    }

    pre_ns_os_ = nullptr;
    if (!namespace_.empty()) {
        os << "namespace " << namespace_ << " {\n\n";
        os << body_ns_cpp.str();
        os << "\n} // namespace " << namespace_ << "\n";
    }
}

// ---------------------------------------------------------------------------
// Inline type pre-generation
// Emits synthetic top-level types for anonymous SEQUENCE/CHOICE/SET members.
// Must run before the parent type so includes resolve.
// ---------------------------------------------------------------------------

/// @brief Pre-generate synthetic types that must be defined before the parent type's header.
/// @param def  Parent type whose inline member types are to be generated.
/// @param mod  Owning module.
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
                emit_file(out_dir_ / (filename_for(synth_name) + ".hpp"), [&](auto& os){ emit_hpp(*synthetic, mod, os); });
                emit_file(out_dir_ / (filename_for(synth_name) + ".cpp"), [&](auto& os){ emit_cpp(*synthetic, os); });
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
            // Compute seqof_name first so anonymous element types are scoped under it,
            // preventing collisions when multiple SeqOf members have structurally-similar
            // but differently-constrained inline element types (e.g. ctfc2Bit vs ctfc6Bit).
            std::string seqof_name = make_synthetic_name(parent_cname, m->name);
            std::string elem_type_name;  // non-empty iff element was an inline complex type
            if (elem.is_sequence() || elem.is_choice() || elem.is_set()) {
                bool was_anon = elem.name.empty();
                elem_type_name = make_synthetic_name(seqof_name, was_anon ? "Anon" : elem.name);
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
                    emit_file(out_dir_ / (filename_for(elem_type_name) + ".hpp"), [&](auto& os){ emit_hpp(*synthetic, mod, os); });
                    emit_file(out_dir_ / (filename_for(elem_type_name) + ".cpp"), [&](auto& os){ emit_cpp(*synthetic, os); });
                }
            } else if (auto* ebt = std::get_if<ast::BuiltinType>(&elem.body);
                       ebt && *ebt == ast::BuiltinType::Enumerated && !elem.enum_values.empty()) {
                bool was_anon = elem.name.empty();
                elem_type_name = make_synthetic_name(seqof_name, was_anon ? "Enum" : elem.name);
                if (!generated_names_.count(elem_type_name)) {
                    generated_names_.insert(elem_type_name);
                    auto synthetic = std::make_shared<ast::TypeDef>(elem);
                    synthetic->name = elem_type_name;
                    current_type_ = elem_type_name;
                    emit_file(out_dir_ / (filename_for(elem_type_name) + ".hpp"), [&](auto& os){ emit_hpp(*synthetic, mod, os); });
                    emit_file(out_dir_ / (filename_for(elem_type_name) + ".cpp"), [&](auto& os){ emit_cpp(*synthetic, os); });
                }
            }
            // Generate synthetic SeqOf wrapper descriptor type named parent + MemberCamel.
            // If element was anonymous inline, replace it with a TypeRef to the named element
            // type so emit_hpp uses the correct name and include path.
            // (seqof_name already computed above)
            if (!generated_names_.count(seqof_name)) {
                generated_names_.insert(seqof_name);
                auto seqof_td = std::make_shared<ast::TypeDef>(*m);
                seqof_td->name = seqof_name;
                if (!elem_type_name.empty()) {
                    auto named_elem = std::make_shared<ast::TypeDef>();
                    named_elem->body = ast::TypeRef{"", elem_type_name, {}};
                    if (m->is_seq_of())
                        seqof_td->body = ast::SequenceOfType{named_elem};
                    else
                        seqof_td->body = ast::SetOfType{named_elem};
                }
                current_type_ = seqof_name;
                emit_file(out_dir_ / (filename_for(seqof_name) + ".hpp"), [&](auto& os){ emit_hpp(*seqof_td, mod, os); });
                emit_file(out_dir_ / (filename_for(seqof_name) + ".cpp"), [&](auto& os){ emit_cpp(*seqof_td, os); });
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

        auto synthetic = std::make_shared<ast::TypeDef>(*m);
        synthetic->name = synth_name;

        generate_inline_types(*synthetic, mod);

        current_type_ = synth_name;
        emit_file(out_dir_ / (filename_for(synth_name) + ".hpp"), [&](auto& os){ emit_hpp(*synthetic, mod, os); });
        emit_file(out_dir_ / (filename_for(synth_name) + ".cpp"), [&](auto& os){ emit_cpp(*synthetic, os); });
    }
}

// ---------------------------------------------------------------------------
// Per-type file writer
// ---------------------------------------------------------------------------

/// @brief Emit `.hpp` and `.cpp` for one top-level ASN.1 type assignment.
/// @param def  Type assignment to generate (skipped if not a type assignment).
/// @param mod  Owning module (sets current_tag_default_ for the duration).
void Generator::generate_type(const ast::TypeDef& def, const ast::Module& mod) {
    if (!is_type_assignment(def)) return;

    current_tag_default_ = mod.tag_default;
    std::string cname = effective_cpp_name(def.name, mod.name);

    // Pre-generate inline ENUMERATED element types for top-level SEQOF/SETOF.
    // (Analogous to the member-SEQOF path in generate_inline_types.)
    if (def.is_seq_of() || def.is_set_of()) {
        const auto* elem_ptr = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body).element.get()
            : std::get<ast::SetOfType>(def.body).element.get();
        auto* ebt = std::get_if<ast::BuiltinType>(&elem_ptr->body);
        if (ebt && *ebt == ast::BuiltinType::Enumerated && !elem_ptr->enum_values.empty()) {
            std::string elem_name = make_synthetic_name(cname, elem_ptr->name.empty() ? "Enum" : elem_ptr->name);
            if (!generated_names_.count(elem_name)) {
                generated_names_.insert(elem_name);
                auto synthetic = std::make_shared<ast::TypeDef>(*elem_ptr);
                synthetic->name = elem_name;
                auto save = current_type_;
                current_type_ = elem_name;
                emit_file(out_dir_ / (filename_for(elem_name) + ".hpp"), [&](auto& os){ emit_hpp(*synthetic, mod, os); });
                emit_file(out_dir_ / (filename_for(elem_name) + ".cpp"), [&](auto& os){ emit_cpp(*synthetic, os); });
                current_type_ = save;
            }
        }
    }

    emit_file(out_dir_ / (filename_for(cname) + ".hpp"), [&](auto& os){ emit_hpp(def, mod, os); });

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
    if (needs_cpp)
        emit_file(out_dir_ / (filename_for(cname) + ".cpp"), [&](auto& os){ emit_cpp(def, os); });
}

/// @brief Append to `worklist` all ASN.1 type names directly referenced by `def`.
/// @param def      Type definition to inspect (TypeRef body, members, or element type).
/// @param worklist BFS queue; names are pushed without deduplication (caller deduplicates).
void Generator::collect_type_refs(const ast::TypeDef& def, std::vector<std::string>& worklist) {
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        worklist.push_back(tr->type_name);
    }
    if (def.is_sequence() || def.is_set() || def.is_choice()) {
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            collect_type_refs(*m, worklist);
        }
    } else if (def.is_seq_of() || def.is_set_of()) {
        const auto& elem = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body).element
            : std::get<ast::SetOfType>(def.body).element;
        collect_type_refs(*elem, worklist);
    }
}

/// @brief Populate `reachable_asn_names_` via BFS from `pdu_roots_`.
/// @param pr  Full parse result; all modules are searched for type definitions.
///
/// Computes the transitive closure of types reachable from the `-pdu=` roots
/// through TypeRef and structural member edges.  `generate()` then skips any
/// TypeDef whose ASN.1 name is absent from `reachable_asn_names_`.
/// Called only when at least one `-pdu=` root has been set.
void Generator::compute_reachable(const ast::ParseResult& pr) {
    // Build ASN.1-name → ALL definitions multimap.
    // Collision types (same name in multiple modules) are common in ETSI schemas;
    // BFS must walk every module's definition so no cross-module refs are missed.
    std::unordered_map<std::string,
        std::vector<const ast::TypeDef*>> type_multimap;
    for (const auto& mod : pr.modules)
        for (const auto& def : mod->assignments)
            if (!def->name.empty() && !def->is_extension_marker)
                type_multimap[def->name].push_back(def.get());

    // BFS from every requested PDU root.
    std::vector<std::string> worklist(pdu_roots_.begin(), pdu_roots_.end());
    while (!worklist.empty()) {
        auto name = worklist.back(); worklist.pop_back();
        if (reachable_asn_names_.count(name)) continue;

        auto it = type_multimap.find(name);
        if (it == type_multimap.end()) continue; // not defined in any module (e.g. extern type)

        reachable_asn_names_.insert(name);
        // Walk ALL definitions for this name (collision types span multiple modules).
        for (const auto* def : it->second)
            collect_type_refs(*def, worklist);
    }

    // Report any PDU roots that could not be resolved.
    for (const auto& root : pdu_roots_)
        if (!reachable_asn_names_.count(root))
            std::cerr << "warning: -pdu type '" << root << "' not found in input\n";
}

} // namespace asn1::codegen
