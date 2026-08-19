#include "Generator.hpp"
#include "CppBackend.hpp"
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <limits>
#include <sstream>
#include "asn1cpp/Tag.hpp"
#include "asn1cpp/TypeDescriptor.hpp"
#include "asn1cpp/codec/Constraints.hpp"

namespace asn1::codegen {

Generator::Generator(fs::path out_dir, sema::Resolver& res)
    : out_dir_(std::move(out_dir)), resolver_(res),
      owned_backend_(std::make_unique<CppBackend>()), backend_(*owned_backend_) {}

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

std::string Generator::native_member_type_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Integer:
            return backend_.native_int_type(classify_integer_storage(def));
        case BT::Enumerated: {
            auto n = capitalize_first(backend_.type_name(def.name.empty() ? "Enum" : def.name));
            // Inline ENUMERATED member (has enum values, not top-level)
            if (!current_type_.empty() && !def.enum_values.empty())
                return current_type_ + n;
            return n;
        }
        default:
            return backend_.native_builtin_type(*bt);
        }
    }
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body))
        return cpp_name_for_typeref(*tr);
    if (def.is_seq_of()) {
        const auto& sof = std::get<ast::SequenceOfType>(def.body);
        const auto& elem = *sof.element;
        if (!def.name.empty() && (elem.is_sequence() || elem.is_choice() || elem.is_set()) && elem.name.empty())
            return backend_.wrap_collection_type(
                               backend_.synthetic_name(backend_.synthetic_name(current_type_, def.name), "Anon"));
        return backend_.wrap_collection_type(native_member_type_for(elem));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        const auto& elem = *sof.element;
        if (!def.name.empty() && (elem.is_sequence() || elem.is_choice() || elem.is_set()) && elem.name.empty())
            return backend_.wrap_collection_type(
                               backend_.synthetic_name(backend_.synthetic_name(current_type_, def.name), "Anon"));
        return backend_.wrap_collection_type(native_member_type_for(elem));
    }
    if (def.is_sequence() || def.is_choice() || def.is_set())
        return backend_.synthetic_name(current_type_, def.name.empty() ? "Anon" : def.name);
    return backend_.native_builtin_type(BT::OctetString);
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

// X.680 §30.6/§30.7 forces EXPLICIT only for an *untagged* CHOICE/ANY — one
// with no tag of its own to substitute onto. A member/alternative whose type
// is a plain reference to an *already-tagged* CHOICE (`c RecChoice` where
// `RecChoice ::= [0] CHOICE {...}`) is a TaggedType (X.680 §31.2), not a bare
// CHOICE, for tagging purposes: IMPLICIT applies normally, substituting for
// the referenced type's own declared tag exactly like any other
// already-tagged reference. An inline CHOICE body (m.is_choice() directly,
// not a TypeRef) can never carry its own `[n]` — only a member/alternative
// wrapping it can — so it's always the untagged case.
bool Generator::member_type_is_untagged_choice(const ast::TypeDef& m) const {
    if (m.is_choice()) return true;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto res = resolver_.resolve_ref(*tr, current_module_);
        if (res) return res->is_choice() && !res->tag.present();
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
    // Exception: an *untagged* CHOICE or ANY cannot be IMPLICIT tagged
    // (X.680 §30.6/30.7 — no tag of its own to substitute onto); tagging
    // must be EXPLICIT even in an IMPLICIT TAGS module. A CHOICE that
    // already carries its own declared [n] is a TaggedType, not a bare
    // CHOICE, for this purpose (member_type_is_untagged_choice's own doc).
    return member_type_is_untagged_choice(member_type) || member_type_is_any(member_type);
}

/// @brief Decide whether a member carries an explicit BER tag override and,
///        if so, what class/number/encoding-form applies.
/// @param tag         The member's (possibly absent) tag override.
/// @param constructed True if the encoding form is constructed, not primitive.
/// @return The tag decision as plain data, or nullopt if `tag` is absent.
/// @note Backend-agnostic: no C++ syntax. Separated from format_tag_literal()
///       so a future non-C++ backend can consume the decision directly.
std::optional<TypeTagSpec> Generator::tag_spec_for(const ast::Tag& tag, bool constructed) const {
    if (!tag.present()) return std::nullopt;
    return TypeTagSpec{tag.cls, tag.number, constructed};
}

/// @brief Returns the backend's tag-literal syntax for a tag override, empty
///        string if absent (gambas-asn1#290: `backend_.format_tag_literal`,
///        not a hardcoded C++ free function).
/// @param tag         The member's (possibly absent) tag override.
/// @param constructed True if the encoding form is constructed, not primitive.
/// @return The backend's literal string, or "" if `tag` is absent.
std::string Generator::tag_literal(const ast::Tag& tag, bool constructed) const {
    auto spec = tag_spec_for(tag, constructed);
    if (!spec) return "";
    return backend_.format_tag_literal(*spec);
}

/// @brief Decide the natural (universal) BER tag for a member def's
///        underlying type — see Generator::natural_tag_spec_for in the header
///        for the full contract. Plain data, no C++ syntax.
std::optional<TypeTagSpec> Generator::natural_tag_spec_for(const ast::TypeDef& def) const {
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
            return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::OctetString, false};
        uint32_t n = sema::builtin_universal_tag(*bt);
        if (n) return TypeTagSpec{ast::TagClass::Universal, n, false};
    }
    if (def.is_sequence())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (def.is_choice())
        return std::nullopt;  // CHOICE has no universal tag
    if (def.is_seq_of())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set_of())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto base = resolver_.resolve_ref(*tr);
        if (base) return natural_tag_spec_for(*base);
    }
    return TypeTagSpec{ast::TagClass::Universal, 4, false};  // fallback: OCTET STRING
}

bool Generator::type_is_explicit(const ast::TypeDef& def) const {
    if (!def.tag.present()) return false;
    return member_is_explicit(def.tag, def);
}

std::optional<TypeTagSpec> Generator::underlying_natural_tag_spec_for(const ast::TypeDef& def) const {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        if (*bt == BT::Any)
            return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::OctetString, false};
        uint32_t n = sema::builtin_universal_tag(*bt);
        if (n) return TypeTagSpec{ast::TagClass::Universal, n, false};
    }
    if (def.is_sequence())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (def.is_choice())
        return std::nullopt;
    if (def.is_seq_of())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Sequence, true};
    if (def.is_set_of())
        return TypeTagSpec{ast::TagClass::Universal, asn1::UniversalTag::Set, true};
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto base = resolver_.resolve_ref(*tr);
        if (base) return underlying_natural_tag_spec_for(*base);
    }
    return TypeTagSpec{ast::TagClass::Universal, 4, false};  // fallback: OCTET STRING
}

/// @brief Returns the natural (universal) tag for a member def's underlying
///        type, in the active backend's literal syntax.
/// @param def Member or referenced type to compute the natural tag for.
/// @return The backend's literal string, or "" for CHOICE (no universal tag).
std::string Generator::natural_tag_for(const ast::TypeDef& def) const {
    auto spec = natural_tag_spec_for(def);
    if (!spec) return "";
    return backend_.format_tag_literal(*spec);
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
    bool is_explicit = false;
    std::optional<MemberTagSpec> resolved_tag;
    if (m.tag.present()) {
        is_explicit = member_is_explicit(m.tag, m);
        // EXPLICIT wrapper is always constructed (X.690 §8.14.3); IMPLICIT inherits.
        bool constructed = is_explicit || member_is_constructed(m);
        resolved_tag = MemberTagSpec{ TypeTagSpec{ m.tag.cls, m.tag.number, constructed },
                                      /*tag_is_override=*/true };
    } else if (apply_auto_tags) {
        // X.680 §22.5/§28.4: AUTOMATIC TAGGING assigns an IMPLICIT context
        // tag substituting for whatever tag the member would otherwise
        // carry — UNLESS the member's type is an *untagged* CHOICE (or
        // ANY), which has no tag to substitute onto, forcing EXPLICIT
        // instead (X.680 §30.6/30.7). A CHOICE that already carries its own
        // declared [n] is not "untagged" for this purpose — see
        // member_type_is_untagged_choice's own doc.
        bool untagged_choice = member_type_is_untagged_choice(m);
        ast::Tag auto_tag;
        auto_tag.cls    = ast::TagClass::Context;
        auto_tag.number = auto_tag_num;
        auto_tag.mode   = untagged_choice ? ast::TagMode::Explicit : ast::TagMode::Implicit;
        bool constructed = untagged_choice || member_is_constructed(m);
        is_explicit = untagged_choice;
        resolved_tag = MemberTagSpec{ TypeTagSpec{ auto_tag.cls, auto_tag.number, constructed },
                                      /*tag_is_override=*/true };
    } else {
        // gambas-asn1#347: structured natural tag, not a pre-rendered
        // string — absent (resolved_tag stays nullopt) only for the one
        // case a member's type has no tag at all (an untagged CHOICE —
        // X.680 §28, no universal tag). Each backend formats this itself
        // at the point of use.
        if (auto natural = natural_tag_spec_for(m))
            resolved_tag = MemberTagSpec{ *natural, /*tag_is_override=*/false };
        // If the tag came from a referenced type's outer context tag, propagate is_explicit.
        // e.g. s4 T4 where T4 ::= [53] CHOICE — CHOICE always forces EXPLICIT.
        if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
            auto base = resolver_.resolve_ref(*tr);
            if (base && base->tag.present())
                is_explicit = member_is_explicit(base->tag, *base);
        }
    }
    return { resolved_tag, is_explicit };
}

bool Generator::is_class_type(const ast::TypeDef& m) const {
    if (m.is_sequence() || m.is_choice() || m.is_set()) return true;
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
        return direct && (direct->is_sequence() || direct->is_choice() || direct->is_set());
    }
    return false;
}

// gambas-asn1#303: is `target` (an ASN.1 type name) reachable from `from`
// by following further class-typed member references? DFS over the
// resolved-type graph, bounded by `visited` (finite — one entry per
// distinct named class type actually reachable, plus one per anonymous
// inline member visited along the way).
bool Generator::type_reaches(const ast::TypeDef& from, const std::string& target,
                              std::set<std::string>& visited) const {
    for (const auto& m : from.members) {
        if (!m || m->is_extension_marker) continue;
        const ast::TypeDef* member_def = nullptr;
        std::string member_key;
        if (m->is_sequence() || m->is_choice() || m->is_set()) {
            // Anonymous inline class-typed member — no independent ASN.1
            // name to compare against `target`, but still needs a unique
            // `visited` key so a cycle purely among anonymous members
            // terminates.
            member_def = m.get();
            member_key = std::format("$anon:{}", static_cast<const void*>(m.get()));
        } else if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
            auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
            if (direct && (direct->is_sequence() || direct->is_choice() || direct->is_set())) {
                member_def = direct.get();
                member_key = tr->type_name;
            }
        }
        if (!member_def) continue;
        if (member_key == target) return true;
        if (!visited.insert(member_key).second) continue; // already visited, not a new cycle path
        if (type_reaches(*member_def, target, visited)) return true;
    }
    return false;
}

// gambas-asn1#303: does member `m`'s class type eventually reference
// `enclosing_name` again (a real ASN.1 type-reference cycle)? Only
// meaningful when `m` is itself class-typed (caller should check
// is_class_type(m) first, or accept the always-false short-circuit below).
bool Generator::member_type_in_cycle(const ast::TypeDef& m, const std::string& enclosing_name) const {
    const ast::TypeDef* member_def = nullptr;
    if (m.is_sequence() || m.is_choice() || m.is_set()) {
        member_def = &m;
    } else if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto direct = resolver_.lookup_direct(tr->type_name, current_module_);
        if (direct && (direct->is_sequence() || direct->is_choice() || direct->is_set()))
            member_def = direct.get();
    }
    if (!member_def) return false;
    std::set<std::string> visited;
    return type_reaches(*member_def, enclosing_name, visited);
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
// type_descriptor_ref_spec_for / type_descriptor_ref_for — Generator members
// (collision-aware)
// ---------------------------------------------------------------------------

/// @brief Decide which reference form a type-descriptor reference takes
///        (see TypeDescriptorRefSpec) — plain data, no C++ syntax. Needs
///        Generator-private resolver/collision state (resolver_,
///        collision_types_, effective_cpp_name/cpp_name_for_ref/
///        cpp_name_for_typeref), so stays a Generator method; the caller
///        (type_descriptor_ref_for, below) renders it via
///        backend_.format_type_descriptor_ref.
/// @see TypeDescriptorRefSpec (Backend.hpp) for the field-by-field contract.
TypeDescriptorRefSpec Generator::type_descriptor_ref_spec_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        if (*bt != BT::Enumerated)  // Enumerated handled below — inline ENUMERATED needs synthetic name
            return TypeDescriptorRefSpec{TypeDescriptorRefKind::Builtin, *bt, {}};
    }
    // Inline ENUMERATED member — use synthetic name (generates a class)
    if (auto* bt2 = std::get_if<BT>(&def.body);
        bt2 && *bt2 == BT::Enumerated && !def.enum_values.empty() && !current_type_.empty()) {
        auto sname = backend_.synthetic_name(current_type_, def.name.empty() ? "Enum" : def.name);
        return TypeDescriptorRefSpec{TypeDescriptorRefKind::ClassScoped, {}, sname};
    }
    // Named type reference.
    // Pure TypeRef aliases (e.g. "LawfulInterceptionIdentifier ::= LIID") generate only a
    // C++ `using` declaration — no asn_DEF_. Follow the chain until reaching a type that
    // generates its own descriptor (BuiltinType with constraints, SEQUENCE, CHOICE, etc.).
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        // For collision types, resolve_ref uses global_ and may pick the wrong module's version.
        // Prefer the current-module's definition (local shadows global), fall back to resolve_ref.
        // Skip this logic for qualified references (module_name set) — they pin the source module.
        if (tr->module_name.empty() && collision_types_.count(backend_.type_name(tr->type_name))) {
            std::string def_mod = resolver_.module_of(tr->type_name, current_module_);
            if (!def_mod.empty()) {
                auto td = resolver_.resolve_in_module(tr->type_name, def_mod);
                if (td && std::get_if<ast::TypeRef>(&td->body))
                    return type_descriptor_ref_spec_for(*td);  // pure alias — follow chain
                if (td) {
                    auto n = effective_cpp_name(tr->type_name, def_mod);
                    if (td->is_sequence() || td->is_set() || td->is_choice() ||
                        (std::get_if<BT>(&td->body) && std::get<BT>(td->body) == BT::Enumerated))
                        return TypeDescriptorRefSpec{TypeDescriptorRefKind::ClassScoped, {}, n};
                    return TypeDescriptorRefSpec{TypeDescriptorRefKind::FreeStanding, {}, n};
                }
            }
        }
        auto resolved = resolver_.resolve_ref(*tr);
        if (resolved && !resolved->name.empty()) {
            if (std::get_if<ast::TypeRef>(&resolved->body))
                return type_descriptor_ref_spec_for(*resolved);  // pure alias — follow chain
            bool is_class = resolved->is_sequence() || resolved->is_set() || resolved->is_choice() ||
                (std::get_if<BT>(&resolved->body) && std::get<BT>(resolved->body) == BT::Enumerated);
            auto kind = is_class ? TypeDescriptorRefKind::ClassScoped : TypeDescriptorRefKind::FreeStanding;
            // Qualified ref: use explicit module for collision disambiguation on resolved name.
            if (!tr->module_name.empty() && collision_types_.count(backend_.type_name(resolved->name))) {
                auto n = effective_cpp_name(resolved->name, tr->module_name);
                return TypeDescriptorRefSpec{kind, {}, n};
            }
            auto n = cpp_name_for_ref(resolved->name, current_module_);
            return TypeDescriptorRefSpec{kind, {}, n};
        }
        // Fallback: unresolved ref — synthetic types (compiler-generated
        // element replacements) are SEQUENCE/CHOICE/ENUM → class-scoped
        // static member, except a promoted anonymous nested SEQUENCE OF/SET
        // OF (seq_of_synthetic_names_, gambas-asn1#427), which — like any
        // other SEQUENCE OF/SET OF — gets a free asn_DEF_X, not X::asn_DEF.
        auto n = cpp_name_for_typeref(*tr);
        auto kind = seq_of_synthetic_names_.count(n) ? TypeDescriptorRefKind::FreeStanding
                                                       : TypeDescriptorRefKind::ClassScoped;
        return TypeDescriptorRefSpec{kind, {}, n};
    }
    // SEQUENCE OF / SET OF — named member uses synthetic SeqOf wrapper descriptor (using alias)
    if (def.is_seq_of()) {
        if (!def.name.empty())
            return TypeDescriptorRefSpec{TypeDescriptorRefKind::FreeStanding, {},
                                          backend_.synthetic_name(current_type_, def.name)};
        const auto& elem = std::get<ast::SequenceOfType>(def.body).element;
        return type_descriptor_ref_spec_for(*elem);
    }
    if (def.is_set_of()) {
        if (!def.name.empty())
            return TypeDescriptorRefSpec{TypeDescriptorRefKind::FreeStanding, {},
                                          backend_.synthetic_name(current_type_, def.name)};
        const auto& elem = std::get<ast::SetOfType>(def.body).element;
        return type_descriptor_ref_spec_for(*elem);
    }
    // Inline SEQUENCE / CHOICE / SET member — synthetic name, generates a class
    if (def.is_sequence() || def.is_choice() || def.is_set()) {
        auto sname = backend_.synthetic_name(current_type_, def.name.empty() ? "Anon" : def.name);
        return TypeDescriptorRefSpec{TypeDescriptorRefKind::ClassScoped, {}, sname};
    }
    return TypeDescriptorRefSpec{};  // kind == None
}

/// @brief Returns the backend's reference-expression syntax for `def`'s
///        type-descriptor reference (gambas-asn1#478:
///        `backend_.format_type_descriptor_ref`, not hardcoded C++ text —
///        same split as tag_literal()/format_tag_literal()).
std::string Generator::type_descriptor_ref_for(const ast::TypeDef& def) {
    return backend_.format_type_descriptor_ref(type_descriptor_ref_spec_for(def));
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
// Emit ENUMERATED
// ---------------------------------------------------------------------------

/// @brief Decide the resolved value list for an ENUMERATED type — automatic
///        numbering (X.680 §20.6) applied, root and extension values in one
///        continuous sequence. Backend-agnostic: shared by both
///        emit_enumerated_declaration and emit_enumerated_definition (previously each
///        recomputed this — now computed once).
static EnumeratedSpec build_enumerated_spec(const ast::TypeDef& def,
                                            const std::string& type_name) {
    EnumeratedSpec spec;
    spec.type_name = type_name;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    spec.extensible = false;
    spec.root_count  = 0;

    long auto_val = 0;
    bool past_ext = false;
    for (const auto& ev : def.enum_values) {
        if (ev.name == "...") { spec.extensible = true; past_ext = true; continue; }
        long v = static_cast<long>(ev.number.value_or(auto_val));
        spec.values.push_back({ev.name, v});
        auto_val = v + 1;
        if (!past_ext) ++spec.root_count;
    }
    return spec;
}

void Generator::emit_enumerated(const ast::TypeDef& def, TypeOutputSession& session) {
    auto spec = build_enumerated_spec(def, effective_cpp_name(def.name, current_module_));
    spec.tag = natural_tag_spec_for(def);
    spec.is_explicit = type_is_explicit(def);
    if (spec.is_explicit) spec.natural_tag = underlying_natural_tag_spec_for(def);
    backend_.emit_enumerated(spec, session);
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

ElemShape Generator::build_elem_shape(const ast::TypeDef& elem) const {
    ElemShape shape;
    if (elem.is_seq_of()) {
        shape.kind = SeqOfKind::SeqOf;
        shape.nested = std::make_shared<ElemShape>(
            build_elem_shape(*std::get<ast::SequenceOfType>(elem.body).element));
        return shape;
    }
    if (elem.is_set_of()) {
        shape.kind = SeqOfKind::SetOf;
        shape.nested = std::make_shared<ElemShape>(
            build_elem_shape(*std::get<ast::SetOfType>(elem.body).element));
        return shape;
    }
    // Scalar leaf: a builtin (kind stays None, builtin set) or a composite
    // TypeRef/SEQUENCE/CHOICE/SET (kind stays None, builtin stays nullopt —
    // same "optional discriminant" convention SequenceMemberSpec::mbuiltin
    // uses one level up).
    if (auto* bt = std::get_if<ast::BuiltinType>(&elem.body)) {
        shape.builtin = *bt;
        if (*bt == ast::BuiltinType::Integer) shape.storage_kind = classify_integer_storage(elem);
    }
    return shape;
}

/// @brief True if any top-level constraint on `def` carries a trailing '...'.
/// @param def Type definition to inspect.
/// @return Whether `def` is constraint-extensible (X.680 §49.3).
/// @note Forward-declared here; defined later in this file. build_integer_spec
///       below needs it before its definition point.
static bool is_constraint_extensible(const ast::TypeDef& def);

IntegerSpec Generator::build_integer_spec(const ast::TypeDef& def, const std::string& type_name) const {
    IntegerSpec spec;
    spec.type_name = type_name;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    spec.storage_kind = classify_integer_storage(def);
    spec.tag = natural_tag_spec_for(def);
    spec.is_explicit = type_is_explicit(def);
    if (spec.is_explicit) spec.natural_tag = underlying_natural_tag_spec_for(def);
    for (const auto& ev : def.enum_values)
        spec.named_values.push_back({ev.name, ev.number.value_or(0)});

    auto r = extract_integer_range(def);
    spec.has_constraint = r.has_value;
    if (!r.has_value) return spec;

    int64_t lo = r.lo, hi = r.hi;
    spec.extensible = is_constraint_extensible(def);
    spec.semi_constrained = r.truly_max;
    spec.hi_is_large = r.hi_is_large;
    spec.lower_s64 = lo;

    if (r.truly_max) {
        // Truly semi-constrained (..MAX keyword): no upper cap.
        spec.range_bits = -1;
        spec.upper_s64 = 0;
        spec.lower_u64 = static_cast<uint64_t>(lo >= 0 ? lo : 0);
        spec.upper_u64 = std::numeric_limits<uint64_t>::max();
    } else if (r.hi_is_large) {
        // TOK_number_large upper bound (e.g. UINT64_MAX).
        // X.691 §10.5.6 UPER: range = hi_u64 - lo + 1; compute range_bits.
        // For the full uint64 range (lo=0, hi=UINT64_MAX), range_bits=64.
        int rb = 0;
        uint64_t u_lo = static_cast<uint64_t>(lo >= 0 ? lo : 0);
        uint64_t range_count_m1 = r.hi_u64 - u_lo; // range - 1 (exact even if range=2^64)
        if (range_count_m1 == std::numeric_limits<uint64_t>::max()) {
            rb = 64; // 2^64 range
        } else {
            for (uint64_t v = range_count_m1; v > 0; v >>= 1) ++rb;
        }
        spec.range_bits = rb;
        spec.upper_s64 = hi; // int64_t view
        spec.lower_u64 = u_lo;
        spec.upper_u64 = r.hi_u64;
    } else {
        int64_t range_count = hi - lo + 1;
        int rb = 0;
        if (range_count > 1)
            for (int64_t v = range_count - 1; v > 0; v >>= 1) ++rb;
        spec.range_bits = rb;
        spec.upper_s64 = hi;
        spec.lower_u64 = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
        spec.upper_u64 = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
    }
    return spec;
}

void Generator::emit_integer(const ast::TypeDef& def, TypeOutputSession& session) {
    auto spec = build_integer_spec(def, effective_cpp_name(def.name, current_module_));
    backend_.emit_integer(spec, session);
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

/// @brief Decide which DEFAULT value (X.680 §25.1) applies to a member, if any.
/// @param m Member to inspect.
/// @return The decision as plain data — see header for the `Kind::None` cases.
DefaultValueSpec Generator::default_value_spec_for(const ast::TypeDef& m) const {
    if (m.marker != ast::Marker::Default) return {};
    if (std::holds_alternative<std::monostate>(m.default_value)) return {};

    if (auto* b = std::get_if<bool>(&m.default_value))
        return { DefaultValueSpec::Kind::Bool, *b, 0, "", "" };
    if (auto* i = std::get_if<int64_t>(&m.default_value))
        return { DefaultValueSpec::Kind::Int, false, *i, "", "" };
    if (auto* s = std::get_if<std::string>(&m.default_value))
        return { DefaultValueSpec::Kind::String, false, 0, *s, "" };
    if (auto* nr = std::get_if<ast::NamedValueRef>(&m.default_value)) {
        // ENUMERATED named ref → EnumType::name; unsupported for other bases.
        const ast::TypeDef* base = resolve_underlying(m, resolver_);
        bool is_enum = base
            && std::holds_alternative<ast::BuiltinType>(base->body)
            && std::get<ast::BuiltinType>(base->body) == ast::BuiltinType::Enumerated;
        if (!is_enum) return {};
        return { DefaultValueSpec::Kind::EnumRef, false, 0, "", nr->name };
    }
    return {};
}

/// @brief Emit the DEFAULT-value setter/checker pair for a member, delegating
///        text emission to the backend.
/// @param m            Member carrying a DEFAULT value (see default_value_spec_for).
/// @param parent_cname C++ name of the enclosing SEQUENCE/SET type.
/// @param mname        Sanitised C++ member name.
/// @param os           Output stream for the generated `.cpp` file.
/// @return "&_setdef_<parent>_<member>", or "nullptr" if `m` has no DEFAULT.
std::string Generator::emit_default_setter(
    const ast::TypeDef& m, const std::string& parent_cname,
    const std::string& mname, TypeOutputSession& session)
{
    auto spec = default_value_spec_for(m);
    if (spec.kind == DefaultValueSpec::Kind::None) return "nullptr";

    std::string mtype = native_member_type_for(m);
    backend_.emit_default_setter(spec, mtype, parent_cname, mname, session);
    return std::format("&_setdef_{}_{}", parent_cname, mname);
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

// ---------------------------------------------------------------------------
// Inline-constrained member TypeDescriptor helpers
// ---------------------------------------------------------------------------

/// @brief Emit the static per-member TypeDescriptor when the member carries
///        inline constraints, delegating the decision to
///        build_member_type_descriptor_spec() and text emission to the backend.
/// @param m             Member type definition (may carry value-range, SIZE, or FROM constraints).
/// @param parent_cname  C++ name of the enclosing SEQUENCE/CHOICE type.
/// @param mname         Sanitised C++ member name used as the descriptor variable suffix.
/// @param os            Output stream to write the generated descriptor to.
/// @return A reference expression to the descriptor (e.g. `"&asn_TYP_Foo_bar"`).
/// @see X.691 §26.5 (character string constraints), §18.5 (SEQUENCE preamble bitmap).
std::string Generator::emit_member_type_descriptor(
    const ast::TypeDef& m, const std::string& parent_cname,
    const std::string& mname, TypeOutputSession& session)
{
    auto spec = build_member_type_descriptor_spec(m, parent_cname, mname);
    if (!spec) return type_descriptor_ref_for(m);
    backend_.emit_member_type_descriptor(*spec, session);
    return "&" + spec->tname;
}

/// @brief Decide the resolved MemberTypeDescriptorSpec for an inline-
///        constrained SEQUENCE/CHOICE member — INTEGER value range or
///        SIZE-able-primitive (string family, OctetString, BitString)
///        constraints.
/// @param m             Member type definition (may carry value-range, SIZE, or FROM constraints).
/// @param parent_cname  C++ name of the enclosing SEQUENCE/CHOICE type.
/// @param mname         Sanitised C++ member name used as the descriptor variable suffix.
/// @return nullopt when the member has no inline constraint worth a dedicated
///         descriptor — caller falls back to type_descriptor_ref_for().
/// @see X.691 §26.5 (character string constraints), §18.5 (SEQUENCE preamble bitmap).
std::optional<MemberTypeDescriptorSpec> Generator::build_member_type_descriptor_spec(
    const ast::TypeDef& m, const std::string& parent_cname, const std::string& mname)
{
    using BT = ast::BuiltinType;
    auto* bt = std::get_if<BT>(&m.body);
    bool needs_xer = m.xer_encoding != ast::XerEncoding::Default;
    if (!bt || (m.constraints.empty() && !needs_xer)) return std::nullopt;

    // INTEGER value range
    if (*bt == BT::Integer) {
        auto ir = extract_integer_range(m);
        if (ir.has_value) {
            MemberTypeDescriptorSpec spec;
            spec.kind = MemberTypeDescriptorSpec::Kind::Integer;
            spec.tname = std::format("asn_TYP_{}_{}", parent_cname, mname);
            int64_t lo = ir.lo, hi = ir.hi;
            spec.extensible = is_constraint_extensible(m);
            spec.storage_kind = classify_integer_storage(m);
            spec.semi_constrained = ir.truly_max;
            spec.hi_is_large = ir.hi_is_large;
            spec.lower_s64 = lo;
            if (ir.truly_max) {
                // Truly semi-constrained (..MAX): no upper cap.
                spec.range_bits = -1;
                spec.upper_s64 = 0;
                spec.lower_u64 = static_cast<uint64_t>(lo >= 0 ? lo : 0);
                spec.upper_u64 = std::numeric_limits<uint64_t>::max();
            } else if (ir.hi_is_large) {
                // TOK_number_large upper bound (e.g. UINT64_MAX).
                uint64_t u_lo = static_cast<uint64_t>(lo >= 0 ? lo : 0);
                uint64_t range_count_m1 = ir.hi_u64 - u_lo;
                int rb = (range_count_m1 == std::numeric_limits<uint64_t>::max())
                    ? 64 : 0;
                if (rb == 0) for (uint64_t v = range_count_m1; v > 0; v >>= 1) ++rb;
                spec.range_bits = rb;
                spec.upper_s64 = hi;
                spec.lower_u64 = u_lo;
                spec.upper_u64 = ir.hi_u64;
            } else {
                int64_t rc = hi - lo + 1;
                int rb = 0;
                if (rc > 1) for (int64_t v = rc - 1; v > 0; v >>= 1) ++rb;
                spec.range_bits = rb;
                spec.upper_s64 = hi;
                spec.lower_u64 = (lo >= 0) ? static_cast<uint64_t>(lo) : 0;
                spec.upper_u64 = (hi >= 0) ? static_cast<uint64_t>(hi) : 0;
            }
            spec.xer_type_name = "INTEGER";
            spec.universal_tag = asn1::UniversalTag::Integer;
            return spec;
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
            MemberTypeDescriptorSpec spec;
            spec.kind = MemberTypeDescriptorSpec::Kind::Sizeable;
            spec.builtin_type = *bt;
            // Compute SIZE constraint fields. size_range_bits/size_lower/
            // size_upper default to 0 (not left indeterminate) even when
            // `!sr` (FROM-alphabet-only or custom-XER-only member, no
            // SIZE at all) — both backends format these fields into their
            // generated Constraints tables unconditionally (gated on
            // `has_size_constraint`/a flags bit at read time, not at
            // codegen time), so leaving them uninitialized here was a
            // real, previously undetected UB/garbage-value bug (only
            // surfaced by gambas-asn1#466 adding a FROM-alphabet-only
            // inline member schema — no existing schema exercised this
            // combination before).
            spec.has_size_constraint = sr.has_value();
            spec.size_bounded = sr.has_value()
                && sr->second != std::numeric_limits<int64_t>::max();
            spec.size_range_bits = 0;
            spec.size_lower = 0;
            spec.size_upper = 0;
            if (sr) {
                auto sc = compute_size_constraint(sr, is_constraint_extensible(m));
                spec.size_range_bits = sc.range_bits;
                spec.size_lower = sc.lower; spec.size_upper = sc.upper;
            }
            spec.extensible = is_constraint_extensible(m);
            // FROM("A".."Z",...) has the extension marker inside the FromConstraint;
            // is_constraint_extensible only checks the outer Constraint::extensible.
            if (!spec.extensible && !alphabet.empty()) {
                walk_type_constraints(m, [&](const ast::ConstraintBody& body) {
                    auto* fc = std::get_if<ast::FromConstraint>(&body);
                    if (fc && fc->inner && fc->inner->extensible) spec.extensible = true;
                });
            }
            if (!alphabet.empty()) {
                spec.alpha_prefix = std::format("asn_FROM_{}_{}", parent_cname, mname);
                spec.alphabet = alphabet;
            }
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
            spec.tname = std::format("asn_TYP_{}_{}", parent_cname, mname);
            spec.xer_type_name = tn;
            spec.universal_tag = *utag;
            spec.xer_encoding = m.xer_encoding;
            return spec;
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// classify_member_setter — determines param type + validate strategy for
// set_<member> helpers, TypeRef-alias members only. Returns empty
// param_type for members that should not get a setter (optional, complex,
// non-primitive types, or an unresolvable/non-builtin-resolving TypeRef).
//
// gambas-asn1#419: the direct-builtin case (this function's own former
// `if (bt) {...}` branch) used to live here as one more piece of
// pre-formatted C++ text riding along on a field RustBackend never reads —
// dead computation on every Rust compile, not just dead storage. It's
// fully self-computable by CppBackend alone from fields already on
// SequenceMemberSpec (`mbuiltin`/`storage_kind`), the same "no Generator-
// private state needed" reasoning `ops`/`offset_expr` were already moved
// for — see CppBackend.cpp's own `classify_builtin_setter`. Only the
// TypeRef-alias case stays here: it needs `resolver_.resolve_ref`, which
// is Generator-private by design (CppBackend has no access, deliberately —
// see this issue's own "known blocker" note).
// ---------------------------------------------------------------------------
Generator::MemberSetterInfo
Generator::classify_member_setter(const ast::TypeDef& m) {
    using BT = ast::BuiltinType;
    if (m.is_sequence() || m.is_set() || m.is_choice() || m.is_seq_of() || m.is_set_of())
        return {};
    if (auto* tr = std::get_if<ast::TypeRef>(&m.body)) {
        auto resolved = resolver_.resolve_ref(*tr);
        if (!resolved) return {};
        auto* rbt = std::get_if<BT>(&resolved->body);
        if (!rbt) return {};
        std::string ct = native_member_type_for(m);
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
std::vector<std::string> Generator::emit_sequence_declaration(const ast::TypeDef& def, std::ostream& os) {
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
        write_type_reference(cn, inc_os);
    };
    auto emit_fwd = [&](const std::string& cn) {
        write_forward_declaration(cn, os);
    };
    // gambas-asn1#312: named SEQUENCE OF/SET OF member's own synthetic
    // wrapper reference — the field's own type text never names the bare
    // wrapper either way (element type directly, or the doubly-suffixed
    // "Anon" type), so whether this reference is needed at all is purely a
    // per-backend fact (CppBackend's tdref points at the wrapper's own
    // asn_DEF_<synth>; RustBackend has no such table wiring yet — see
    // Backend::needs_seqof_wrapper_reference's doc comment).
    auto emit_wrapper_inc = [&](const std::string& cn) {
        if (backend_.needs_seqof_wrapper_reference()) emit_inc(cn);
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
                auto* tr_elem = std::get_if<ast::TypeRef>(&seqof_elem->body);
                bool self_ref = tr_elem &&
                    (backend_.type_name(tr_elem->type_name) == backend_.type_name(def.name));
                auto synth = backend_.synthetic_name(cname, m.name);
                if (self_ref) {
                    post_class_includes.push_back(synth); // defer: needs current class complete
                } else {
                    emit_wrapper_inc(synth);
                    // gambas-asn1#301: native_member_type_for's SEQUENCE OF branch uses
                    // the element type directly (wrap_collection_type(native_member_type_for(elem)))
                    // when the element is a plain TypeRef — it only falls
                    // back to the synthetic name above for an *anonymous*
                    // inline element. CppBackend gets away with including
                    // only the synthetic wrapper header because that header
                    // itself #includes the element's header, and #include is
                    // transitive; Rust's `use` only brings the one named
                    // symbol into scope, not whatever *that* module itself
                    // `use`d — so a field typed `Vec<CallId>` with no direct
                    // `use crate::CallId::CallId;` failed to compile
                    // (E0425), the second-largest error category on the real
                    // ETSI LI PS-PDU schema (#299/#301).
                    if (tr_elem) {
                        emit_inc(cpp_name_for_typeref(*tr_elem));
                    } else if (seqof_elem->is_sequence() || seqof_elem->is_choice() || seqof_elem->is_set()) {
                        // Anonymous inline element: native_member_type_for's SEQUENCE
                        // OF branch names the field type with a *second*,
                        // "Anon"-suffixed synthetic name layered on top of
                        // `synth` (synthetic_name(synth, "Anon")) — a real
                        // generated type distinct from `synth` itself
                        // (`synth` is just a `pub type X = Vec<...>;` alias
                        // in Rust). Same missing-import shape as the
                        // plain-TypeRef case above, different root name.
                        emit_inc(backend_.synthetic_name(synth, "Anon"));
                    }
                }
            } else {
                const auto& elem = m.is_seq_of()
                    ? std::get<ast::SequenceOfType>(m.body).element
                    : std::get<ast::SetOfType>(m.body).element;
                if (auto* tr2 = std::get_if<ast::TypeRef>(&elem->body)) {
                    emit_inc(cpp_name_for_typeref(*tr2));
                } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
                    emit_inc(backend_.synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name));
                }
            }
        } else if ((m.is_sequence() || m.is_choice() || m.is_set()) && !m.name.empty()) {
            auto synth = backend_.synthetic_name(cname, m.name);
            optional ? emit_fwd(synth) : emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m.body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m.enum_values.empty())
                emit_inc(backend_.synthetic_name(cname, m.name));
        }
    };
    for (auto* m : sm_root) emit_member_include(*m, m->is_optional());
    for (auto* m : sm_ext)  emit_member_include(*m, /*optional=*/true);
    if (mcount > 0) os << "\n";

    // Field storage (unique_ptr vs plain) and setter declarations — the rest
    // of SequenceSpec (tag, ops, descriptor refs, ...) is only computed in
    // emit_sequence_definition's pass; that pass's member rows are a strict
    // superset of what this declaration side needs (same mtype/mname/
    // optional/setter_* computation), so emit_sequence (the combined
    // wrapper) uses emit_sequence_definition's spec for both halves instead
    // of building a second, redundant one here.
    //
    // Self-referential SeqOf includes are deferred until the class is
    // complete — returned so emit_sequence can emit them after the combined
    // backend_.emit_sequence() call (post_ns_os_ routes them after
    // `} // namespace` in namespace mode).
    return post_class_includes;
}

/// @brief Emit the .cpp-side definitions for a generated SEQUENCE type.
/// @param def  The SEQUENCE TypeDef from the AST.
/// @param os   Output stream for the generated .cpp source file.
/// @see X.680 §24 — SEQUENCE type.
SequenceSpec Generator::emit_sequence_definition(const ast::TypeDef& def, TypeOutputSession& session) {
    std::ostream& os = session.buffer(backend_.definition_extension());
    std::string cname = effective_cpp_name(def.name, current_module_);
    bool is_set = def.is_set();

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
                    // Self-referential member (e.g. `next Node OPTIONAL` inside
                    // Node itself): the enclosing type's own definition file
                    // already has full visibility of itself, so re-including/
                    // re-`use`ing it here is at best redundant (harmless under
                    // C++'s #pragma once) and at worst a self-import (Rust:
                    // declaration+definition share one file, unlike C++'s
                    // .hpp/.cpp split — E0255, gambas-asn1#320).
                    if (cn != cname) {
                        auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
                        write_type_reference(cn, inc_os);
                        emitted_extra = true;
                    }
                }
            } else if ((m.is_sequence() || m.is_choice() || m.is_set()) && !m.name.empty()) {
                auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
                auto synth = backend_.synthetic_name(cname, m.name);
                write_type_reference(synth, inc_os);
                emitted_extra = true;
            }
        };
        for (auto* m : sm_root) { if (m->is_optional()) emit_opt_include(*m); }
        for (auto* m : sm_ext)  emit_opt_include(*m);
        if (emitted_extra) { auto& nl_os = pre_ns_os_ ? *pre_ns_os_ : os; nl_os << "\n"; }

        // All special members defined here where unique_ptr<T> has complete T.
        // Must be written before Ops aliases / member table below (original
        // ordering) — pure text, no per-member decision content.
        backend_.emit_special_members(cname, session);
    }

    // Count root-only optional members (for PER preamble bitmap width).
    // Extension members are NOT counted — they have their own extension bitmap.
    int roms_count = static_cast<int>(
        std::count_if(sm_root.begin(), sm_root.end(),
                      [](const ast::TypeDef* m){ return m->is_optional(); }));

    // Determine if AUTOMATIC TAGS applies: module is AUTOMATIC TAGS and none of the
    // ComponentTypes in any ComponentTypeList has an explicit tag (X.680 §24.8).
    bool apply_auto_tags = should_apply_auto_tags(def);

    SequenceSpec spec;
    spec.type_name = cname;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    spec.has_optional_members = has_optional_members;
    spec.mcount = mcount;
    spec.ext_at = ext_at;
    spec.roms_count = roms_count;
    spec.is_set = is_set;
    spec.tag = natural_tag_spec_for(def);
    spec.is_explicit = type_is_explicit(def);
    if (spec.is_explicit) spec.natural_tag = underlying_natural_tag_spec_for(def);

    // Storage-ops helper for optional member callbacks — one per optional
    // member. Must be written before the collect() pass below:
    // emit_default_setter's generated static functions reference these
    // types directly by name.
    for (auto* m : sm_root) {
        if (!m->is_optional()) continue;
        backend_.emit_optional_member_ops(cname, backend_.member_name(m->name), native_member_type_for(*m), session);
    }
    for (auto* m : sm_ext) {
        backend_.emit_optional_member_ops(cname, backend_.member_name(m->name), native_member_type_for(*m), session);
    }
    os << "\n";

    // Collect per-row data; emits any static per-member TypeDescriptors/
    // default-setter pairs as a side effect (before the member table, which
    // references them — can't have declarations inside an initializer list).
    // atag continues across root→ext so auto-tagging numbers extensions
    // after root members.
    int atag = 0;
    auto collect = [&](const ast::TypeDef& m, bool optional) {
        SequenceMemberSpec row;
        row.asn1_name = m.name;
        row.mname = backend_.member_name(m.name);
        row.mtype = native_member_type_for(m);
        if (auto* bt = std::get_if<ast::BuiltinType>(&m.body)) {
            row.mbuiltin = *bt;
            // gambas-asn1#350: same decision native_member_type_for's own Integer
            // branch already made to produce row.mtype above — threaded
            // through as structured data too, not re-derived from mtype text.
            if (*bt == ast::BuiltinType::Integer) row.storage_kind = classify_integer_storage(m);
        }
        if (m.is_seq_of()) {
            row.seq_of_kind = SeqOfKind::SeqOf;
            row.elem_shape = build_elem_shape(*std::get<ast::SequenceOfType>(m.body).element);
        } else if (m.is_set_of()) {
            row.seq_of_kind = SeqOfKind::SetOf;
            row.elem_shape = build_elem_shape(*std::get<ast::SetOfType>(m.body).element);
        }
        if (is_class_type(m))
            row.member_type_in_cycle = member_type_in_cycle(m, def.name);
        row.optional = optional;
        auto tag_result = compute_member_tag(m, apply_auto_tags, atag);
        row.is_explicit = tag_result.is_explicit;
        row.resolved_tag = tag_result.resolved_tag;
        row.tdref = emit_member_type_descriptor(m, cname, row.mname, session);
        row.def_setter = emit_default_setter(m, cname, row.mname, session);
        row.has_default = (m.marker == ast::Marker::Default);
        if (!optional) {
            auto si = classify_member_setter(m);
            row.setter_param_type = si.param_type;
            row.setter_is_move = si.is_move;
            row.setter_is_int_alias = si.is_int_alias;
            row.setter_is_uint_alias = si.is_uint_alias;
        }
        spec.members.push_back(std::move(row));
        ++atag;
    };
    if (mcount > 0) {
        for (auto* m : sm_root) collect(*m, m->is_optional());
        for (auto* m : sm_ext)  collect(*m, /*optional=*/true);
    }

    return spec;
}

/// @brief Emit a SEQUENCE/SET type's declaration+definition.
/// @param def     SEQUENCE/SET TypeDef.
/// @param session Per-type output session.
void Generator::emit_sequence(const ast::TypeDef& def, TypeOutputSession& session) {
    std::ostream& decl_os = session.buffer(backend_.declaration_extension());
    auto post_class_includes = emit_sequence_declaration(def, decl_os);
    auto spec = emit_sequence_definition(def, session);
    backend_.emit_sequence(spec, session);

    // Self-referential SeqOf includes: deferred until class is complete.
    // post_ns_os_ routes them after `} // namespace` in namespace mode.
    if (!post_class_includes.empty()) {
        auto& inc_os = post_ns_os_ ? *post_ns_os_ : decl_os;
        for (const auto& sinc : post_class_includes) {
            write_type_reference(sinc, inc_os);
        }
        inc_os << "\n";
    }
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
std::vector<ChoiceAlternativeSpec> Generator::emit_choice_declaration(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto [count, ext_at] = count_members(def);

    // #include referenced alternative types and inline-type headers
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        auto emit_inc = [&](const std::string& cn) {
            // Self-referential alternative (e.g. `c RecChoice` inside
            // RecChoice itself, X.680 §28 permits this): the enclosing
            // type's own definition file already has full visibility of
            // itself, so re-including/re-`use`ing it here is at best
            // redundant (harmless under C++'s #pragma once) and at worst a
            // self-import (Rust: declaration+definition share one file,
            // unlike C++'s .hpp/.cpp split — E0255). Same fix
            // emit_sequence_definition's emit_opt_include already has.
            if (cn == cname) return;
            auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
            write_type_reference(cn, inc_os);
        };
        // gambas-asn1#312: same wrapper-reference decision as
        // emit_sequence_declaration's emit_wrapper_inc (see
        // Backend::needs_seqof_wrapper_reference's doc comment).
        auto emit_wrapper_inc = [&](const std::string& cn) {
            if (backend_.needs_seqof_wrapper_reference()) emit_inc(cn);
        };
        if (auto* tr = std::get_if<ast::TypeRef>(&m->body)) {
            emit_inc(cpp_name_for_typeref(*tr));
        } else if ((m->is_seq_of() || m->is_set_of()) && !m->name.empty()) {
            // Named SEQUENCE OF alternative — include the synthetic SeqOf wrapper header
            auto cn2 = cpp_name_for_ref(backend_.synthetic_name(cname, m->name), current_module_);
            emit_wrapper_inc(cn2);
            // gambas-asn1#301: also include the actual element type directly
            // when it's a plain TypeRef — see the matching fix (and its
            // rationale) in Generator::emit_type_files's emit_member_include
            // lambda, same bug, independently duplicated here for CHOICE.
            const auto& seqof_elem = m->is_seq_of()
                ? std::get<ast::SequenceOfType>(m->body).element
                : std::get<ast::SetOfType>(m->body).element;
            if (auto* tr_elem = std::get_if<ast::TypeRef>(&seqof_elem->body)) {
                emit_inc(cpp_name_for_typeref(*tr_elem));
            } else if (seqof_elem->is_sequence() || seqof_elem->is_choice() || seqof_elem->is_set()) {
                // Anonymous inline element — see the matching fix in
                // emit_member_include for the "Anon"-suffixed doubly-nested
                // synthetic name rationale.
                emit_inc(backend_.synthetic_name(backend_.synthetic_name(cname, m->name), "Anon"));
            }
        } else if ((m->is_sequence() || m->is_choice() || m->is_set()) && !m->name.empty()) {
            auto synth = backend_.synthetic_name(cname, m->name);
            emit_inc(synth);
        } else {
            auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
            if (mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty()) {
                auto synth = backend_.synthetic_name(cname, m->name);
                emit_inc(synth);
            }
        }
    }
    if (count > 0) os << "\n";

    bool apply_auto_tags_hpp = should_apply_auto_tags(def);
    auto canon_members = canonical_choice_members(def, apply_auto_tags_hpp);

    std::vector<ChoiceAlternativeSpec> alts;
    for (const auto* m : canon_members) {
        ChoiceAlternativeSpec alt;
        alt.mtype = native_member_type_for(*m);
        alt.accessor_name = backend_.member_name(m->name,
            {"present", "set_present", "val_", "val_storage_", "active_lifecycle",
             "s_alternatives", "s_alternative_count"});
        alt.pr_name = backend_.escape(backend_.type_name(m->name), {"NOTHING"});
        // Not otherwise needed by the declaration side — carried along
        // purely so emit_choice's zip can assert the two independently
        // computed canonical orderings actually agree, index by index.
        alt.asn1_name = m->name;
        alts.push_back(std::move(alt));
    }
    return alts;
}

ChoiceSpec Generator::emit_choice_definition(const ast::TypeDef& def, TypeOutputSession& session) {
    std::string cname = effective_cpp_name(def.name, current_module_);

    auto [count, ext_at] = count_members(def);
    bool apply_auto_tags = should_apply_auto_tags(def);

    ChoiceSpec spec;
    spec.type_name = cname;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    spec.count = count;
    spec.ext_at = ext_at;

    // X.680 §30.6 — CHOICE has no universal tag; a declared [n] on the type
    // assignment itself is always EXPLICIT (wraps the chosen alternative's
    // own encoding in an outer TLV) rather than substituting for anything.
    spec.tag = tag_spec_for(def.tag, /*constructed=*/true);
    spec.is_explicit = type_is_explicit(def);

    // Alternative descriptor table
    if (count > 0) {
        struct AltRow {
            std::string name, tdref, alt_type;
            bool is_explicit;
            int  tag_cls_int = -1;  // -1 = not context; >=0 = Context tag number
            ast::Tag full_tag;      // for canonical sort
            std::optional<ast::BuiltinType> mbuiltin;
            IntStorageKind storage_kind = IntStorageKind::S64;
            std::optional<MemberTagSpec> resolved_tag;  // gambas-asn1#336/#347
        };
        std::vector<AltRow> rows;
        // Pass 1: collect rows in declaration order + emit static TypeDescriptors.
        // TypeDescriptors must be emitted before the alternatives array references them.
        { int auto_tag_num = 0;
          for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string mname = backend_.member_name(m->name);
            auto [resolved_tag, is_explicit] = compute_member_tag(*m, apply_auto_tags, auto_tag_num);
            std::string tdref = emit_member_type_descriptor(*m, cname, mname, session);
            std::string alt_type = native_member_type_for(*m);
            int tag_ctx_num = -1;
            ast::Tag full_tag = m->tag;
            if (apply_auto_tags && !m->tag.present()) {
                tag_ctx_num = auto_tag_num;
                full_tag.cls = ast::TagClass::Context;
                full_tag.number = auto_tag_num;
            } else if (m->tag.present() && m->tag.cls == ast::TagClass::Context) {
                tag_ctx_num = m->tag.number;
            }
            std::optional<ast::BuiltinType> mbuiltin;
            IntStorageKind alt_storage_kind = IntStorageKind::S64;
            if (auto* bt = std::get_if<ast::BuiltinType>(&m->body)) {
                mbuiltin = *bt;
                if (*bt == ast::BuiltinType::Integer) alt_storage_kind = classify_integer_storage(*m);
            }
            rows.push_back({ m->name, tdref, alt_type, is_explicit,
                             tag_ctx_num, full_tag, mbuiltin, alt_storage_kind, resolved_tag });
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

        for (const auto& r : rows) {
            ChoiceAlternativeSpec alt;
            alt.mtype = r.alt_type;
            alt.asn1_name = r.name;
            alt.tdref = r.tdref;
            alt.is_explicit = r.is_explicit;
            alt.mbuiltin = r.mbuiltin;
            alt.storage_kind = r.storage_kind;
            alt.resolved_tag = r.resolved_tag;
            spec.alternatives.push_back(std::move(alt));
        }

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
            std::vector<int16_t> idx_table(range, -1);
            for (int i = 0; i < (int)rows.size(); ++i)
                idx_table[rows[i].tag_cls_int - min_tag] = (int16_t)i;
            spec.has_tag_index = true;
            spec.tag_index_base = min_tag;
            spec.tag_index_table = std::move(idx_table);
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
        spec.has_ber_table = true;
        spec.ber_tags = std::move(ber_tags);
    }

    return spec;
}

/// @brief Emit a CHOICE type's declaration+definition.
/// @param def     CHOICE TypeDef.
/// @param session Per-type output session.
/// @note Zips the declaration-only fields (mtype/accessor_name/pr_name) from
///       emit_choice_declaration onto the definition-built ChoiceSpec by
///       index — see the class-level note on emit_choice_declaration/
///       emit_choice_definition for why this is safe (both compute the same
///       canonical order; the runtime already depends on that invariant
///       today via the generated enum vs. alternatives table).
void Generator::emit_choice(const ast::TypeDef& def, TypeOutputSession& session) {
    auto decl_alts = emit_choice_declaration(def, session.buffer(backend_.declaration_extension()));
    auto spec = emit_choice_definition(def, session);
    assert(spec.alternatives.size() == decl_alts.size() &&
           "emit_choice_declaration/emit_choice_definition disagree on alternative count");
    for (std::size_t i = 0; i < spec.alternatives.size() && i < decl_alts.size(); ++i) {
        // Both sides compute canonical PER tag order independently (see the
        // header note on emit_choice_declaration/emit_choice_definition) —
        // assert they actually agree index-by-index before trusting the
        // zip; a silent divergence here would attach the wrong accessor
        // name to the wrong alternative rather than crash.
        assert(spec.alternatives[i].asn1_name == decl_alts[i].asn1_name &&
               "emit_choice_declaration/emit_choice_definition canonical order mismatch");
        spec.alternatives[i].mtype = decl_alts[i].mtype;
        spec.alternatives[i].accessor_name = decl_alts[i].accessor_name;
        spec.alternatives[i].pr_name = decl_alts[i].pr_name;
    }
    backend_.emit_choice(spec, session);
}

// ---------------------------------------------------------------------------
// Top-level emit_declaration / emit_definition dispatch
// ---------------------------------------------------------------------------

/// @brief Write the output file(s) for one type definition, driven by a
///        TypeOutputSession (gambas-asn1#262) instead of hardcoding a
///        ".hpp"/".cpp" pair — see Generator.hpp's declaration for the
///        parameter contract.
/// @note Merging is implicit: when backend_.declaration_extension() ==
///       backend_.definition_extension(), the session hands emit_declaration and
///       emit_definition the *same* stream, so they naturally combine into one
///       file with no separate branch here. Always calls both emit_declaration and
///       emit_definition — emit_definition itself decides whether a definition exists
///       (returns without writing anything for a plain TypeRef alias), so
///       there's no separately-computed "needs a definition" flag to keep
///       in sync with emit_definition's own dispatch. Buffers that end up empty
///       (that decision, or a backend's genuinely-empty declaration half —
///       e.g. RustBackend's emit_builtin_alias_declaration) are simply not written.
///       Known limitation (not yet hit in practice — no backend combines
///       single-file output with -fprefix namespace wrapping today): each
///       of emit_declaration/emit_definition independently wraps its own body in
///       backend_.emit_namespace_open/close when namespace_ is set, which
///       would produce two conflicting module blocks of the same name in
///       one file. Revisit if/when that combination occurs.
void Generator::emit_type_files(const std::string& name, const ast::TypeDef& def,
                                 const ast::Module& mod) {
    std::string base = filename_for(name);
    emitted_type_refs_.clear();
    TypeOutputSession session;
    emit_type_body(def, mod, session);
    for (auto& [ext, content] : session.finish()) {
        if (content.empty()) continue;
        fs::path path = out_dir_ / (base + "." + ext);
        known_files_.insert(path);
        write_if_changed(path, content);
    }
}

void Generator::write_type_reference(const std::string& type_name, std::ostream& target) {
    // gambas-asn1#300: skip a reference this type's declaration output has
    // already written (gated on backend_.dedupe_type_references(), true by
    // default for every backend — see that method's doc, Backend.hpp).
    // Found on the real ETSI LI PS-PDU schema (#299/#300): RustBackend's
    // `use crate::X::X;` has no #include-guard equivalent, so a duplicate
    // reference was a hard compile error (E0252), the single largest error
    // category on that schema.
    if (backend_.dedupe_type_references() && !emitted_type_refs_.insert(type_name).second) return;
    TypeOutputSession ref;
    ref.seed(backend_.declaration_extension(), target);
    backend_.emit_type_reference(type_name, filename_for(type_name), ref);
}

void Generator::write_forward_declaration(const std::string& type_name, std::ostream& target) {
    TypeOutputSession ref;
    ref.seed(backend_.declaration_extension(), target);
    backend_.emit_forward_declaration(type_name, ref);
}

/// @brief Emit both output files for any top-level type definition.
/// @param def     ASN.1 type definition to generate.
/// @param mod     Owning module (provides tag default and OID for the file header comment).
/// @param session The type's real output session (backing the final files).
void Generator::emit_type_body(const ast::TypeDef& def, const ast::Module& mod, TypeOutputSession& session) {
    std::string cname = effective_cpp_name(def.name, mod.name);
    const std::string decl_ext = backend_.declaration_extension();
    const std::string def_ext  = backend_.definition_extension();
    std::ostream& decl_os = session.buffer(decl_ext);
    std::ostream& def_os  = session.buffer(def_ext);   // == decl_os when merged (e.g. Rust)

    // Module header comment with OID if present
    std::string module_comment = mod.name;
    if (!mod.oid.arcs.empty()) {
        module_comment += " {";
        for (const auto& arc : mod.oid.arcs) {
            module_comment += " ";
            if (arc.number >= 0) module_comment += std::to_string(arc.number);
            else module_comment += arc.name;
        }
        module_comment += " }";
    }
    backend_.emit_declaration_preamble(module_comment, session);

    bool has_definition = def.is_sequence() || def.is_set() || def.is_choice()
        || def.is_seq_of() || def.is_set_of()
        || std::holds_alternative<ast::BuiltinType>(def.body);
    if (has_definition) backend_.emit_definition_preamble(filename_for(cname), session);

    // When namespace wrapping is active, cross-type #include "X.hpp" directives must land
    // BEFORE the namespace opens (each peer .hpp already wraps itself in the namespace).
    // Forward declarations (class X;) and the class body go inside the namespace.
    // Dispatch writes into temporary body buffers instead of the real streams;
    // pre_ns_os_ routes includes discovered during dispatch to the real decl_os
    // directly. Deferred self-referential includes (post_class_includes from
    // emit_sequence_declaration) must land AFTER the closing `} // namespace`
    // brace — use post_ns_ss for that.
    std::ostringstream body_ns, body_ns_definition, post_ns_ss;
    std::ostream& decl_body = namespace_.empty() ? decl_os : static_cast<std::ostream&>(body_ns);
    std::ostream& def_body  = namespace_.empty() ? def_os  : static_cast<std::ostream&>(body_ns_definition);
    if (!namespace_.empty()) {
        pre_ns_os_  = &decl_os;
        post_ns_os_ = &post_ns_ss;
    }

    // Dispatch session: rebinds declaration_extension()/definition_extension()
    // to the body targets above (real streams with no namespace, temporary
    // buffers otherwise) so the combined backend_.emit_*() calls write into
    // the right place either way. A single seed() when merged (decl_ext ==
    // def_ext) — dispatch.buffer(def_ext) then finds the same binding as
    // dispatch.buffer(decl_ext), so both halves land in decl_body in write
    // order, exactly like the un-wrapped single-file case.
    TypeOutputSession dispatch;
    dispatch.seed(decl_ext, decl_body);
    if (def_ext != decl_ext) dispatch.seed(def_ext, def_body);

    if (def.is_sequence() || def.is_set()) {
        current_type_ = cname;
        emit_sequence(def, dispatch);
    } else if (def.is_choice()) {
        current_type_ = cname;
        emit_choice(def, dispatch);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated) {
            emit_enumerated(def, dispatch);
        } else if (*bt == ast::BuiltinType::Integer) {
            emit_integer(def, dispatch);
        } else {
            emit_builtin_alias(def, dispatch);
        }
    } else if (def.is_seq_of() || def.is_set_of()) {
        current_type_ = cname;
        emit_seq_of(def, dispatch);
    } else if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        auto inc = cpp_name_for_typeref(*tr);
        auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : decl_body;
        write_type_reference(inc, inc_os);
        backend_.emit_typeref_alias_declaration(cname, inc, dispatch);
    }

    pre_ns_os_  = nullptr;
    post_ns_os_ = nullptr;
    if (!namespace_.empty()) {
        backend_.emit_namespace_open(namespace_, session);
        decl_os << body_ns.str();
        if (has_definition) def_os << body_ns_definition.str();
        backend_.emit_namespace_close(namespace_, session);
        if (!has_definition && def_ext != decl_ext) {
            // A plain TypeRef alias has no definition half, but
            // emit_namespace_open/close above still wrote open/close
            // markers into def_os unconditionally (gambas-asn1#265) —
            // reset it back to empty now that both have run, so the stray
            // markers don't turn into a near-empty file at write time.
            // Guarded on def_ext != decl_ext: for a single-file backend
            // def_os *is* decl_os, and clearing it would wipe the real
            // declaration content too.
            static_cast<std::ostringstream&>(def_os).str("");
        }
        auto post = post_ns_ss.str();
        if (!post.empty()) decl_os << "\n" << post;
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

/// @brief Decide the resolved BuiltinAliasSpec for a top-level builtin
///        string/octet/bit-string type alias (e.g.
///        `MyStr ::= IA5String (SIZE(1..32) FROM("A".."Z"))`).
/// @param def       ASN.1 type assignment that resolves to a sizeable primitive.
/// @param type_name Final backend-resolved type identifier.
/// @return The decision as plain data — see BuiltinAliasSpec.
/// @see X.691 §26.5 (character string PER constraints); X.690 §8.7 (OCTET STRING BER encoding).
BuiltinAliasSpec Generator::build_builtin_alias_spec(const ast::TypeDef& def,
                                                       const std::string& type_name) const {
    BuiltinAliasSpec spec;
    spec.type_name = type_name;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    // Defensive fallback (unreachable in practice — this is only called from
    // emit_definition's dispatch after confirming def.body is a BuiltinType): if
    // absent, fall back to Utf8String, whose LUT entries are the generic
    // string handlers, matching the original defensive fallback.
    auto* bt = std::get_if<ast::BuiltinType>(&def.body);
    spec.builtin_type = bt ? *bt : ast::BuiltinType::Utf8String;
    spec.tag = natural_tag_spec_for(def);
    spec.is_explicit = type_is_explicit(def);
    if (spec.is_explicit) spec.natural_tag = underlying_natural_tag_spec_for(def);

    spec.alphabet = extract_from_alphabet(def);
    auto size_range = extract_size_range(def);
    spec.has_size_constraint = size_range.has_value();
    spec.size_bounded = size_range.has_value()
        && size_range->second != std::numeric_limits<int64_t>::max();
    if (size_range) {
        auto sc = compute_size_constraint(size_range);
        spec.size_range_bits = sc.range_bits;
        spec.size_lower = sc.lower;
        spec.size_upper = sc.upper;  // meaningless when !size_bounded (semi-constrained)
    }
    spec.extensible = is_constraint_extensible(def);
    spec.xer_encoding = def.xer_encoding;
    return spec;
}

/// @brief Emit a builtin-alias type's declaration+definition.
/// @param def ASN.1 type assignment (must resolve to a plain builtin type,
///            not INTEGER/ENUMERATED — those have their own emit_integer/
///            emit_enumerated).
/// @param session Per-type output session.
void Generator::emit_builtin_alias(const ast::TypeDef& def, TypeOutputSession& session) {
    auto spec = build_builtin_alias_spec(def, effective_cpp_name(def.name, current_module_));
    backend_.emit_builtin_alias(spec, session);
}

// ---------------------------------------------------------------------------
// Emit SEQUENCE OF / SET OF
// ---------------------------------------------------------------------------

/// @brief Emit the declaration-side element include (if any) and return the
///        declaration-only SeqOfSpec fields (type_name/elem_type).
/// @param def SEQUENCE OF / SET OF type definition.
/// @param os  Output stream for the generated declaration file.
SeqOfSpec Generator::emit_seq_of_declaration(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    const auto& elem = def.is_seq_of()
        ? std::get<ast::SequenceOfType>(def.body).element
        : std::get<ast::SetOfType>(def.body).element;
    // SeqOf element includes go before the namespace (each .hpp wraps itself).
    auto& inc_os = pre_ns_os_ ? *pre_ns_os_ : os;
    if (auto* tr = std::get_if<ast::TypeRef>(&elem->body)) {
        auto inc = cpp_name_for_typeref(*tr);
        write_type_reference(inc, inc_os);
        inc_os << "\n";
    } else if (elem->is_sequence() || elem->is_choice() || elem->is_set()) {
        auto synth = backend_.synthetic_name(cname, elem->name.empty() ? "Anon" : elem->name);
        write_type_reference(synth, inc_os);
        inc_os << "\n";
    } else if (auto* ebt = std::get_if<ast::BuiltinType>(&elem->body);
               ebt && *ebt == ast::BuiltinType::Enumerated && !elem->enum_values.empty()) {
        auto synth = backend_.synthetic_name(cname, elem->name.empty() ? "Enum" : elem->name);
        write_type_reference(synth, inc_os);
        inc_os << "\n";
    }
    SeqOfSpec spec;
    spec.type_name = cname;
    spec.elem_type = native_member_type_for(*elem);
    return spec;
}

/// @brief Decide the resolved SeqOfSpec, emit the element's own inline-
///        constrained descriptor (if any) as a side effect, then return
///        the SeqOfSpec for the combined backend call.
/// @param def     SEQUENCE OF / SET OF type definition.
/// @param session Per-type output session.
SeqOfSpec Generator::emit_seq_of_definition(const ast::TypeDef& def, TypeOutputSession& session) {
    std::string cname = effective_cpp_name(def.name, current_module_);
    const auto& elem_node = def.is_seq_of()
        ? *std::get<ast::SequenceOfType>(def.body).element
        : *std::get<ast::SetOfType>(def.body).element;

    SeqOfSpec spec;
    spec.type_name = cname;
    spec.xer_name  = def.xer_name.empty() ? def.name : def.xer_name;
    spec.is_set_of = def.is_set_of();
    spec.tag = natural_tag_spec_for(def);
    spec.is_explicit = type_is_explicit(def);
    if (spec.is_explicit) spec.natural_tag = underlying_natural_tag_spec_for(def);

    // SIZE constraint on collection length
    auto size_range = extract_size_range(def);
    auto sc = compute_size_constraint(size_range, is_constraint_extensible(def));
    spec.has_size_constraint = size_range.has_value();
    spec.extensible = is_constraint_extensible(def);
    spec.range_bits = sc.range_bits;
    spec.size_lower = sc.lower;
    if (sc.flags & asn1::Constraints::SIZE_CONSTRAINED) spec.size_upper = sc.upper;

    // When the element is an inline-constrained builtin, emit a per-element
    // TypeDescriptor that carries the constraint; otherwise reuse the natural descriptor.
    // Writes directly into `os` (== session.buffer(definition_extension())),
    // before the SeqOfSpec it's referenced from is emitted later.
    spec.elem_ref = emit_member_type_descriptor(elem_node, cname, "elem", session);

    // X.693 §12: declared element identifier overrides the XER tag at the use site.
    // Exception: asn1c uses <NULL/> for NULL-typed elements regardless of declared name.
    // Similarly, ANY keeps is_any=true semantics and must not be renamed.
    if (!elem_node.name.empty()) {
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
        if (!is_null_or_any) spec.elem_xer_name = elem_node.name;
    }

    return spec;
}

/// @brief Emit a SEQUENCE OF / SET OF type's declaration+definition.
/// @param def     SEQUENCE OF / SET OF TypeDef.
/// @param session Per-type output session.
/// @note Declaration and definition each contribute disjoint SeqOfSpec
///       fields (elem_type vs. everything else) — merge decl_spec.elem_type
///       onto def_spec before the combined backend_.emit_seq_of() call.
void Generator::emit_seq_of(const ast::TypeDef& def, TypeOutputSession& session) {
    auto decl_spec = emit_seq_of_declaration(def, session.buffer(backend_.declaration_extension()));
    auto spec = emit_seq_of_definition(def, session);
    spec.elem_type = decl_spec.elem_type;
    backend_.emit_seq_of(spec, session);
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
            std::string synth_name = backend_.synthetic_name(parent_cname, was_anon ? "Anon" : elem.name);
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
                emit_type_files(synth_name, *synthetic, mod);
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
            std::string seqof_name = backend_.synthetic_name(parent_cname, m->name);
            std::string elem_type_name;  // non-empty iff element was an inline complex type
            if (elem.is_sequence() || elem.is_choice() || elem.is_set()) {
                bool was_anon = elem.name.empty();
                elem_type_name = backend_.synthetic_name(seqof_name, was_anon ? "Anon" : elem.name);
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
                    emit_type_files(elem_type_name, *synthetic, mod);
                }
            } else if (elem.is_seq_of() || elem.is_set_of()) {
                // Anonymous nested SEQUENCE OF/SET OF element (X.680 §25/26
                // nesting, to unbounded depth — "rows SEQUENCE OF SEQUENCE
                // OF INTEGER", both levels unnamed). Same promote-to-a-real-
                // named-type treatment as the composite-element case just
                // above: without this, the element stays embedded inline
                // and native_member_type_for/type_descriptor_ref_for's own SEQUENCE
                // OF/SET OF branches (which only know how to resolve a
                // *named* nested collection, or recurse straight through an
                // anonymous one to its innermost scalar) skip the
                // intermediate collection level entirely — corrupting the
                // C++ BER encoding (the generic SeqOf handler reads each
                // outer element as the wrong type) and, on the Rust side,
                // producing a bare Vec<Vec<T>> field with no Asn1Value impl
                // (same coherence problem octet_string::OctetString's own
                // module doc describes) that fails to compile. Promoting
                // gives this level a real name, a real recursive descriptor
                // (generate_inline_types recurses into it below, handling
                // further nesting the same way), and — critically — the
                // rewrite to a TypeRef a few lines down means every other
                // resolution path (type_descriptor_ref_for, native_member_type_for)
                // just takes their already-correct, already-tested named-
                // type branch from here on, no special-casing needed there.
                // See gambas-asn1#427.
                bool was_anon = elem.name.empty();
                elem_type_name = backend_.synthetic_name(seqof_name, was_anon ? "Anon" : elem.name);
                seq_of_synthetic_names_.insert(elem_type_name);
                if (!generated_names_.count(elem_type_name)) {
                    generated_names_.insert(elem_type_name);
                    auto synthetic = std::make_shared<ast::TypeDef>(elem);
                    synthetic->name = elem_type_name;
                    if (was_anon) synthetic->xer_name = elem.is_seq_of() ? "SEQUENCE" : "SET";
                    generate_inline_types(*synthetic, mod);
                    current_type_ = elem_type_name;
                    emit_type_files(elem_type_name, *synthetic, mod);
                }
            } else if (auto* ebt = std::get_if<ast::BuiltinType>(&elem.body);
                       ebt && *ebt == ast::BuiltinType::Enumerated && !elem.enum_values.empty()) {
                bool was_anon = elem.name.empty();
                elem_type_name = backend_.synthetic_name(seqof_name, was_anon ? "Enum" : elem.name);
                if (!generated_names_.count(elem_type_name)) {
                    generated_names_.insert(elem_type_name);
                    auto synthetic = std::make_shared<ast::TypeDef>(elem);
                    synthetic->name = elem_type_name;
                    current_type_ = elem_type_name;
                    emit_type_files(elem_type_name, *synthetic, mod);
                }
            }
            // Generate synthetic SeqOf wrapper descriptor type named parent + MemberCamel.
            // If element was anonymous inline, replace it with a TypeRef to the named element
            // type so emit_declaration uses the correct name and include path.
            // (seqof_name already computed above)
            if (!generated_names_.count(seqof_name)) {
                generated_names_.insert(seqof_name);
                auto seqof_td = std::make_shared<ast::TypeDef>(*m);
                seqof_td->name = seqof_name;
                // The member's own [n] tag (X.680's per-member tagging) is not the
                // synthetic wrapper TYPE's own declared tag — clear it so
                // natural_tag_for() doesn't mistake the copied member tag for a
                // top-level [n] IMPLICIT/EXPLICIT declaration on this type itself.
                seqof_td->tag = ast::Tag{};
                if (!elem_type_name.empty()) {
                    auto named_elem = std::make_shared<ast::TypeDef>();
                    named_elem->body = ast::TypeRef{"", elem_type_name, {}};
                    if (m->is_seq_of())
                        seqof_td->body = ast::SequenceOfType{named_elem};
                    else
                        seqof_td->body = ast::SetOfType{named_elem};
                }
                current_type_ = seqof_name;
                emit_type_files(seqof_name, *seqof_td, mod);
            }
            continue;
        }

        auto* mbt = std::get_if<ast::BuiltinType>(&m->body);
        bool is_inline_enum = mbt && *mbt == ast::BuiltinType::Enumerated && !m->enum_values.empty();
        if (!m->is_sequence() && !m->is_choice() && !m->is_set() && !is_inline_enum) continue;
        if (m->name.empty()) continue;

        std::string synth_name = backend_.synthetic_name(parent_cname, m->name);

        if (generated_names_.count(synth_name)) continue;
        generated_names_.insert(synth_name);

        auto synthetic = std::make_shared<ast::TypeDef>(*m);
        synthetic->name = synth_name;
        // Same reasoning as the SeqOf wrapper above: the member's own [n] tag must
        // not be mistaken for this synthetic type's own top-level declared tag.
        synthetic->tag = ast::Tag{};

        generate_inline_types(*synthetic, mod);

        current_type_ = synth_name;
        emit_type_files(synth_name, *synthetic, mod);
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
            std::string elem_name = backend_.synthetic_name(cname, elem_ptr->name.empty() ? "Enum" : elem_ptr->name);
            if (!generated_names_.count(elem_name)) {
                generated_names_.insert(elem_name);
                auto synthetic = std::make_shared<ast::TypeDef>(*elem_ptr);
                synthetic->name = elem_name;
                auto save = current_type_;
                current_type_ = elem_name;
                emit_type_files(elem_name, *synthetic, mod);
                current_type_ = save;
            }
        }
    }

    emit_type_files(cname, def, mod);
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
