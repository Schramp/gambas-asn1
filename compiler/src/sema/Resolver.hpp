#pragma once
#include <algorithm>
#include <climits>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"

namespace asn1::sema {

// SymbolTable maps type_name -> TypeDefPtr
using SymbolTable = std::unordered_map<std::string, ast::TypeDefPtr>;

// Compare two OID arcs: match if both have numbers (compare numerically),
// or both are name-only (compare by name). Mixed = mismatch.
inline bool arcs_match(const ast::OidValue::Arc& a, const ast::OidValue::Arc& b) {
    bool a_num = a.number >= 0, b_num = b.number >= 0;
    if (a_num && b_num)   return a.number == b.number;
    if (!a_num && !b_num) return a.name == b.name;
    return false; // one has number, other doesn't — treat as mismatch
}

inline bool oids_match(const ast::OidValue& a, const ast::OidValue& b) {
    if (a.arcs.size() != b.arcs.size()) return false;
    for (std::size_t i = 0; i < a.arcs.size(); ++i)
        if (!arcs_match(a.arcs[i], b.arcs[i])) return false;
    return true;
}

// WITH SUCCESSORS: same length, all arcs match except last which must be >=
inline bool oids_match_successors(const ast::OidValue& imp, const ast::OidValue& mod) {
    if (imp.arcs.size() != mod.arcs.size() || imp.arcs.empty()) return false;
    for (std::size_t i = 0; i + 1 < imp.arcs.size(); ++i)
        if (!arcs_match(imp.arcs[i], mod.arcs[i])) return false;
    const auto& ia = imp.arcs.back();
    const auto& ma = mod.arcs.back();
    if (ia.number >= 0 && ma.number >= 0) return ma.number >= ia.number;
    return ia.name == ma.name;
}

// WITH DESCENDANTS: mod OID starts with imp OID prefix (mod may be longer)
inline bool oids_match_descendants(const ast::OidValue& imp, const ast::OidValue& mod) {
    if (imp.arcs.size() > mod.arcs.size()) return false;
    for (std::size_t i = 0; i < imp.arcs.size(); ++i)
        if (!arcs_match(imp.arcs[i], mod.arcs[i])) return false;
    return true;
}

// Version-aware OID comparison for -fallow-newer-modules.
// Assumes available is the full versioned OID; last two arcs are (release, minor).
// Returns:
//   0       exact version match     — silent accept
//  -1       available is newer      — accept with warning
//   2       imported is base prefix — accept with warning
//   1       available is older      — reject
//  INT_MIN  unrelated family        — fall through to normal OID check
inline int oid_version_compare(const ast::OidValue& imp, const ast::OidValue& mod) {
    int ai = static_cast<int>(imp.arcs.size());
    int av = static_cast<int>(mod.arcs.size());
    int ver_start = av - 2;

    if (ver_start < 0) return INT_MIN;   // available too short to carry version arcs
    if (ai > av)       return INT_MIN;   // imported longer than available
    if (av - ai > 2)   return INT_MIN;   // imported too short to be a valid base prefix

    // Base arcs must match up to min(ai, ver_start)
    int base_end = (ai < ver_start) ? ai : ver_start;
    for (int i = 0; i < base_end; ++i)
        if (!arcs_match(imp.arcs[i], mod.arcs[i])) return INT_MIN;

    if (ai <= ver_start) return 2;  // imported has no version arcs — bare base prefix

    // Compare version arcs [ver_start, av)
    for (int i = ver_start; i < av; ++i) {
        int64_t a = (i < ai) ? imp.arcs[i].number : -1;
        int64_t b = mod.arcs[i].number;
        // Fall back to name comparison if either arc is name-only
        if (a < 0 || b < 0) {
            std::string an = (i < ai) ? imp.arcs[i].name : "";
            std::string bn = mod.arcs[i].name;
            if (bn > an) return -1;
            if (bn < an) return  1;
        } else {
            if (b > a) return -1;
            if (b < a) return  1;
        }
    }
    return 0;
}

// -fallow-newer-modules: accept if mod is same version, newer, or a descendant prefix.
// Returns false for older (reject) or unrelated OID family (no match).
inline bool oids_match_newer(const ast::OidValue& imp, const ast::OidValue& mod) {
    int v = oid_version_compare(imp, mod);
    return v == 0 || v == -1 || v == 2;
}

inline const char* builtin_type_name(ast::BuiltinType bt) {
    using B = ast::BuiltinType;
    switch (bt) {
    case B::Boolean:          return "BOOLEAN";
    case B::Integer:          return "INTEGER";
    case B::BitString:        return "BIT STRING";
    case B::OctetString:      return "OCTET STRING";
    case B::Null:             return "NULL";
    case B::ObjectIdentifier: return "OBJECT IDENTIFIER";
    case B::RelativeOid:      return "RELATIVE-OID";
    case B::Real:             return "REAL";
    case B::Enumerated:       return "ENUMERATED";
    case B::Utf8String:       return "UTF8String";
    case B::NumericString:    return "NumericString";
    case B::PrintableString:  return "PrintableString";
    case B::T61String:        return "T61String";
    case B::VideotexString:   return "VideotexString";
    case B::Ia5String:        return "IA5String";
    case B::GraphicString:    return "GraphicString";
    case B::VisibleString:    return "VisibleString";
    case B::GeneralString:    return "GeneralString";
    case B::UniversalString:  return "UniversalString";
    case B::BmpString:        return "BMPString";
    case B::ObjectDescriptor: return "ObjectDescriptor";
    case B::UtcTime:          return "UTCTime";
    case B::GeneralizedTime:  return "GeneralizedTime";
    case B::Any:              return "ANY";
    }
    return "builtin type";
}

inline std::string oid_to_string(const ast::OidValue& oid) {
    std::string s = "{";
    for (const auto& arc : oid.arcs) {
        s += " ";
        if (arc.number >= 0) s += std::to_string(arc.number);
        else s += arc.name;
    }
    return s + " }";
}

class Resolver {
    // Per-module symbol tables: module_name -> all definitions in that module
    std::unordered_map<std::string, SymbolTable> module_symbols_;
    // Per-module visible-name → typedef map: own symbols + symbols imported
    // by that module. Distinct from global_ so that name collisions across
    // modules resolve correctly per importing scope.
    std::unordered_map<std::string, SymbolTable> module_resolution_;
    // Per-module visible names: own symbols + explicitly imported names
    std::unordered_map<std::string, std::unordered_set<std::string>> module_visible_;
    // Flat global table for codegen lookups (all resolvable symbols)
    SymbolTable global_;

    std::unordered_map<std::string, ast::TagDefault> module_tag_defaults_;

    bool allow_newer_modules_{false};
    std::vector<std::string> errors_;
    std::vector<std::string> warnings_;

public:
    void set_allow_newer_modules(bool v)    { allow_newer_modules_ = v; }
    const std::vector<std::string>& errors()   const { return errors_; }
    const std::vector<std::string>& warnings() const { return warnings_; }

    // Phase 1: collect all top-level definitions from all modules
    void collect(const ast::ParseResult& pr) {
        // Collect per-module symbols.
        // Duplicate module name: error (X.680 §12.1).
        // Intra-module duplicate type name: error.
        // Cross-module same-name types are legal: Generator prefixes them with the module
        // name (effective_cpp_name) so each gets a distinct C++ identifier.
        std::unordered_set<std::string> seen_modules;
        for (const auto& mod : pr.modules) {
            if (!seen_modules.insert(mod->name).second) {
                errors_.push_back("duplicate module name '" + mod->name + "'");
                continue;
            }
            module_tag_defaults_[mod->name] = mod->tag_default;
            SymbolTable& tbl = module_symbols_[mod->name];
            for (const auto& def : mod->assignments) {
                if (!def->name.empty()) {
                    if (!tbl.emplace(def->name, def).second)
                        errors_.push_back("duplicate type name '" + def->name
                                          + "' in module '" + mod->name + "'");
                }
            }
        }
    }

    // Phase 2: resolve cross-module imports
    // Builds module_visible_ (scoped) and global_ (for codegen)
    void resolve_imports(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules) {
            auto& vis = module_visible_[mod->name];
            auto& res = module_resolution_[mod->name];

            // Every module can see its own symbols
            for (auto& [name, def] : module_symbols_[mod->name]) {
                global_[name] = def;
                vis.insert(name);
                res[name] = def;
            }

            // Bring in imports
            for (const auto& imp : mod->imports) {
                // X.680 §12.3: a module may not import from itself.
                if (imp.from_module == mod->name) {
                    errors_.push_back("module '" + mod->name + "' imports from itself");
                    continue;
                }

                // Select OID matcher from import version policy.
                // X.680 §12.3: OID is authoritative identity; name in IMPORTS is alias only.
                using VP = ast::ImportVersionPolicy;
                using OidMatcher = bool(*)(const ast::OidValue&, const ast::OidValue&);
                OidMatcher oid_matches =
                    (allow_newer_modules_ && (imp.version_policy == VP::Exact ||
                                              imp.version_policy == VP::Successors))
                        ? &oids_match_newer
                        : (imp.version_policy == VP::Successors)  ? &oids_match_successors
                        : (imp.version_policy == VP::Descendants) ? &oids_match_descendants
                        :                                            &oids_match;

                // Lookup: OID authoritative when present; fall back to name when absent.
                std::string resolved_name;
                auto it = module_symbols_.end();
                if (!imp.module_oid.arcs.empty()) {
                    for (const auto& m : pr.modules) {
                        if (!m->oid.arcs.empty() && oid_matches(imp.module_oid, m->oid)) {
                            auto candidate = module_symbols_.find(m->name);
                            if (candidate != module_symbols_.end()) {
                                it = candidate;
                                resolved_name = m->name;
                                break;
                            }
                        }
                    }
                } else {
                    it = module_symbols_.find(imp.from_module);
                    if (it != module_symbols_.end())
                        resolved_name = imp.from_module;
                }

                if (it == module_symbols_.end()) {
                    // OID scan failed — check if module exists by name for a better diagnostic.
                    if (!imp.module_oid.arcs.empty()
                            && module_symbols_.count(imp.from_module)) {
                        const char* policy =
                            (imp.version_policy == VP::Successors)  ? "WITH SUCCESSORS" :
                            (imp.version_policy == VP::Descendants) ? "WITH DESCENDANTS" : "exact";
                        errors_.push_back("module '" + imp.from_module
                            + "': available OID does not satisfy " + policy + " import constraint");
                    } else {
                        errors_.push_back("module '" + imp.from_module
                            + "' imported by '" + mod->name + "' was not found");
                    }
                    continue;
                }
                // OID lookup may resolve an alias to the importing module itself.
                if (resolved_name == mod->name) {
                    errors_.push_back("module '" + mod->name + "' imports from itself");
                    continue;
                }

                // resolved_name was taken from pr.modules during lookup, so find_if is guaranteed to match
                const auto& src_mod = *std::find_if(
                    pr.modules.begin(), pr.modules.end(),
                    [&](const auto& m){ return m->name == resolved_name; });

                // Check EXPORTS restriction of source module
                bool src_exports_all = src_mod->exports_all;
                const auto& src_exports = src_mod->exports;

                for (const auto& imported_name : imp.names) {
                    // Enforce EXPORTS if source module has explicit list
                    if (!src_exports_all) {
                        bool exported = std::find(src_exports.begin(), src_exports.end(),
                                                  imported_name) != src_exports.end();
                        if (!exported) {
                            errors_.push_back("'" + imported_name + "' is not exported by module '"
                                + imp.from_module + "'");
                            continue;
                        }
                    }
                    auto sym = it->second.find(imported_name);
                    if (sym != it->second.end()) {
                        global_[imported_name] = sym->second;
                        vis.insert(imported_name);
                        res[imported_name] = sym->second;
                    }
                }
            }
        }
    }

    // Phase 3: check TypeRefs used in each module are visible there,
    // then walk all TypeDef trees.
    void resolve_types(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                check_and_resolve(def, mod->name);
    }

    // Look up a type by name in global table (returns nullptr if not found)
    ast::TypeDefPtr lookup(const std::string& name) const {
        auto it = global_.find(name);
        return it != global_.end() ? it->second : nullptr;
    }

    // Walk a TypeRef alias chain starting at `def`, using `start_module` as the
    // initial scope; cross to other modules via qualified TypeRefs.
    ast::TypeDefPtr follow_aliases(ast::TypeDefPtr def,
                                   const std::string& start_module) const {
        std::string scope = start_module;
        for (int depth = 0; depth < 64; ++depth) {
            if (!def) return nullptr;
            auto* tr = std::get_if<ast::TypeRef>(&def->body);
            if (!tr) return def;
            if (!tr->module_name.empty()) {
                auto mit = module_symbols_.find(tr->module_name);
                if (mit == module_symbols_.end()) return nullptr;
                auto sit = mit->second.find(tr->type_name);
                if (sit == mit->second.end()) return nullptr;
                def = sit->second;
                scope = tr->module_name;
                continue;
            }
            def = lookup_direct(tr->type_name, scope);
        }
        return nullptr;
    }

    // Look up a type in the context of from_module: per-module map already
    // contains own + imported symbols (built in resolve_imports), so no fallback
    // to global_ is needed — that flat map is unsafe under name collisions.
    ast::TypeDefPtr lookup_direct(const std::string& name,
                                  const std::string& from_module) const {
        auto rit = module_resolution_.find(from_module);
        if (rit != module_resolution_.end()) {
            auto sit = rit->second.find(name);
            if (sit != rit->second.end()) return sit->second;
        }
        // Last-resort fallback (e.g. when from_module unknown to resolver).
        auto it = global_.find(name);
        return it != global_.end() ? it->second : nullptr;
    }

    // Return the module name where `type_name` is defined as seen from `from_module`.
    // 1. Own module wins (locally-defined types shadow imports).
    // 2. Otherwise resolve through the importing module's IMPORTS (module_resolution_),
    //    so a name imported from one module isn't accidentally matched against a
    //    same-named type defined in some unrelated module.
    // 3. Last-resort: any module that defines the name (legacy fallback).
    std::string module_of(const std::string& type_name,
                          const std::string& from_module) const {
        auto own = module_symbols_.find(from_module);
        if (own != module_symbols_.end() && own->second.count(type_name))
            return from_module;
        auto rit = module_resolution_.find(from_module);
        if (rit != module_resolution_.end()) {
            auto sit = rit->second.find(type_name);
            if (sit != rit->second.end()) {
                // Walk all module_symbols_ to find which module owns the resolved def.
                for (const auto& [mod, syms] : module_symbols_) {
                    auto symit = syms.find(type_name);
                    if (symit != syms.end() && symit->second == sit->second)
                        return mod;
                }
            }
        }
        for (const auto& [mod, syms] : module_symbols_)
            if (syms.count(type_name)) return mod;
        return "";
    }

    // Look up a type in a specific module's symbol table (no chain following).
    ast::TypeDefPtr resolve_in_module(const std::string& type_name,
                                      const std::string& mod_name) const {
        auto mit = module_symbols_.find(mod_name);
        if (mit == module_symbols_.end()) return nullptr;
        auto sit = mit->second.find(type_name);
        return sit != mit->second.end() ? sit->second : nullptr;
    }

    // Fully resolve a TypeRef chain to the base TypeDef (follows aliases)
    ast::TypeDefPtr resolve_ref(const ast::TypeRef& ref) const {
        return resolve_ref(ref, /*from_module=*/{});
    }

    // Module-aware resolution: when the ref is unqualified, look up via the
    // importing module's IMPORTS so that name collisions across modules resolve
    // to the correct type (e.g. CivicAddress is CHOICE in UmtsHI2Operations
    // but SEQUENCE in TS33128Payloads).
    ast::TypeDefPtr resolve_ref(const ast::TypeRef& ref,
                                const std::string& from_module) const {
        // Qualified ref: look up directly in the named module's symbol table
        if (!ref.module_name.empty()) {
            auto mit = module_symbols_.find(ref.module_name);
            if (mit == module_symbols_.end()) return nullptr;
            auto sit = mit->second.find(ref.type_name);
            if (sit == mit->second.end()) return nullptr;
            return follow_aliases(sit->second, mit->first);
        }
        // Unqualified: prefer module-scoped lookup if from_module known.
        if (!from_module.empty()) {
            if (auto def = lookup_direct(ref.type_name, from_module))
                return follow_aliases(def, from_module);
        }
        // Fall back to global flat lookup (legacy path).
        auto name = ref.type_name;
        for (int depth = 0; depth < 64; ++depth) {
            auto it = global_.find(name);
            if (it == global_.end()) return nullptr;
            auto* tr = std::get_if<ast::TypeRef>(&it->second->body);
            if (!tr) return it->second;
            name = tr->type_name;
        }
        return nullptr; // circular
    }

private:
    // --- Tag-distinctness helpers ------------------------------------------------
    struct TagSet {
        using Key = std::pair<uint8_t /*TagClass*/, uint32_t /*tag number*/>;
        std::set<Key> concrete;
        bool open = false; // extensible CHOICE: unknown extension tags possible
        bool any  = false; // legacy ANY type (X.208): no fixed BER tag, clashes with all concrete tags
    };

    static const char* tag_class_str(uint8_t c) {
        switch (static_cast<ast::TagClass>(c)) {
        case ast::TagClass::Universal:   return "UNIVERSAL";
        case ast::TagClass::Application: return "APPLICATION";
        case ast::TagClass::Context:     return "CONTEXT";
        case ast::TagClass::Private:     return "PRIVATE";
        default:                         return "?";
        }
    }

    // X.680 Annex B.5 / asn1c asn1fix_compat.c — string type compatibility group.
    // KM  (group 1): IA5/Printable/Visible/Numeric/Universal/BMP + UTF8String.
    // NKM (group 2): General/Graphic/T61/Videotex/ObjectDescriptor.
    // Two strings are compatible iff they are in the same group.
    // Returns 0 for non-string types.
    static int string_group(ast::BuiltinType bt) {
        using B = ast::BuiltinType;
        switch (bt) {
        case B::Utf8String: case B::PrintableString: case B::VisibleString:
        case B::NumericString: case B::UniversalString: case B::BmpString:
        case B::Ia5String:
            return 1;
        case B::GeneralString: case B::GraphicString: case B::T61String:
        case B::VideotexString: case B::ObjectDescriptor:
            return 2;
        default:
            return 0;
        }
    }

    // Compute the set of BER tags visible at the outermost level for `def`.
    // For CHOICE (no outer tag): union of alternatives' visible tags.
    // For extensible CHOICE: also sets open=true (extension alternatives = any tag).
    // TypeRef: resolved before recursing so alias chains don't cause extra depth.
    TagSet tag_set_of(const ast::TypeDef& def, const std::string& from_module,
                      int depth) const {
        if (depth > 16) return {};
        // Explicit outer tag: decoder sees only this tag (IMPLICIT or EXPLICIT wrapper)
        if (def.tag.present()) {
            TagSet::Key k{static_cast<uint8_t>(def.tag.cls),
                          static_cast<uint32_t>(def.tag.number)};
            return {{k}, false, false};
        }
        // CHOICE: union of all alternatives' visible tags
        if (def.is_choice()) {
            TagSet result;
            for (const auto& m : def.members) {
                if (!m) continue;
                if (m->is_extension_marker) { result.open = true; continue; }
                auto sub = tag_set_of(*m, from_module, depth + 1);
                result.concrete.insert(sub.concrete.begin(), sub.concrete.end());
                if (sub.open) result.open = true;
                if (sub.any)  result.any  = true;
            }
            return result;
        }
        // TypeRef: resolve (follow_aliases inside resolve_ref) then check base
        if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
            auto base = resolve_ref(*tr, from_module);
            if (base && base.get() != &def)
                return tag_set_of(*base, from_module, depth + 1);
            return {};
        }
        // BuiltinType: natural UNIVERSAL tag
        if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
            uint8_t  u = static_cast<uint8_t>(ast::TagClass::Universal);
            uint32_t n = 0;
            using B = ast::BuiltinType;
            switch (*bt) {
            case B::Boolean:          n = 1;  break;
            case B::Integer:          n = 2;  break;
            case B::BitString:        n = 3;  break;
            case B::OctetString:      n = 4;  break;
            case B::Null:             n = 5;  break;
            case B::ObjectIdentifier: n = 6;  break;
            case B::ObjectDescriptor: n = 7;  break;
            case B::Real:             n = 9;  break;
            case B::Enumerated:       n = 10; break;
            case B::Utf8String:       n = 12; break;
            case B::RelativeOid:      n = 13; break;
            case B::NumericString:    n = 18; break;
            case B::PrintableString:  n = 19; break;
            case B::T61String:        n = 20; break;
            case B::VideotexString:   n = 21; break;
            case B::Ia5String:        n = 22; break;
            case B::UtcTime:          n = 23; break;
            case B::GeneralizedTime:  n = 24; break;
            case B::GraphicString:    n = 25; break;
            case B::VisibleString:    n = 26; break;
            case B::GeneralString:    n = 27; break;
            case B::UniversalString:  n = 28; break;
            case B::BmpString:        n = 30; break;
            case B::Any:              return {{}, false, true};  // ANY has no fixed BER tag (X.208 legacy)
            default: break;
            }
            if (n) return {{{u, n}}, false};
            return {};
        }
        // SEQUENCE / SEQUENCE OF → [UNIV 16]
        if (def.is_sequence() || def.is_seq_of())
            return {{{static_cast<uint8_t>(ast::TagClass::Universal), 16u}}, false};
        // SET / SET OF → [UNIV 17]
        if (def.is_set() || def.is_set_of())
            return {{{static_cast<uint8_t>(ast::TagClass::Universal), 17u}}, false};
        // INSTANCE OF → SEQUENCE encoding [UNIV 16]
        if (std::holds_alternative<ast::InstanceOfType>(def.body))
            return {{{static_cast<uint8_t>(ast::TagClass::Universal), 16u}}, false};
        return {};
    }
    // ----------------------------------------------------------------------------

    // in_parameterized: true when recursing inside a parameterized type body.
    // TypeRefs within parameterized types may name formal parameters, not module-level
    // types, so undefined-type checks are suppressed there.
    void check_and_resolve(const ast::TypeDefPtr& def, const std::string& mod_name,
                           bool in_parameterized = false) {
        if (!def) return;
        // Set in_parameterized for recursion into parameterized type bodies.
        if (def->is_parameterized) in_parameterized = true;
        // Undefined-type check: a TypeRef that names a type not defined in this module
        // and not brought in by any IMPORT is always an error (same as asn1c).
        // Inside a parameterized type body, TypeRefs may be formal parameters — skip.
        {
            if (auto* tr = std::get_if<ast::TypeRef>(&def->body)) {
                if (!in_parameterized && tr->module_name.empty() && !tr->type_name.empty()) {
                    const auto& tname = tr->type_name;
                    // Skip non-module-level names:
                    // - __COMPONENTS_OF__: synthetic parser placeholder
                    // - '.' or '&' in name: IOC field references (X.681)
                    // - X.680 §33-35 useful types + X.681 §14 built-in IOCs (always visible)
                    static const std::unordered_set<std::string> builtin_visible = {
                        "EXTERNAL", "EmbeddedPDV", "CharacterString",
                        "TYPE-IDENTIFIER", "ABSTRACT-SYNTAX",
                    };
                    bool skip = tname == "__COMPONENTS_OF__"
                        || tname.find('.') != std::string::npos
                        || tname.find('&') != std::string::npos
                        || builtin_visible.count(tname);
                    if (!skip && !module_visible_[mod_name].count(tname))
                        errors_.push_back("'" + tname + "' used in module '"
                            + mod_name + "' is not defined or imported");
                    // X.680 §24.1: COMPONENTS OF must reference a SEQUENCE or SET type.
                    if (tname == "__COMPONENTS_OF__" && !tr->params.empty()) {
                        const auto& param = tr->params[0];
                        auto base = follow_aliases(param, mod_name);
                        if (base && !base->is_sequence() && !base->is_set()) {
                            std::string ref_name;
                            if (auto* tr2 = std::get_if<ast::TypeRef>(&param->body))
                                ref_name = tr2->type_name;
                            if (ref_name.empty() && !base->name.empty())
                                ref_name = base->name;
                            if (ref_name.empty()) {
                                if (auto* bt2 = std::get_if<ast::BuiltinType>(&param->body))
                                    ref_name = builtin_type_name(*bt2);
                            }
                            if (ref_name.empty()) ref_name = "inline type";
                            errors_.push_back("COMPONENTS OF '" + ref_name
                                + "' is not a SEQUENCE or SET in module '" + mod_name + "'");
                        }
                    }
                }
                // Qualified ref (ModuleA.TypeFoo): warn if module not in compilation unit
                if (!tr->module_name.empty()
                        && module_symbols_.find(tr->module_name) == module_symbols_.end()) {
                    warnings_.push_back("qualified reference '" + tr->module_name + "."
                        + tr->type_name + "': module '" + tr->module_name + "' not found");
                }
            }
        }
        // X.680 §18.3 / §22.4: all identifiers and all numeric values in an INTEGER
        // named-number or BIT STRING named-bit list must be distinct.
        {
            auto* bt = std::get_if<ast::BuiltinType>(&def->body);
            if (bt && (*bt == ast::BuiltinType::Integer || *bt == ast::BuiltinType::BitString)
                    && !def->enum_values.empty()) {
                const char* kind = (*bt == ast::BuiltinType::Integer) ? "INTEGER" : "BIT STRING";
                std::string type_ctx = def->name.empty() ? "" : " '" + def->name + "'";
                std::unordered_set<std::string> seen_names;
                std::unordered_set<int64_t>     seen_nums;
                for (const auto& ev : def->enum_values) {
                    if (!seen_names.insert(ev.name).second)
                        errors_.push_back(std::string("duplicate identifier '") + ev.name
                            + "' in " + kind + " named-value list" + type_ctx
                            + " in module '" + mod_name + "'");
                    if (ev.number.has_value() && !seen_nums.insert(*ev.number).second)
                        errors_.push_back(std::string("duplicate numeric value ")
                            + std::to_string(*ev.number) + " in " + kind
                            + " named-value list" + type_ctx + " in module '" + mod_name + "'");
                }
            }
        }
        // X.680 §20: ENUMERATED — at most one extension marker; all identifiers and
        // all numeric values (auto-resolved) distinct; extension values in ascending order.
        {
            auto* bt = std::get_if<ast::BuiltinType>(&def->body);
            if (bt && *bt == ast::BuiltinType::Enumerated && !def->enum_values.empty()) {
                std::string type_ctx = def->name.empty() ? "" : " '" + def->name + "'";
                const auto& evs = def->enum_values;
                int n = static_cast<int>(evs.size());

                // Locate extension marker(s)
                int marker_count = 0, ext_start = n;
                for (int i = 0; i < n; ++i)
                    if (evs[i].name == "...") { ++marker_count; if (marker_count == 1) ext_start = i; }
                if (marker_count > 1)
                    errors_.push_back("more than one extension marker in ENUMERATED"
                                      + type_ctx + " in module '" + mod_name + "'");

                // Auto-assign numeric values: root phase (0,1,...), then extension phase
                // (max_root+1, ...). Explicit numbers override; next tracks the sequence.
                std::vector<int64_t> vals(n, 0);
                int64_t next = 0;
                for (int i = 0; i < ext_start; ++i) {
                    vals[i] = evs[i].number.value_or(next);
                    next = vals[i] + 1;
                }
                int64_t max_root = ext_start > 0
                    ? *std::max_element(vals.begin(), vals.begin() + ext_start)
                    : -1;
                next = max_root + 1;
                for (int i = ext_start + 1; i < n; ++i) {
                    if (evs[i].name == "...") continue;
                    vals[i] = evs[i].number.value_or(next);
                    next = vals[i] + 1;
                }

                // Duplicate identifier / duplicate numeric value
                std::unordered_set<std::string> seen_names;
                std::unordered_set<int64_t>     seen_vals;
                for (int i = 0; i < n; ++i) {
                    if (evs[i].name == "...") continue;
                    if (!seen_names.insert(evs[i].name).second)
                        errors_.push_back("duplicate identifier '" + evs[i].name
                                          + "' in ENUMERATED" + type_ctx
                                          + " in module '" + mod_name + "'");
                    if (!seen_vals.insert(vals[i]).second)
                        errors_.push_back("duplicate numeric value " + std::to_string(vals[i])
                                          + " in ENUMERATED" + type_ctx
                                          + " in module '" + mod_name + "'");
                }

                // Extension values must be in strictly ascending order (X.680 §20.6)
                if (ext_start < n) {
                    std::optional<int64_t> prev;
                    for (int i = ext_start + 1; i < n; ++i) {
                        if (evs[i].name == "...") continue;
                        if (prev && vals[i] <= *prev)
                            errors_.push_back("extension value '" + evs[i].name + "' ("
                                              + std::to_string(vals[i])
                                              + ") not in ascending order in ENUMERATED"
                                              + type_ctx + " in module '" + mod_name + "'");
                        prev = vals[i];
                    }
                }
            }
        }
        // X.680 §24.8 / §25.5: tag distinctness in SEQUENCE/SET/CHOICE.
        // Under AUTOMATIC TAGS, if no member carries an explicit tag,
        // auto-tagging assigns distinct context tags — skip in that case.
        if ((def->is_sequence() || def->is_set() || def->is_choice()) && !def->members.empty()) {
            auto td_it = module_tag_defaults_.find(mod_name);
            bool skip = td_it != module_tag_defaults_.end()
                     && td_it->second == ast::TagDefault::Automatic;
            if (skip) {
                for (const auto& m : def->members)
                    if (m && !m->is_extension_marker && m->tag.present()) { skip = false; break; }
            }
            if (!skip) {
                const char* kind = def->is_sequence() ? "SEQUENCE"
                                 : def->is_set()      ? "SET" : "CHOICE";
                std::string ctx = def->name.empty() ? "" : " '" + def->name + "'";
                const auto& mems = def->members;
                const int nm = static_cast<int>(mems.size());

                auto report_tag = [&](const TagSet::Key& tk) {
                    errors_.push_back("ambiguous tag ["
                        + std::string(tag_class_str(tk.first)) + " "
                        + std::to_string(tk.second) + "] in "
                        + kind + ctx + " in module '" + mod_name + "'");
                };
                auto report_open = [&]() {
                    errors_.push_back("ambiguous extensible CHOICE members in "
                        + std::string(kind) + ctx + " in module '" + mod_name + "'");
                };
                auto report_any = [&]() {
                    errors_.push_back("ANY tag conflict in "
                        + std::string(kind) + ctx + " in module '" + mod_name + "'");
                };

                // Compare two TagSets; report any collision.
                // ANY (any=true): no fixed BER tag — clashes with any concrete OPTIONAL member (X.208).
                auto compare_sets = [&](const TagSet& a, const TagSet& b) {
                    if (a.any || b.any) { report_any(); return; }
                    for (const auto& tk : a.concrete)
                        if (b.concrete.count(tk)) { report_tag(tk); return; }
                    if (a.open && b.open) { report_open(); return; }
                };

                if (def->is_sequence()) {
                    // SEQUENCE: mirrors asn1c's asn1f_check_constr_tags_distinct logic.
                    // Only OPTIONAL/DEFAULT members (not extension markers) enter the
                    // outer check. Inner loop stops after the first non-optional member
                    // (including extension markers, which act as mandatory delimiters).
                    for (int i = 0; i < nm; ++i) {
                        const auto& v = mems[i];
                        if (!v) continue;
                        if (!v->is_optional()) continue;  // only DEFAULT/OPTIONAL members
                        auto ts_v = tag_set_of(*v, mod_name, 0);

                        for (int j = i + 1; j < nm; ++j) {
                            const auto& nv = mems[j];
                            if (!nv) continue;
                            // Extension markers terminate the optional span; they carry
                            // no BER tag so there is nothing to compare.
                            if (!nv->is_extension_marker)
                                compare_sets(ts_v, tag_set_of(*nv, mod_name, 0));
                            if (!nv->is_optional()) break;
                        }
                    }
                } else {
                    // SET / CHOICE: compare every pair (i < j),
                    // skipping extension markers as the outer member v.
                    for (int i = 0; i < nm; ++i) {
                        const auto& v = mems[i];
                        if (!v || v->is_extension_marker) continue;
                        auto ts_v = tag_set_of(*v, mod_name, 0);
                        for (int j = i + 1; j < nm; ++j) {
                            const auto& nv = mems[j];
                            if (!nv || nv->is_extension_marker) continue;
                            auto ts_nv = tag_set_of(*nv, mod_name, 0);
                            compare_sets(ts_v, ts_nv);
                        }
                    }
                }
            }
        }
        // IMPLICIT tag on legacy ANY is meaningless: ANY encodes as a complete TLV whose tag
        // is determined at runtime; stripping it via IMPLICIT leaves an undecodable structure.
        // ANY is a deprecated X.208 type; X.680 §30.8 governs X.681 open types, but the
        // practical prohibition is identical.  asn1c rejects this with a fatal error.
        if (def->tag.present() && def->tag.mode == ast::TagMode::Implicit) {
            auto base = follow_aliases(def, mod_name);
            if (base) {
                auto* bt = std::get_if<ast::BuiltinType>(&base->body);
                if (bt && *bt == ast::BuiltinType::Any)
                    errors_.push_back("IMPLICIT tag on ANY '"
                        + def->name + "' in module '" + mod_name + "'");
            }
        }
        // X.680 §24.11: the DEFAULT value "shall be a value notation for a value of
        // the type defined by 'Type'".  This fires when a NamedValueRef DEFAULT
        // resolves to a type incompatible with the member's type.
        // String compatibility per Annex B.5 (see string_group()); all other builtin
        // type mismatches are unconditionally incompatible per §24.11.
        if (def->has_default()) {
            if (auto* nvr = std::get_if<ast::NamedValueRef>(&def->default_value)) {
                if (!nvr->name.empty()) {
                    // Value assignments are stored in the same symbol table as types
                    // (module_resolution_ holds own + imported symbols).
                    auto val_def = lookup_direct(nvr->name, mod_name);
                    if (val_def) {
                        auto member_base = follow_aliases(def, mod_name);
                        auto val_base    = follow_aliases(val_def, mod_name);
                        if (member_base && val_base) {
                            auto* mb = std::get_if<ast::BuiltinType>(&member_base->body);
                            auto* vb = std::get_if<ast::BuiltinType>(&val_base->body);
                            // X.680 §24.11 + Annex B: same builtin type → always
                            // compatible (e.g. INTEGER aliases per B.4.5, same string
                            // type per B.5).  Only cross-type mismatches need checking.
                            if (mb && vb && *mb != *vb) {
                                int gm = string_group(*mb);
                                int gv = string_group(*vb);
                                // String member: error only when value is from a different
                                // string group (Annex B.5 allows cross-type within same group).
                                // Non-string member: any builtin mismatch is an error (§24.11).
                                bool incompatible = (gm != 0) ? (gm != gv) : true;
                                if (incompatible)
                                    errors_.push_back("DEFAULT value '" + nvr->name
                                        + "' type incompatible with member '"
                                        + def->name + "' in module '" + mod_name + "'");
                            }
                        }
                    }
                }
            }
        }
        // Recurse into SEQUENCE/SET/CHOICE members
        for (auto& member : def->members)
            check_and_resolve(member, mod_name, in_parameterized);
        // Recurse into SEQUENCE OF / SET OF element
        if (auto* sof = std::get_if<ast::SequenceOfType>(&def->body))
            check_and_resolve(sof->element, mod_name, in_parameterized);
        if (auto* sof = std::get_if<ast::SetOfType>(&def->body))
            check_and_resolve(sof->element, mod_name, in_parameterized);
    }
};

} // namespace asn1::sema
