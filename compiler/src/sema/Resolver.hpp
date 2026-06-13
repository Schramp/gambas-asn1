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

    bool ignore_missing_modules_{false};
    bool allow_newer_modules_{false};
    std::vector<std::string> errors_;
    std::vector<std::string> warnings_;

public:
    void set_ignore_missing_modules(bool v) { ignore_missing_modules_ = v; }
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
                auto it = module_symbols_.find(imp.from_module);
                if (it == module_symbols_.end()) {
                    std::string msg = "module '" + imp.from_module
                        + "' imported by '" + mod->name + "' was not found";
                    if (ignore_missing_modules_)
                        warnings_.push_back(msg);
                    else
                        errors_.push_back(msg);
                    continue;
                }
                // If import specifies an OID, verify it matches the source module's OID
                const auto& src_mod = *std::find_if(
                    pr.modules.begin(), pr.modules.end(),
                    [&](const auto& m){ return m->name == imp.from_module; });

                if (!imp.module_oid.arcs.empty() && !src_mod->oid.arcs.empty()) {
                    bool oid_accepted = false;

                    // -fallow-newer-modules: version-aware matching (overrides WITH SUCCESSORS too)
                    using VP = ast::ImportVersionPolicy;
                    bool use_newer = allow_newer_modules_
                        && (imp.version_policy == VP::Exact
                            || imp.version_policy == VP::Successors);
                    if (use_newer) {
                        int vcmp = oid_version_compare(imp.module_oid, src_mod->oid);
                        if (vcmp == 0) {
                            oid_accepted = true;  // exact — silent
                        } else if (vcmp == -1) {
                            warnings_.push_back("module '" + imp.from_module
                                + "': available OID is newer than imported OID;"
                                  " accepting (-fallow-newer-modules)");
                            oid_accepted = true;
                        } else if (vcmp == 2) {
                            warnings_.push_back("module '" + imp.from_module
                                + "': imported OID is a base prefix of available OID;"
                                  " accepting (-fallow-newer-modules)");
                            oid_accepted = true;
                        } else if (vcmp == 1) {
                            errors_.push_back("module '" + imp.from_module
                                + "': available OID is older than imported OID");
                            continue;
                        }
                        // INT_MIN: unrelated family — fall through to normal check
                    }

                    if (!oid_accepted) {
                        bool ok = oids_match(imp.module_oid, src_mod->oid);
                        if (!ok) {
                            if (imp.version_policy == VP::Successors) {
                                ok = oids_match_successors(imp.module_oid, src_mod->oid);
                            } else if (imp.version_policy == VP::Descendants) {
                                ok = oids_match_descendants(imp.module_oid, src_mod->oid);
                            }
                            // Implicit: import OID is a prefix of module OID (ETSI versioning)
                            if (!ok)
                                ok = oids_match_descendants(imp.module_oid, src_mod->oid);
                        }
                        if (!ok) {
                            errors_.push_back("module '" + imp.from_module
                                + "' OID mismatch: import specifies "
                                + oid_to_string(imp.module_oid)
                                + " but module defines "
                                + oid_to_string(src_mod->oid));
                            continue;
                        }
                    }
                }

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
    // Visibility check is skipped when ignore_missing_modules_ is set because
    // we cannot determine which names come from unresolved imports.
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
    };

    static const char* tag_class_str(uint8_t c) {
        switch (static_cast<ast::TagClass>(c)) {
        case ast::TagClass::Universal:   return "UNIV";
        case ast::TagClass::Application: return "APPLICATION";
        case ast::TagClass::Context:     return "CONTEXT";
        case ast::TagClass::Private:     return "PRIVATE";
        default:                         return "?";
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
            return {{k}, false};
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
            case B::Any:              return {{{u, 4u}}, true}; // ANY = open
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

    void check_and_resolve(const ast::TypeDefPtr& def, const std::string& mod_name) {
        if (!def) return;
        // Check unqualified TypeRef visibility (only when all modules are available)
        if (!ignore_missing_modules_) {
            if (auto* tr = std::get_if<ast::TypeRef>(&def->body)) {
                if (tr->module_name.empty() && !tr->type_name.empty()) {
                    auto& vis = module_visible_[mod_name];
                    if (vis.find(tr->type_name) == vis.end()) {
                        errors_.push_back("'" + tr->type_name + "' used in module '"
                            + mod_name + "' is not defined or imported");
                    }
                }
                // Qualified ref (ModuleA.TypeFoo): verify module exists
                if (!tr->module_name.empty()) {
                    if (module_symbols_.find(tr->module_name) == module_symbols_.end() &&
                        !ignore_missing_modules_) {
                        errors_.push_back("qualified reference '" + tr->module_name + "."
                            + tr->type_name + "': module '" + tr->module_name + "' not found");
                    }
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

                // Compare two TagSets; report any collision.
                auto compare_sets = [&](const TagSet& a, const TagSet& b) {
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
                            auto ts_nv = nv->is_extension_marker
                                ? TagSet{{}, false}  // extension marker: no concrete tags
                                : tag_set_of(*nv, mod_name, 0);
                            compare_sets(ts_v, ts_nv);
                            // Stop after first non-optional (mandatory or extension marker)
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
        // Recurse into SEQUENCE/SET/CHOICE members
        for (auto& member : def->members)
            check_and_resolve(member, mod_name);
        // Recurse into SEQUENCE OF / SET OF element
        if (auto* sof = std::get_if<ast::SequenceOfType>(&def->body))
            check_and_resolve(sof->element, mod_name);
        if (auto* sof = std::get_if<ast::SetOfType>(&def->body))
            check_and_resolve(sof->element, mod_name);
    }
};

} // namespace asn1::sema
