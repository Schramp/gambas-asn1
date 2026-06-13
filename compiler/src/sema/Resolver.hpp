#pragma once
#include <algorithm>
#include <climits>
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
