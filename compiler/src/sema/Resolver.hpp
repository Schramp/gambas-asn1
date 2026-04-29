#pragma once
#include <algorithm>
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
    // Per-module visible names: own symbols + explicitly imported names
    std::unordered_map<std::string, std::unordered_set<std::string>> module_visible_;
    // Flat global table for codegen lookups (all resolvable symbols)
    SymbolTable global_;

    bool ignore_missing_modules_{false};
    std::vector<std::string> errors_;
    std::vector<std::string> warnings_;

public:
    void set_ignore_missing_modules(bool v) { ignore_missing_modules_ = v; }
    const std::vector<std::string>& errors()   const { return errors_; }
    const std::vector<std::string>& warnings() const { return warnings_; }

    // Phase 1: collect all top-level definitions from all modules
    void collect(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules) {
            SymbolTable& tbl = module_symbols_[mod->name];
            for (const auto& def : mod->assignments) {
                if (!def->name.empty())
                    tbl[def->name] = def;
            }
        }
    }

    // Phase 2: resolve cross-module imports
    // Builds module_visible_ (scoped) and global_ (for codegen)
    void resolve_imports(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules) {
            auto& vis = module_visible_[mod->name];

            // Every module can see its own symbols
            for (auto& [name, def] : module_symbols_[mod->name]) {
                global_[name] = def;
                vis.insert(name);
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
                    bool ok = oids_match(imp.module_oid, src_mod->oid);
                    if (!ok) {
                        using VP = ast::ImportVersionPolicy;
                        if (imp.version_policy == VP::Successors) {
                            // Accept if all arcs match except last, and last arc of
                            // actual module is >= last arc of import
                            ok = oids_match_successors(imp.module_oid, src_mod->oid);
                        } else if (imp.version_policy == VP::Descendants) {
                            // Accept if actual OID starts with import OID prefix
                            ok = oids_match_descendants(imp.module_oid, src_mod->oid);
                        }
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

    // Fully resolve a TypeRef chain to the base TypeDef (follows aliases)
    ast::TypeDefPtr resolve_ref(const ast::TypeRef& ref) const {
        // Qualified ref: look up directly in the named module's symbol table
        if (!ref.module_name.empty()) {
            auto mit = module_symbols_.find(ref.module_name);
            if (mit == module_symbols_.end()) return nullptr;
            auto sit = mit->second.find(ref.type_name);
            return sit != mit->second.end() ? sit->second : nullptr;
        }
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
