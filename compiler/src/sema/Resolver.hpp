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
                // Check EXPORTS restriction of source module
                const auto& src_mod = *std::find_if(
                    pr.modules.begin(), pr.modules.end(),
                    [&](const auto& m){ return m->name == imp.from_module; });
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
