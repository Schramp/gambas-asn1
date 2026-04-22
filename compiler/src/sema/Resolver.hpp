#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"

namespace asn1::sema {

// SymbolTable maps (module_name, type_name) -> TypeDefPtr
using SymbolTable = std::unordered_map<std::string, ast::TypeDefPtr>;

class Resolver {
    // Per-module export tables: module_name -> set of exported names
    std::unordered_map<std::string, SymbolTable> module_symbols_;
    // Flat global table after import resolution
    SymbolTable global_;

public:
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

    // Phase 2: resolve cross-module imports (populate global_ with everything)
    void resolve_imports(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules) {
            // Every module can see its own symbols
            for (auto& [name, def] : module_symbols_[mod->name])
                global_[name] = def;

            // Bring in imports
            for (const auto& imp : mod->imports) {
                auto it = module_symbols_.find(imp.from_module);
                if (it == module_symbols_.end()) continue; // ignore missing modules
                for (const auto& imported_name : imp.names) {
                    auto sym = it->second.find(imported_name);
                    if (sym != it->second.end())
                        global_[imported_name] = sym->second;
                }
            }
        }
    }

    // Phase 3: walk all TypeDef trees and resolve A1TC_REFERENCE nodes
    void resolve_types(const ast::ParseResult& pr) {
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                resolve_def(def);
    }

    // Look up a type by name (returns nullptr if not found)
    ast::TypeDefPtr lookup(const std::string& name) const {
        auto it = global_.find(name);
        return it != global_.end() ? it->second : nullptr;
    }

    // Fully resolve a TypeRef chain to the base TypeDef (follows aliases)
    ast::TypeDefPtr resolve_ref(const ast::TypeRef& ref) const {
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
    void resolve_def(const ast::TypeDefPtr& def) {
        if (!def) return;
        // Resolve SEQUENCE/SET/CHOICE members
        for (auto& member : def->members)
            resolve_def(member);
        // Resolve SEQUENCE OF / SET OF element
        if (auto* sof = std::get_if<ast::SequenceOfType>(&def->body))
            resolve_def(sof->element);
        if (auto* sof = std::get_if<ast::SetOfType>(&def->body))
            resolve_def(sof->element);
    }
};

} // namespace asn1::sema
