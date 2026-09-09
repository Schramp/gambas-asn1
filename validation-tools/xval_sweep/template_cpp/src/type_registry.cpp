#include "type_registry.hpp"

namespace randgen {

std::vector<TypeEntry>& global_registry() {
    static std::vector<TypeEntry> reg;
    return reg;
}

void register_types(std::vector<TypeEntry> entries) {
    auto& reg = global_registry();
    for (auto& e : entries)
        reg.push_back(std::move(e));
}

const TypeEntry* find_type(const std::string& name) {
    for (const auto& e : global_registry())
        if (e.name == name) return &e;
    return nullptr;
}

void list_types() {
    for (const auto& e : global_registry())
        fprintf(stderr, "  %s\n", e.name.c_str());
}

} // namespace randgen
