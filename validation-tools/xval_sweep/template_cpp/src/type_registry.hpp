#pragma once
#include <asn1cpp/asn1cpp.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace randgen {

// Typed handle: all generated types inherit Asn1Object, so ~T() runs correctly
// and the pointer is directly usable as Asn1Object*.
using ObjHandle = std::shared_ptr<asn1::Asn1Object>;

struct TypeEntry {
    std::string name;
    const asn1::TypeDescriptor* def;
    std::function<ObjHandle()> make;  // heap-allocate T{}, return as void handle
};

template<typename T>
TypeEntry make_entry(const char* name, const asn1::TypeDescriptor& def) {
    return {
        name,
        &def,
        []() -> ObjHandle { return std::make_shared<T>(); },
    };
}

std::vector<TypeEntry>& global_registry();
void register_types(std::vector<TypeEntry> entries);
const TypeEntry* find_type(const std::string& name);
void list_types();

} // namespace randgen
