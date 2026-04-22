#pragma once
#include <variant>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace asn1::ast {

struct NamedValueRef { std::string module_name; std::string name; };

struct OidValue {
    struct Arc { std::string name; int64_t number{-1}; };
    std::vector<Arc> arcs;
};

using Value = std::variant<
    std::monostate,        // absent / not set
    int64_t,               // integer or enumerated literal
    double,                // real literal
    bool,                  // TRUE / FALSE
    std::string,           // cstring or identifier value
    OidValue,              // OID value
    NamedValueRef          // DefinedValue (reference resolved later)
>;

} // namespace asn1::ast
