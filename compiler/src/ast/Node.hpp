#pragma once
#include <string>
#include <cstdint>

namespace asn1::ast {

struct SourceLocation {
    std::string filename;
    int line{0};
};

// Base for all AST nodes — carries source location.
struct Node {
    SourceLocation loc;
    virtual ~Node() = default;
};

} // namespace asn1::ast
