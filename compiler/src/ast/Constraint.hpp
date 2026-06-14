#pragma once
#include <variant>
#include <vector>
#include <memory>
#include <optional>
#include <string>
#include "Value.hpp"

namespace asn1::ast {

struct Constraint;
using ConstraintPtr = std::shared_ptr<Constraint>;

struct RangeEndpoint {
    enum class Kind { Min, Max, Value } kind{Kind::Value};
    Value value;
};

struct ValueRange {
    RangeEndpoint lower;
    RangeEndpoint upper;
};

struct SizeConstraint  { ConstraintPtr inner; };
struct FromConstraint  { ConstraintPtr inner; };
struct WithComponent   { ConstraintPtr inner; };
struct PatternConstraint { std::string pattern; };
struct ContentsConstraint { std::string type_ref; };
struct ExtensionMarker {};

struct IntersectionConstraint {
    std::vector<ConstraintPtr> operands;
    bool serial{false}; // true when built from serial (A)(B) syntax, not explicit A ^ B
};
struct UnionConstraint {
    std::vector<ConstraintPtr> operands;
};
struct ExceptionConstraint {
    Value value;
};

struct TableConstraint {
    std::string object_set;
    std::vector<std::string> at_notation;
};

using ConstraintBody = std::variant<
    std::monostate,
    ValueRange,
    Value,           // Single value
    SizeConstraint,
    FromConstraint,
    WithComponent,
    PatternConstraint,
    ContentsConstraint,
    ExtensionMarker,
    IntersectionConstraint,
    UnionConstraint,
    ExceptionConstraint,
    TableConstraint
>;

struct Constraint {
    ConstraintBody body;
    bool extensible{false};         // trailing ...
    std::optional<Value> exception; // EXCEPT clause
};

} // namespace asn1::ast
