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
    bool open{false};  // X.680 §47.4.3: "<" excludes the endpoint value itself
};

struct ValueRange {
    RangeEndpoint lower;
    RangeEndpoint upper;
};

struct SizeConstraint  { ConstraintPtr inner; };
struct FromConstraint  { ConstraintPtr inner; };
struct WithComponent   { ConstraintPtr inner; };
struct PatternConstraint { std::string pattern; };
struct TypeDef;
/// X.682 §11 contents constraint. `type` is null for the bare
/// `ENCODED BY` form; `encoded_by` is the OID value's source text
/// (empty when absent, i.e. the outer encoding rules apply, §11.4).
struct ContentsConstraint {
    std::shared_ptr<TypeDef> type;
    std::string encoded_by;
};
struct ExtensionMarker {};

struct IntersectionConstraint {
    std::vector<ConstraintPtr> operands;
    // X.680 §47.4: serial (A)(B) constraints form a narrowing chain; each must be
    // a subset of the preceding. Explicit intersection (A ^ B, X.680 §46.3) does not.
    bool serial{false};
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
