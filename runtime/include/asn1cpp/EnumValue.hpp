#pragma once
#include "Asn1Object.hpp"

namespace asn1 {

// Base class for all generated ENUMERATED types.
// Generated code emits: class MyEnum : public asn1::EnumValue { enum Enm : long {...}; ... };
class EnumValue : public Asn1Object {
protected:
    long value_ = 0;
public:
    long value() const { return value_; }
    void set(long v)   { value_ = v; }
    /// @brief Compare two ENUMERATED values by their numeric value.
    /// @return true when both hold the same value.
    /// A hidden friend rather than a member: with a member, C++20's reversed
    /// candidate for `Derived == Derived` needs the same derived-to-base
    /// conversions as the normal one, which clang reports as ambiguous.
    /// operator!= is rewritten from this one (C++20 [over.match.oper]).
    friend bool operator==(const EnumValue& a, const EnumValue& b) { return a.value_ == b.value_; }
};

} // namespace asn1
