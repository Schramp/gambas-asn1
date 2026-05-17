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
    bool operator==(const EnumValue& o) const { return value_ == o.value_; }
    bool operator!=(const EnumValue& o) const { return value_ != o.value_; }
};

} // namespace asn1
