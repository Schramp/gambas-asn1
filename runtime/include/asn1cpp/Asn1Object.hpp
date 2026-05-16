#pragma once

namespace asn1 {

// Non-virtual marker base for every runtime ASN.1 type and every generated struct.
// Allows codec handlers to hold Asn1Object* instead of void*, making all downcasts
// static_cast (proper inheritance downcast) rather than reinterpret_cast.
// Zero overhead: no data members, no virtual functions.
class Asn1Object {
public:
    bool operator==(const Asn1Object&) const = default;
};

} // namespace asn1
