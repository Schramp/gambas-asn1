#pragma once
#include <asn1cpp/TypeDescriptor.hpp>
#include <asn1cpp/Asn1Object.hpp>

namespace asn1 {

// Deep-copy src into dst using the type's descriptor tables.
// Both src and dst must point to a live, fully-constructed T (default-constructed is fine).
// Dispatches by TypeDescriptor::kind — no virtual calls on generated types.
//
// SEQUENCE: copies each member field-by-field; optional members are set/cleared to match src.
// CHOICE:   destroys dst's current arm, constructs + recursively copies src's active arm.
// SEQOF:    resizes dst to match src count, recursively copies each element.
// Primitive / ENUMERATED / leaf: destroy-then-clone (placement-new copy from src).
void deep_copy(const TypeDescriptor& def, Asn1Object* dst, const Asn1Object* src);

} // namespace asn1
