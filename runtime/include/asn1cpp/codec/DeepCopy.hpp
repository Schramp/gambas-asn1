#pragma once
#include <asn1cpp/TypeDescriptor.hpp>
#include <asn1cpp/Asn1Object.hpp>

namespace asn1 {

// Deep-copy src into dst using the type's descriptor tables.
// Both src and dst must point to a live, fully-constructed T (default-constructed is fine).
// Dispatches by TypeDescriptor::kind — no virtual calls on generated types.
//
/// @brief Copy \p src into \p dst by walking \p def's tables, the copy
///        behind every generated copy constructor and copy assignment.
///
/// SEQUENCE: copies each member field-by-field; optional members are set/cleared to match src.
/// CHOICE:   selects src's alternative in dst with emplace_alt, then recursively copies it.
/// SEQOF:    resizes dst to match src count, recursively copies each element.
/// Primitive / ENUMERATED / leaf: destroy-then-clone (placement-new copy from src).
/// @param def  Type descriptor shared by \p dst and \p src.
/// @param dst  Destination value.
/// @param src  Source value.
void deep_copy(const TypeDescriptor& def, Asn1Object* dst, const Asn1Object* src);

} // namespace asn1
