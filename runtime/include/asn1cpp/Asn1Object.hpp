#pragma once

namespace asn1 {

/// @brief Non-virtual marker base for every runtime ASN.1 type and every generated struct.
///
/// Allows codec handlers to hold \c Asn1Object* instead of \c void*, making all
/// downcasts \c static_cast (proper inheritance) rather than \c reinterpret_cast.
///
/// Every generated type inherits from \c Asn1Object, as do all runtime primitive
/// types (\c Integer, \c OctetString, etc.).  Zero overhead — no data members,
/// no virtual functions.
///
/// Example — CHOICE alternative access (generated code pattern):
/// @code
/// const Asn1Object* alt = desc.get_const_fn(choice_ptr);
/// const MyAlt& typed = *static_cast<const MyAlt*>(alt);
/// @endcode
///
/// @see TypeDescriptor — holds the \c asn_DEF static member for each type.
class Asn1Object {
public:
    bool operator==(const Asn1Object&) const = default;
};

} // namespace asn1
