#pragma once
// Per-type runtime constraint validator.
//
// Single entry point that dispatches on def.tag / def.enum_spec /
// def.seq_of_spec to the per-primitive validate() methods. Used by
// RandomFiller (retry on invalid) and BerCodec (fail-soft warn).
//
// Composite types (SEQUENCE / SET / CHOICE) return true here — caller
// recurses into members via the descriptor table when that is desired.
//
// Returns 0 when valid (or no constraint to check), otherwise a signed
// delta such that (current_value + delta) lands at the nearest valid bound:
//   +delta — value/size below lower bound; raise sampling min by delta.
//   -delta — value/size above upper bound; lower sampling max by |delta|.
// Units:
//   - INTEGER:        units = value.
//   - OCTET / BIT / strings / SEQ-OF: units = bytes / bits / chars / elements.
//   - ENUMERATED:     1 when value is unknown, 0 otherwise (no metric).
//
// EXTENSIBLE constraints always return 0 — extension space is open.
// Composite types (SEQUENCE / SET / CHOICE) return 0; the caller is
// expected to walk members itself when desired.

#include "TypeDescriptor.hpp"
#include "types/Integer.hpp"
#include "types/OctetString.hpp"
#include "types/BitString.hpp"
#include "types/Strings.hpp"

namespace asn1 {

inline int64_t validate(const TypeDescriptor& def, const void* obj) {
    if (def.enum_spec)
        return def.enum_spec->validate(*static_cast<const long*>(obj));
    if (def.seq_of_spec)
        return def.seq_of_spec->validate(*static_cast<const SeqOfBase*>(obj));

    if (def.tag.cls != TagClass::Universal) return 0;

    const auto& c = def.constraints;
    switch (def.tag.number) {
    case UniversalTag::Integer:
        if (c.int_kind == Constraints::INT_U64)
            return static_cast<const UInteger*>(obj)->validate(c);
        return static_cast<const Integer*>(obj)->validate(c);
    case UniversalTag::OctetString:
        return static_cast<const OctetString*>(obj)->validate(c);
    case UniversalTag::BitString:
        return static_cast<const BitString*>(obj)->validate(c);
    case UniversalTag::Utf8String:
        return static_cast<const Utf8String*>(obj)->validate(c);
    case UniversalTag::NumericString:
        return static_cast<const NumericString*>(obj)->validate(c);
    case UniversalTag::PrintableString:
        return static_cast<const PrintableString*>(obj)->validate(c);
    case UniversalTag::T61String:
        return static_cast<const T61String*>(obj)->validate(c);
    case UniversalTag::VideotexString:
        return static_cast<const VideotexString*>(obj)->validate(c);
    case UniversalTag::Ia5String:
        return static_cast<const Ia5String*>(obj)->validate(c);
    case UniversalTag::GraphicString:
        return static_cast<const GraphicString*>(obj)->validate(c);
    case UniversalTag::VisibleString:
        return static_cast<const VisibleString*>(obj)->validate(c);
    case UniversalTag::GeneralString:
        return static_cast<const GeneralString*>(obj)->validate(c);
    case UniversalTag::UniversalString:
        return static_cast<const UniversalString*>(obj)->validate(c);
    case UniversalTag::BmpString:
        return static_cast<const BmpString*>(obj)->validate(c);
    case UniversalTag::ObjectDescriptor:
        return static_cast<const ObjectDescriptor*>(obj)->validate(c);
    default:
        return 0;
    }
}

} // namespace asn1
