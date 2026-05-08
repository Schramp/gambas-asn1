#pragma once
#include <cstdint>
#include <string_view>
#include "../Tag.hpp"

namespace asn1 {

// Canonical alphabets for restricted ASN.1 string types (X.680 §41).
// Single source of truth — used by PerCodec (canonical bit-index encoding),
// RandomFiller (pick chars from a valid set), and validate() (reject strings
// containing bytes outside the permitted set).
//
// FROM constraints (PerConstraints::alphabet) override these by narrowing
// further; an empty FROM constraint means "use the type's built-in alphabet".

// PrintableString (X.680 Table 8): 74 chars, sorted lexicographically — order
// matters for PER canonical encoding (asn1c PrintableString.c uses the same
// sequence; PerCodec maps each char to its index in this string).
inline constexpr std::string_view PRINTABLE_STRING_ALPHABET =
    " '()+,-./"
    "0123456789"
    ":=?"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

// NumericString (X.680 §41.2): digits 0..9 plus space.
inline constexpr std::string_view NUMERIC_STRING_ALPHABET =
    "0123456789 ";

// VisibleString / IA5String alphabet — full 0x20..0x7E (VisibleString range).
// IA5String permits 0x00..0x7F but randgen sticks to printable subset since
// control chars round-trip-trip differently in XER. XerCodec now escapes
// `< > &` on encode and resolves named + numeric entities on decode, so the
// XML specials are safe in randomly generated content.
inline constexpr std::string_view VISIBLE_STRING_ALPHABET =
    " !\"#$%&'()*+,-./"
    "0123456789:;<=>?@"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}~";

// Default alphabet for unrestricted string types (Utf8/BMP/General/...) when
// neither a FROM constraint nor a per-type built-in alphabet applies. Used by
// RandomFiller as the safe fallback so generated content is always printable.
inline constexpr std::string_view DEFAULT_STRING_ALPHABET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

// Returns the built-in permitted alphabet for a universal-tag string type,
// or empty when the type has no fixed alphabet (Utf8String, BMPString, etc.)
// and any byte sequence is legal. Use DEFAULT_STRING_ALPHABET as the picker
// fallback when this returns empty.
inline std::string_view builtin_alphabet(uint32_t universal_tag) {
    switch (universal_tag) {
    case UniversalTag::NumericString:   return NUMERIC_STRING_ALPHABET;
    case UniversalTag::PrintableString: return PRINTABLE_STRING_ALPHABET;
    case UniversalTag::VisibleString:
    case UniversalTag::Ia5String:       return VISIBLE_STRING_ALPHABET;
    default:                            return {};
    }
}

} // namespace asn1
