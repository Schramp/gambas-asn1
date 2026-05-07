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

// VisibleString / IA5String safe randgen subset.
// Full type permits 0x20..0x7E (VisibleString) / 0x00..0x7F (IA5String), but
// XER serialisation needs character escaping for `< > & " '` and we don't yet
// emit/parse XML entities round-trip-cleanly. Until XerCodec gains entity
// escape, randgen sticks to PrintableString-safe subset (no XML specials);
// validate() also accepts only this subset for those tags so generated
// content roundtrips.
//
// TODO(XER-entity-escape): XerCodec must emit `&lt; &gt; &amp; &quot; &apos;`
// when encoding string content and resolve them on decode. After that lands,
// expand this alphabet back to full 0x20..0x7E and update validate() to
// match.
inline constexpr std::string_view VISIBLE_STRING_ALPHABET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 ()+,-./:=?";

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
