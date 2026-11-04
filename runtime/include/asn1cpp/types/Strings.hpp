#pragma once
#include <string>
#include <string_view>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"
#include "../codec/Alphabets.hpp"

namespace asn1 {

/// @brief Non-virtual base for all \c AsnString<N> types.
///
/// Codec handlers upcast to \c AsnStringBase* via static_cast (safe by inheritance) —
/// no layout assumptions or \c reinterpret_cast needed.
/// Holds a single \c std::string regardless of the ASN.1 string type.
class AsnStringBase : public Asn1Object {
    std::string value_;
public:
    AsnStringBase() = default;
    explicit AsnStringBase(std::string s) : value_(std::move(s)) {}

    /// @brief Access the string contents.
    const std::string& str() const { return value_; }
    /// @brief Mutable access to the string contents.
    std::string& str()             { return value_; }

    bool operator==(const AsnStringBase&) const = default;
};

/// @brief Calls \p f with each character's code point of a stored string value, in order.
///
/// Stored bytes are the string type's own encoding: UTF-8 for UTF8String,
/// UCS-2 big-endian for BMPString, UCS-4 big-endian for UniversalString,
/// one byte per character otherwise. A malformed UTF-8 byte counts as one
/// character; trailing bytes of an incomplete wide unit are not a character.
/// Shared by \c AsnString::validate and the PER codec's constraint checks.
/// @param tag  Universal tag number of the string type (\c UniversalTag::).
/// @param s    Stored string bytes.
/// @param f    Called as \c f(uint32_t code_point).
/// @see X.680 §41 — character string types and their character sets.
template<typename F>
void for_each_code_point(uint32_t tag, std::string_view s, F&& f) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const std::size_t n = s.size();
    if (tag == UniversalTag::BmpString || tag == UniversalTag::UniversalString) {
        const std::size_t w = tag == UniversalTag::BmpString ? 2 : 4;
        for (std::size_t i = 0; i + w <= n; i += w) {
            uint32_t cp = 0;
            for (std::size_t b = 0; b < w; ++b) cp = (cp << 8) | p[i + b];
            f(cp);
        }
    } else if (tag == UniversalTag::Utf8String) {
        for (std::size_t i = 0; i < n;) {
            const unsigned char lead = p[i];
            std::size_t len = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2
                            : (lead >> 4) == 0xE ? 3 : (lead >> 3) == 0x1E ? 4 : 1;
            if (i + len > n) len = 1;
            for (std::size_t b = 1; b < len; ++b)
                if ((p[i + b] & 0xC0) != 0x80) { len = 1; break; }
            uint32_t cp = len == 1 ? lead : lead & (0x7F >> len);
            for (std::size_t b = 1; b < len; ++b) cp = (cp << 6) | (p[i + b] & 0x3F);
            f(cp);
            i += len;
        }
    } else {
        for (std::size_t i = 0; i < n; ++i) f(static_cast<uint32_t>(p[i]));
    }
}

/// @brief Number of characters in a stored string value, as SIZE constraints count them.
/// @param tag  Universal tag number of the string type (\c UniversalTag::).
/// @param s    Stored string bytes.
/// @return Character count; equals \c s.size() for the one-byte-per-character kinds.
/// @see X.680 §51.5 — SizeConstraint counts characters of a character string.
inline std::size_t string_char_count(uint32_t tag, std::string_view s) {
    if (tag != UniversalTag::BmpString && tag != UniversalTag::UniversalString &&
        tag != UniversalTag::Utf8String)
        return s.size();
    std::size_t count = 0;
    for_each_code_point(tag, s, [&](uint32_t) { ++count; });
    return count;
}

/// @brief Thin per-tag ASN.1 string wrapper — tag number \c N selects the BER
/// universal tag and the built-in alphabet for constraint validation.
///
/// Named aliases (\c Utf8String, \c Ia5String, etc.) are defined below.
/// Access the string contents via the inherited \c str() method.
///
/// @tparam TagNumber  Universal tag number from \c UniversalTag::.
/// @see X.680 §40–50 — string type definitions; X.690 §8.21 — BER string encoding.
template<uint32_t TagNumber>
class AsnString : public AsnStringBase {
public:
    AsnString() = default;
    explicit AsnString(std::string s) : AsnStringBase(std::move(s)) {}
    AsnString(const char* s) : AsnStringBase(std::string(s)) {}

    /// @brief True if the string is empty.
    bool empty() const { return str().empty(); }
    /// @brief Number of stored bytes; see \c char_count() for characters.
    std::size_t size() const { return str().size(); }

    bool operator==(const AsnString&) const = default;

    static const TypeDescriptor& asn_DEF;

    /// @brief Number of characters (code points), as SIZE constraints count them.
    /// @return Character count of the stored value.
    /// @see X.680 §51.5 — SizeConstraint counts characters of a character string.
    std::size_t char_count() const { return string_char_count(TagNumber, str()); }

    /// @brief Return 0 when the string satisfies SIZE and alphabet constraints.
    ///
    /// Part of constraint validation dispatched by \c asn1::validate (Validate.hpp).
    /// - SIZE: signed delta in characters such that \c (chars+delta) lands at the
    ///   nearest valid bound — positive = too short, negative = too long.
    /// - Alphabet: returns 1 (sentinel) when any character is outside the permitted
    ///   set. \c c.encode_table holds either the FROM constraint (codegen-emitted)
    ///   or the built-in alphabet per tag (NumericString / PrintableString /
    ///   IA5String / VisibleString). The table covers code points 0..255; a
    ///   character above that is never in it.
    /// - A \c SIZE(lb..MAX) (SIZE_LOWER_BOUND) only has a lower bound.
    /// @param c  The type's Constraints.
    /// @return 0 when valid, else the SIZE delta or the alphabet sentinel.
    /// @see X.680 §51.5 (SIZE), §51.7 (PermittedAlphabet).
    int64_t validate(const Constraints& c) const {
        const bool sized = !(c.flags & Constraints::EXTENSIBLE) &&
                           (c.flags & (Constraints::SIZE_CONSTRAINED | Constraints::SIZE_LOWER_BOUND));
        if (sized) {
            auto n = static_cast<int64_t>(char_count());
            if (n < c.size_lower) return c.size_lower - n;
            if ((c.flags & Constraints::SIZE_CONSTRAINED) && n > c.size_upper)
                return c.size_upper - n;
        }
        if (c.encode_table) {
            bool bad = false;
            for_each_code_point(TagNumber, str(), [&](uint32_t cp) {
                if (cp > 0xFF || c.encode_table[cp] == 0xFFFFu) bad = true;
            });
            if (bad) return 1;
        }
        return 0;
    }
};

template<uint32_t N>
struct BerTraits<AsnString<N>> {
    static constexpr Tag tag() { return Tag::universal(N, false); }

    static void encode(BerWriter& w, const AsnString<N>& v) {
        const auto& s = v.str();
        w.write_primitive(tag(), std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }

    static Expected<AsnString<N>, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<AsnString<N>, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<AsnString<N>, DecodeError>(
                DecodeError(std::format("expected string tag {}, got {}", N, tlv->tag.number)));
        return AsnString<N>{std::string(
            reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size())};
    }
};

/// @name ASN.1 string type aliases
/// Named \c AsnString<N> instantiations matching ASN.1 built-in type names.
///@{
using Utf8String       = AsnString<UniversalTag::Utf8String>;       ///< UTF-8 (unrestricted).
using NumericString    = AsnString<UniversalTag::NumericString>;    ///< Digits and space only.
using PrintableString  = AsnString<UniversalTag::PrintableString>;  ///< Printable subset of ASCII.
using T61String        = AsnString<UniversalTag::T61String>;        ///< Teletex / T.61.
using VideotexString   = AsnString<UniversalTag::VideotexString>;   ///< Videotex.
using Ia5String        = AsnString<UniversalTag::Ia5String>;        ///< IA5 / ASCII (7-bit).
using GraphicString    = AsnString<UniversalTag::GraphicString>;    ///< Graphic characters.
using VisibleString    = AsnString<UniversalTag::VisibleString>;    ///< Visible (printable) ASCII.
using GeneralString    = AsnString<UniversalTag::GeneralString>;    ///< General character set.
using UniversalString  = AsnString<UniversalTag::UniversalString>;  ///< ISO/IEC 10646-1 (UCS-4).
using BmpString        = AsnString<UniversalTag::BmpString>;        ///< Basic Multilingual Plane (UCS-2).
using ObjectDescriptor = AsnString<UniversalTag::ObjectDescriptor>; ///< Object descriptor string.
///@}

} // namespace asn1
