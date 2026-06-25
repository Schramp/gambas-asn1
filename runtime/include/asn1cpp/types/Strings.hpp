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
    /// @brief Number of bytes (not characters for multi-byte encodings like UTF-8).
    std::size_t size() const { return str().size(); }

    bool operator==(const AsnString&) const = default;

    /// @brief Return 0 when the string satisfies SIZE and alphabet constraints.
    ///
    /// - SIZE: signed delta (chars) such that \c (size+delta) lands at nearest
    ///   valid bound — positive = too short, negative = too long.
    /// - Alphabet: returns 1 (sentinel) when any byte is outside the permitted set.
    ///   FROM constraint (\c c.encode_table) takes precedence; otherwise the built-in
    ///   alphabet per tag (NumericString / PrintableString / IA5String / VisibleString).
    ///   Unrestricted types (UTF8String, BMPString, …) always return 0.
    int64_t validate(const Constraints& c) const {
        if ((c.flags & Constraints::SIZE_CONSTRAINED) &&
            !(c.flags & Constraints::EXTENSIBLE)) {
            auto n = static_cast<int64_t>(str().size());
            if (n < c.size_lower) return c.size_lower - n;
            if (n > c.size_upper) return c.size_upper - n;
        }
        // encode_table is present for both FROM-constrained types (codegen-emitted) and
        // built-in restricted types (NumericString, PrintableString, IA5String, VisibleString).
        // O(1) lookup: 0xFFFF = character not in permitted alphabet.
        if (c.encode_table)
            for (char ch : str())
                if (c.encode_table[static_cast<unsigned char>(ch)] == 0xFFFFu) return 1;
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
