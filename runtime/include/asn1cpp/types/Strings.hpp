#pragma once
#include <string>
#include <string_view>
#include <format>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"
#include "../codec/Alphabets.hpp"

namespace asn1 {

// Non-virtual base for all AsnString<N> types.
// Codec handlers cast void* to AsnStringBase* — language-safe via inheritance,
// no layout assumptions needed.
class AsnStringBase : public Asn1Object {
    std::string value_;
public:
    AsnStringBase() = default;
    explicit AsnStringBase(std::string s) : value_(std::move(s)) {}

    const std::string& str() const { return value_; }
    std::string& str()             { return value_; }

    bool operator==(const AsnStringBase&) const = default;
};

// Thin per-tag wrapper. Tag number N selects the BER universal tag and
// the built-in alphabet for validation.
template<uint32_t TagNumber>
class AsnString : public AsnStringBase {
public:
    AsnString() = default;
    explicit AsnString(std::string s) : AsnStringBase(std::move(s)) {}
    AsnString(const char* s) : AsnStringBase(std::string(s)) {}

    bool empty() const { return str().empty(); }
    std::size_t size() const { return str().size(); }

    bool operator==(const AsnString&) const = default;

    // SIZE + alphabet check. Returns 0 when valid.
    // SIZE: signed delta (chars) such that (size + delta) lands at nearest
    //       valid bound — positive = too short, negative = too long.
    // Alphabet: returns 1 (sentinel; no meaningful distance metric) when any
    //           byte is outside the permitted set. FROM constraint
    //           (c.alphabet) takes precedence; otherwise built-in alphabet
    //           per type tag (NumericString / PrintableString / VisibleString
    //           / IA5String). Unrestricted types (Utf8/BMP/...) return 0.
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

// Named string type aliases matching ASN.1 built-in names
using Utf8String       = AsnString<UniversalTag::Utf8String>;
using NumericString    = AsnString<UniversalTag::NumericString>;
using PrintableString  = AsnString<UniversalTag::PrintableString>;
using T61String        = AsnString<UniversalTag::T61String>;
using VideotexString   = AsnString<UniversalTag::VideotexString>;
using Ia5String        = AsnString<UniversalTag::Ia5String>;
using GraphicString    = AsnString<UniversalTag::GraphicString>;
using VisibleString    = AsnString<UniversalTag::VisibleString>;
using GeneralString    = AsnString<UniversalTag::GeneralString>;
using UniversalString  = AsnString<UniversalTag::UniversalString>;
using BmpString        = AsnString<UniversalTag::BmpString>;
using ObjectDescriptor = AsnString<UniversalTag::ObjectDescriptor>;

} // namespace asn1
