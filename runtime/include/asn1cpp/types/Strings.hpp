#pragma once
#include <string>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

// Base for all string types — each is a thin wrapper over std::string.
// The tag number differs per subtype.
template<uint32_t TagNumber>
class AsnString {
    std::string value_;
public:
    AsnString() = default;
    explicit AsnString(std::string s) : value_(std::move(s)) {}
    AsnString(const char* s) : value_(s) {}

    const std::string& str() const { return value_; }
    std::string& str()             { return value_; }
    bool empty() const { return value_.empty(); }
    std::size_t size() const { return value_.size(); }

    bool operator==(const AsnString&) const = default;
};

template<uint32_t N>
struct BerTraits<AsnString<N>> {
    static constexpr Tag tag() { return Tag::universal(N, false); }

    static void encode(BerWriter& w, const AsnString<N>& v) {
        auto s = v.str();
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
