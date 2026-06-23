#pragma once
#include <string>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"
#include "../types/Strings.hpp"

namespace asn1 {

/// @brief ASN.1 UTCTime — stored as the raw ASN.1 string (e.g. \c "240115143000Z").
/// Inherits \c AsnStringBase so codec handlers can access the string uniformly.
/// @see X.680 §46 — UTCTime; X.690 §11.7 — DER UTCTime encoding.
class UtcTime : public AsnStringBase {
public:
    UtcTime() = default;
    explicit UtcTime(std::string s) : AsnStringBase(std::move(s)) {}
    bool operator==(const UtcTime&) const = default;
};

/// @brief ASN.1 GeneralizedTime — stored as the raw ASN.1 string (e.g. \c "20240115143000Z").
/// Inherits \c AsnStringBase so codec handlers can access the string uniformly.
/// @see X.680 §47 — GeneralizedTime; X.690 §11.7 — DER GeneralizedTime encoding.
class GeneralizedTime : public AsnStringBase {
public:
    GeneralizedTime() = default;
    explicit GeneralizedTime(std::string s) : AsnStringBase(std::move(s)) {}
    bool operator==(const GeneralizedTime&) const = default;
};

template<>
struct BerTraits<UtcTime> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::UtcTime, false); }

    static void encode(BerWriter& w, const UtcTime& v) {
        auto& s = v.str();
        w.write_primitive(tag(), std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }

    static Expected<UtcTime, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<UtcTime, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<UtcTime, DecodeError>(
                DecodeError(std::format("expected UTCTime tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    static Expected<UtcTime, DecodeError> decode_value(std::span<const uint8_t> value) {
        return UtcTime{std::string(
            reinterpret_cast<const char*>(value.data()), value.size())};
    }
};

template<>
struct BerTraits<GeneralizedTime> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::GeneralizedTime, false); }

    static void encode(BerWriter& w, const GeneralizedTime& v) {
        auto& s = v.str();
        w.write_primitive(tag(), std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }

    static Expected<GeneralizedTime, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<GeneralizedTime, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<GeneralizedTime, DecodeError>(
                DecodeError(std::format("expected GeneralizedTime tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    static Expected<GeneralizedTime, DecodeError> decode_value(std::span<const uint8_t> value) {
        return GeneralizedTime{std::string(
            reinterpret_cast<const char*>(value.data()), value.size())};
    }
};

} // namespace asn1
