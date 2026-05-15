#pragma once
#include <string>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

// Both time types store their value as the raw ASN.1 string (e.g. "240115143000Z").
// Validation is left to higher layers.

class UtcTime {
    std::string value_;
public:
    UtcTime() = default;
    explicit UtcTime(std::string s) : value_(std::move(s)) {}
    void set(std::string s) { value_ = std::move(s); }
    void assign(const char* p, std::size_t n) { value_.assign(p, n); }
    const std::string& str() const { return value_; }
    bool operator==(const UtcTime&) const = default;
};

class GeneralizedTime {
    std::string value_;
public:
    GeneralizedTime() = default;
    explicit GeneralizedTime(std::string s) : value_(std::move(s)) {}
    void set(std::string s) { value_ = std::move(s); }
    void assign(const char* p, std::size_t n) { value_.assign(p, n); }
    const std::string& str() const { return value_; }
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
