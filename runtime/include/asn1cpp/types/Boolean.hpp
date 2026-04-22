#pragma once
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

class Boolean {
    bool value_{false};
public:
    Boolean() = default;
    explicit Boolean(bool v) : value_(v) {}
    bool value() const { return value_; }
    operator bool() const { return value_; }
    bool operator==(const Boolean&) const = default;
};

template<>
struct BerTraits<Boolean> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Boolean, false); }

    static void encode(BerWriter& w, const Boolean& v) {
        // DER: FALSE = 0x00, TRUE = 0xFF
        uint8_t b = v.value() ? 0xFF : 0x00;
        w.write_primitive(tag(), std::span<const uint8_t>(&b, 1));
    }

    static Expected<Boolean, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Boolean, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Boolean, DecodeError>(
                DecodeError(std::format("expected BOOLEAN tag, got number {}", tlv->tag.number)));
        if (tlv->value.size() != 1)
            return make_unexpected<Boolean, DecodeError>(DecodeError("BOOLEAN must be 1 byte"));
        return Boolean{tlv->value[0] != 0x00};
    }
};

template<>
struct BerTraits<bool> {
    static constexpr Tag tag() { return BerTraits<Boolean>::tag(); }
    static void encode(BerWriter& w, bool v) { BerTraits<Boolean>::encode(w, Boolean{v}); }
    static Expected<bool, DecodeError> decode(BerReader& r) {
        auto r2 = BerTraits<Boolean>::decode(r);
        if (!r2) return make_unexpected<bool, DecodeError>(r2.error());
        return r2->value();
    }
};

} // namespace asn1
