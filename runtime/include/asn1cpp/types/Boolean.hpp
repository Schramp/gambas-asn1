#pragma once
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

/// @brief ASN.1 BOOLEAN.
/// DER encoding: FALSE = 0x00, TRUE = 0xFF (X.690 §11.1).
/// @see X.680 §17 — BOOLEAN type; X.690 §8.2 — BER encoding.
class Boolean : public Asn1Object {
    bool value_{false};
public:
    Boolean() = default;
    explicit Boolean(bool v) : value_(v) {}
    /// @brief Return the stored boolean value.
    bool value() const { return value_; }
    /// @brief Set the stored boolean value.
    void set(bool v) { value_ = v; }
    operator bool() const { return value_; }
    bool operator==(const Boolean&) const = default;

    static const TypeDescriptor& asn_DEF;
};

template<>
struct BerTraits<Boolean> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Boolean, false); }

    /// @brief BER-encode the value as a primitive TLV with tag \p t.
    /// @param t  Tag to write: the universal tag by default, or the tag of a
    ///           type assignment (X.680 §31.2) such as `T ::= [APPLICATION 1] ...`.
    /// @see X.690 §8.2.
    static void encode(BerWriter& w, const Boolean& v, Tag t = tag()) {
        // DER: FALSE = 0x00, TRUE = 0xFF
        uint8_t b = v.value() ? 0xFF : 0x00;
        w.write_primitive(t, std::span<const uint8_t>(&b, 1));
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

} // namespace asn1
