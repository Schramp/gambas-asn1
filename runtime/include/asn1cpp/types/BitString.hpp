#pragma once
#include <vector>
#include <span>
#include <format>
#include <stdexcept>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

/// @brief ASN.1 BIT STRING — a sequence of bits with optional trailing padding.
///
/// Stored as raw payload bytes plus an unused-bits count (0–7) for the last byte.
/// \c bit_count() returns the logical bit length.
///
/// @see X.680 §21 — BIT STRING type; X.690 §8.6 — BER encoding.
class BitString : public Asn1Object {
    std::vector<uint8_t> bytes_;  // raw bytes (excluding unused-bits byte)
    uint8_t unused_bits_{0};      // 0-7 unused bits in the last byte

public:
    BitString() = default;
    /// @brief Construct from payload bytes with \p unused trailing bits in the last byte.
    BitString(std::vector<uint8_t> b, uint8_t unused = 0)
        : bytes_(std::move(b)), unused_bits_(unused) {
        if (unused > 7) throw std::invalid_argument("unused_bits must be 0-7");
    }

    /// @brief Replace the payload bytes and unused-bit count.
    void set(std::vector<uint8_t> b, uint8_t unused = 0) {
        if (unused > 7) throw std::invalid_argument("unused_bits must be 0-7");
        bytes_ = std::move(b);
        unused_bits_ = unused;
    }

    /// @brief View the payload bytes (excludes the BER unused-bits prefix byte).
    std::span<const uint8_t> bytes() const { return bytes_; }
    /// @brief Number of unused (padding) bits in the last payload byte (0–7).
    uint8_t unused_bits()            const { return unused_bits_; }
    /// @brief Logical bit length: \c bytes.size()*8 - unused_bits.
    std::size_t bit_count()          const {
        return bytes_.empty() ? 0 : bytes_.size() * 8 - unused_bits_;
    }

    bool operator==(const BitString&) const = default;

    /// @brief Return 0 when \c bit_count() satisfies the SIZE constraint (in bits),
    /// otherwise signed delta such that \c (bit_count+delta) lands at the nearest bound.
    /// Positive = too short; negative = too long.
    int64_t validate(const Constraints& c) const {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & Constraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(bit_count());
        if (n < c.size_lower) return c.size_lower - n;
        if (n > c.size_upper) return c.size_upper - n;
        return 0;
    }
};

template<>
struct BerTraits<BitString> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::BitString, false); }

    static void encode(BerWriter& w, const BitString& v) {
        // Value = unused_bits_byte + payload
        std::vector<uint8_t> val;
        val.reserve(1 + v.bytes().size());
        val.push_back(v.unused_bits());
        val.insert(val.end(), v.bytes().begin(), v.bytes().end());
        w.write_primitive(tag(), val);
    }

    static Expected<BitString, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<BitString, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<BitString, DecodeError>(
                DecodeError(std::format("expected BIT STRING tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    static Expected<BitString, DecodeError> decode_value(std::span<const uint8_t> value) {
        if (value.empty())
            return make_unexpected<BitString, DecodeError>(DecodeError("BIT STRING value is empty (need at least unused-bits byte)"));
        uint8_t unused = value[0];
        if (unused > 7)
            return make_unexpected<BitString, DecodeError>(
                DecodeError(std::format("BIT STRING unused bits out of range: {}", unused)));
        auto payload = value.subspan(1);
        return BitString{std::vector<uint8_t>(payload.begin(), payload.end()), unused};
    }
};

} // namespace asn1
