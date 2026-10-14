#pragma once
#include <algorithm>
#include <vector>
#include <span>
#include <asn1cpp/compat/format.hpp>
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

    /// @brief Bit value at position \p i (0 = first bit); 0 beyond \c bit_count().
    bool bit(std::size_t i) const {
        return i < bit_count() && ((bytes_[i / 8] >> (7 - i % 8)) & 1);
    }

    /// @brief Length of the value with its trailing 0 bits removed: the
    ///        position after the last 1 bit, 0 when no bit is set.
    /// @see X.680 §22.7 — trailing 0 bits of a NamedBitList value carry no meaning.
    std::size_t significant_bit_count() const {
        for (std::size_t i = bytes_.size(); i-- > 0;) {
            uint8_t b = bytes_[i];
            if (i + 1 == bytes_.size()) b &= static_cast<uint8_t>(0xFF << unused_bits_);
            if (b) return i * 8 + 8 - static_cast<std::size_t>(__builtin_ctz(b));
        }
        return 0;
    }

    /// @brief Length a NamedBitList value is encoded with in PER: trailing 0
    ///        bits removed, then 0 bits added up to the SIZE lower bound.
    /// @param c  Constraints of the BIT STRING type (\c size_lower is 0 without SIZE).
    /// @see X.691 §15.2, §15.3.
    std::size_t named_bits_length(const Constraints& c) const {
        auto lb = static_cast<std::size_t>(c.size_lower > 0 ? c.size_lower : 0);
        return std::max(significant_bit_count(), lb);
    }

    /// @brief Rewrite this NamedBitList value into the form PER transmits
    ///        (\c named_bits_length bits), so it survives a PER round trip unchanged.
    /// @param c  Constraints of the BIT STRING type.
    /// @see X.691 §15.2, §15.3; X.680 §22.7.
    void normalize_named_bits(const Constraints& c) {
        std::size_t n = named_bits_length(c);
        bytes_.resize((n + 7) / 8, 0);
        unused_bits_ = static_cast<uint8_t>((8 - n % 8) % 8);
        if (!bytes_.empty()) bytes_.back() &= static_cast<uint8_t>(0xFF << unused_bits_);
    }

    bool operator==(const BitString&) const = default;

    static const TypeDescriptor& asn_DEF;

    /// @brief Return 0 when \c bit_count() satisfies the SIZE constraint (in bits),
    /// otherwise signed delta such that \c (bit_count+delta) lands at the nearest bound.
    /// Positive = too short; negative = too long. A NamedBitList value satisfies
    /// the constraint when adding or removing trailing 0 bits can make it fit,
    /// so only its significant bits are checked against the upper bound.
    /// @see X.680 §22.7; X.691 §15.3.
    int64_t validate(const Constraints& c) const {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & Constraints::EXTENSIBLE) return 0;
        if (c.flags & Constraints::NAMED_BITS) {
            auto sig = static_cast<int64_t>(significant_bit_count());
            return sig > c.size_upper ? c.size_upper - sig : 0;
        }
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
