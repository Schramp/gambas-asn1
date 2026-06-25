#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"
#include "../codec/BerWriter.hpp"
#include "../codec/BerReader.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

namespace detail {
// Returns minimal two's-complement big-endian encoding of n (used by ENUMERATED codegen).
inline std::vector<uint8_t> encode_integer_bytes(int64_t n) {
    uint8_t buf[8];
    int len = 0;
    if (n == 0) {
        return {0x00};
    }
    uint64_t u = static_cast<uint64_t>(n);
    for (int i = 7; i >= 0; --i) { buf[i] = u & 0xFF; u >>= 8; }
    int start = 0;
    if (n > 0) {
        while (start < 7 && buf[start] == 0x00 && (buf[start+1] & 0x80) == 0) ++start;
    } else {
        while (start < 7 && buf[start] == 0xFF && (buf[start+1] & 0x80) != 0) ++start;
    }
    len = 8 - start;
    return std::vector<uint8_t>(buf + start, buf + start + len);
}
} // namespace detail

/// @brief ASN.1 INTEGER — signed 64-bit value.
///
/// Sufficient for all constrained INTEGER types in ETSI LI and most real-world schemas.
/// Implicit construction from \c int64_t allows natural assignment syntax.
/// For non-negative semi-constrained types with values > INT64_MAX use \c UInteger.
///
/// @see X.680 §18 — INTEGER type; X.690 §8.3 — BER encoding.
class Integer : public Asn1Object {
    int64_t value_{0};
public:
    Integer() = default;
    Integer(int64_t v) : value_(v) {}  // implicit: allows using MyAlias = asn1::Integer with natural syntax
    /// @brief Return the stored integer value.
    int64_t value() const { return value_; }
    /// @brief Set the stored integer value.
    void    set(int64_t v) { value_ = v; }
    Integer& operator=(int64_t v) { value_ = v; return *this; }
    explicit operator int64_t() const { return value_; }
    bool operator==(const Integer& o) const { return value_ == o.value_; }
    bool operator!=(const Integer& o) const { return value_ != o.value_; }
    bool operator==(int64_t v) const { return value_ == v; }
    bool operator!=(int64_t v) const { return value_ != v; }

    /// @brief Return 0 when the value satisfies the constraint, otherwise signed delta
    /// such that \c (value+delta) lands at the nearest valid bound.
    /// Positive = below lower_bound; negative = above upper_bound.
    /// EXTENSIBLE ranges are open (always returns 0).
    int64_t validate(const Constraints& c) const {
        if (c.flags & Constraints::EXTENSIBLE) return 0;
        if (c.flags & Constraints::CONSTRAINED) {
            if (value_ < c.lower_bound) return c.lower_bound - value_;
            if (value_ > c.upper_bound) return c.upper_bound - value_;
            return 0;
        }
        if (c.flags & Constraints::SEMI_CONSTRAINED) {
            if (value_ < c.lower_bound) return c.lower_bound - value_;
            return 0;
        }
        return 0;
    }
};

// BerTraits for Integer and for long (plain integer fields)
template<>
struct BerTraits<Integer> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Integer, false); }

    static void encode(BerWriter& w, const Integer& v) {
        int64_t n = v.value();
        // Compute minimal two's-complement big-endian encoding
        uint8_t buf[8];
        int len = 0;
        if (n == 0) {
            buf[0] = 0x00; len = 1;
        } else {
            // Fill 8 bytes big-endian two's complement
            uint64_t u = static_cast<uint64_t>(n);
            for (int i = 7; i >= 0; --i) {
                buf[i] = u & 0xFF;
                u >>= 8;
            }
            // Skip leading redundant bytes:
            // For positive: skip 0x00 bytes as long as the next byte has MSB clear
            // For negative: skip 0xFF bytes as long as the next byte has MSB set
            int start = 0;
            if (n > 0) {
                while (start < 7 && buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0)
                    ++start;
            } else {
                while (start < 7 && buf[start] == 0xFF && (buf[start + 1] & 0x80) != 0)
                    ++start;
            }
            len = 8 - start;
            std::memmove(buf, buf + start, len);
        }
        w.write_primitive(tag(), std::span<const uint8_t>(buf, len));
    }

    static Expected<Integer, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Integer, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Integer, DecodeError>(
                DecodeError(std::format("expected INTEGER tag (0x{:02x}) got 0x{:02x}",
                    0x02, (static_cast<uint8_t>(tlv->tag.cls) << 6) | tlv->tag.number), 0));
        return decode_value(tlv->value);
    }

    static Expected<Integer, DecodeError> decode_value(std::span<const uint8_t> bytes) {
        if (bytes.empty())
            return make_unexpected<Integer, DecodeError>(DecodeError("empty INTEGER value"));
        if (bytes.size() > 8)
            return make_unexpected<Integer, DecodeError>(DecodeError("INTEGER value too large for int64_t"));
        // Sign-extend from first byte
        int64_t v = (bytes[0] & 0x80) ? -1LL : 0LL;
        for (uint8_t b : bytes)
            v = (v << 8) | b;
        return Integer{v};
    }
};

// Convenience specialisation for int64_t directly
template<>
struct BerTraits<int64_t> {
    static constexpr Tag tag() { return BerTraits<Integer>::tag(); }
    static void encode(BerWriter& w, int64_t v) { BerTraits<Integer>::encode(w, Integer{v}); }
    static Expected<int64_t, DecodeError> decode(BerReader& r) {
        auto r2 = BerTraits<Integer>::decode(r);
        if (!r2) return make_unexpected<int64_t, DecodeError>(r2.error());
        return r2->value();
    }
};

// ---------------------------------------------------------------------------
// UInteger — uint64_t storage for non-negative semi-constrained / large ranges
// ---------------------------------------------------------------------------

/// @brief ASN.1 INTEGER with unsigned 64-bit storage.
/// Used for constrained INTEGER types whose upper bound exceeds INT64_MAX,
/// or for non-negative semi-constrained types with lower_bound ≥ 0.
/// @see Integer — the signed 64-bit variant.
class UInteger : public Asn1Object {
    uint64_t value_{0};
public:
    UInteger() = default;
    UInteger(uint64_t v) : value_(v) {}  // implicit: same rationale as Integer
    /// @brief Return the stored unsigned integer value.
    uint64_t value() const { return value_; }
    /// @brief Set the stored unsigned integer value.
    void     set(uint64_t v) { value_ = v; }
    UInteger& operator=(uint64_t v) { value_ = v; return *this; }
    explicit operator uint64_t() const { return value_; }
    bool operator==(const UInteger& o) const { return value_ == o.value_; }
    bool operator!=(const UInteger& o) const { return value_ != o.value_; }
    bool operator==(uint64_t v) const { return value_ == v; }
    bool operator!=(uint64_t v) const { return value_ != v; }

    int64_t validate(const Constraints& c) const {
        if (c.flags & Constraints::EXTENSIBLE) return 0;
        if (c.flags & Constraints::CONSTRAINED) {
            if (value_ < c.lower_u64) {
                uint64_t delta = c.lower_u64 - value_;
                return (delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
                    ? std::numeric_limits<int64_t>::max() : static_cast<int64_t>(delta);
            }
            if (value_ > c.upper_u64) {
                uint64_t delta = value_ - c.upper_u64;
                return (delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
                    ? std::numeric_limits<int64_t>::min() : -static_cast<int64_t>(delta);
            }
            return 0;
        }
        if (c.flags & Constraints::SEMI_CONSTRAINED) {
            // lower_u64 == 0 → any uint64_t is valid; otherwise check lower
            if (value_ < c.lower_u64) {
                uint64_t delta = c.lower_u64 - value_;
                return (delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
                    ? std::numeric_limits<int64_t>::max() : static_cast<int64_t>(delta);
            }
            return 0;
        }
        return 0;
    }
};

template<>
struct BerTraits<UInteger> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Integer, false); }

    static void encode(BerWriter& w, const UInteger& u) {
        uint64_t v = u.value();
        if (v == 0) {
            uint8_t zero = 0x00;
            w.write_primitive(tag(), std::span<const uint8_t>(&zero, 1));
            return;
        }
        // buf[0] = potential 0x00 pad; buf[1..8] = big-endian bytes of v
        uint8_t buf[9];
        buf[0] = 0x00;
        for (int i = 8; i >= 1; --i) { buf[i] = v & 0xFF; v >>= 8; }
        // Skip leading zero bytes where the following byte has MSB clear
        int start = 1;
        while (start < 8 && buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0)
            ++start;
        // If first significant byte has MSB set, include the 0x00 pad at buf[0]
        if (buf[start] & 0x80) --start;
        w.write_primitive(tag(), std::span<const uint8_t>(buf + start, 9 - start));
    }

    static Expected<UInteger, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<UInteger, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<UInteger, DecodeError>(
                DecodeError(std::format("expected INTEGER tag (0x{:02x}) got 0x{:02x}",
                    0x02, (static_cast<uint8_t>(tlv->tag.cls) << 6) | tlv->tag.number), 0));
        return decode_value(tlv->value);
    }

    static Expected<UInteger, DecodeError> decode_value(std::span<const uint8_t> bytes) {
        if (bytes.empty())
            return make_unexpected<UInteger, DecodeError>(DecodeError("empty INTEGER value"));
        // Strip 0x00 pad byte: present when value > INT64_MAX needs 9 bytes (X.690 §8.3.3).
        // After stripping, the first byte may have MSB=1 — that is valid for large U64.
        bool stripped_pad = false;
        if (bytes.size() == 9 && bytes[0] == 0x00) {
            bytes = bytes.subspan(1);
            stripped_pad = true;
        }
        if (bytes.size() > 8)
            return make_unexpected<UInteger, DecodeError>(
                DecodeError("INTEGER value too large for uint64_t"));
        // Only reject negative values when we did NOT strip a pad (unpadded MSB=1 → negative)
        if (!stripped_pad && (bytes[0] & 0x80))
            return make_unexpected<UInteger, DecodeError>(
                DecodeError("negative INTEGER cannot decode as UInteger"));
        uint64_t v = 0;
        for (uint8_t b : bytes) v = (v << 8) | b;
        return UInteger{v};
    }
};

template<>
struct BerTraits<uint64_t> {
    static constexpr Tag tag() { return BerTraits<UInteger>::tag(); }
    static void encode(BerWriter& w, uint64_t v) { BerTraits<UInteger>::encode(w, UInteger{v}); }
    static Expected<uint64_t, DecodeError> decode(BerReader& r) {
        auto r2 = BerTraits<UInteger>::decode(r);
        if (!r2) return make_unexpected<uint64_t, DecodeError>(r2.error());
        return r2->value();
    }
};

// ---------------------------------------------------------------------------
// BigInteger — __int128 storage (architecture placeholder, not yet implemented)
// ---------------------------------------------------------------------------

/// @brief Placeholder for `__int128` INTEGER storage — not yet implemented.
/// Constructors are deleted; instantiation is a compile error.
class BigInteger {
public:
    BigInteger() = delete;
};

// ---------------------------------------------------------------------------
// ArbitraryInteger — vector<uint8_t> BER byte-blob for unconstrained INTEGER
// ---------------------------------------------------------------------------

/// @brief Placeholder for arbitrary-precision INTEGER (e.g. crypto-key schemas).
/// Constructors are deleted; instantiation is a compile error until implemented.
class ArbitraryInteger {
public:
    ArbitraryInteger() = delete;
};

} // namespace asn1
