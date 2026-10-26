#pragma once
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <asn1cpp/compat/format.hpp>
#include <limits>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

namespace detail {
/// @brief Decode the contents octets of a BER REAL into a double (Real.cpp).
/// @see X.690 §8.5.
Expected<double, DecodeError> decode_real_contents(std::span<const uint8_t> value);
} // namespace detail

/// @brief ASN.1 REAL — IEEE 754 double-precision floating point.
/// BER encoding uses the X.690 §8.5.7 binary form (base-2, minimal mantissa bytes).
/// Special values +∞, -∞, and NaN are encoded per X.690 §8.5.9.
/// @see X.680 §21 — REAL type; X.690 §8.5 — BER encoding.
class Real : public Asn1Object {
    double value_{0.0};
public:
    Real() = default;
    explicit Real(double v) : value_(v) {}
    /// @brief Return the stored double value.
    double value() const { return value_; }
    /// @brief Set the stored double value.
    void   set(double v)   { value_ = v; }
    operator double() const { return value_; }
    /// @brief Equality of REAL abstract values: minus zero and plus zero
    ///        differ, and NOT-A-NUMBER equals itself: X.690 §8.5.9 gives each
    ///        its own encoding, so a DEFAULT comparison never conflates -0 with 0.
    bool operator==(const Real& o) const {
        if (std::isnan(value_) || std::isnan(o.value_)) return std::isnan(value_) && std::isnan(o.value_);
        return value_ == o.value_ && std::signbit(value_) == std::signbit(o.value_);
    }

    /// @brief Check the value against a REAL value-range constraint.
    /// @param c  Constraints; only REAL_RANGE / REAL_*_OPEN / EXTENSIBLE and
    ///           real_lower / real_upper are read.
    /// @return 0 when inside the range (or no range, or extensible). Otherwise a
    ///         signed distance to the nearest bound, rounded away from zero to at
    ///         least 1 and saturated at INT64_MAX: positive below the lower bound,
    ///         negative above the upper bound. NOT-A-NUMBER lies in no range and
    ///         returns 1.
    /// @see X.680 §47.4 — ValueRange; PLUS-INFINITY exceeds and MINUS-INFINITY
    ///      precedes every other REAL value (§47.4.2 NOTE).
    int64_t validate(const Constraints& c) const {
        if (!(c.flags & Constraints::REAL_RANGE) || (c.flags & Constraints::EXTENSIBLE)) return 0;
        if (std::isnan(value_)) return 1;
        auto distance = [](double d) -> int64_t {
            if (!(d < 9.2e18)) return std::numeric_limits<int64_t>::max();
            return std::max<int64_t>(1, static_cast<int64_t>(std::ceil(d)));
        };
        bool lower_open = c.flags & Constraints::REAL_LOWER_OPEN;
        bool upper_open = c.flags & Constraints::REAL_UPPER_OPEN;
        if (value_ < c.real_lower || (lower_open && value_ == c.real_lower))
            return distance(c.real_lower - value_);
        if (value_ > c.real_upper || (upper_open && value_ == c.real_upper))
            return -distance(value_ - c.real_upper);
        return 0;
    }

    static const TypeDescriptor& asn_DEF;
};

template<>
struct BerTraits<Real> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Real, false); }

    static void encode(BerWriter& w, const Real& v) {
        double d = v.value();
        if (d == 0.0) {
            // X.690 §8.5.9: PLUS-ZERO is the empty encoding; MINUS-ZERO
            // (distinct from PLUS-ZERO -- `==` can't tell them apart,
            // hence std::signbit) is a single content octet 0x43, not
            // empty. Conflating the two here used to silently drop the
            // sign of -0.0 on every encode.
            if (std::signbit(d)) {
                uint8_t b = 0x43;
                w.write_primitive(tag(), std::span<const uint8_t>(&b, 1));
            } else {
                w.write_primitive(tag(), {});
            }
            return;
        }
        if (std::isinf(d)) {
            uint8_t b = d > 0 ? 0x40 : 0x41;  // PLUS-INFINITY / MINUS-INFINITY
            w.write_primitive(tag(), std::span<const uint8_t>(&b, 1));
            return;
        }
        if (std::isnan(d)) {
            uint8_t b = 0x42;  // NOT-A-NUMBER
            w.write_primitive(tag(), std::span<const uint8_t>(&b, 1));
            return;
        }

        // Extract mantissa/exponent directly from IEEE 754 bits (X.690 §8.5.7 binary).
        uint64_t bits;
        std::memcpy(&bits, &d, 8);

        uint8_t info = 0x80;               // binary encoding, base-2, scaling-factor 0
        if (bits >> 63) info |= 0x40;      // negative

        int32_t e = static_cast<int32_t>((bits >> 52) & 0x7FF) - 1023 - 52;
        uint64_t M = (bits & 0x000FFFFFFFFFFFFFULL) | (1ULL << 52);  // implicit leading 1

        // Remove trailing zero bits for minimal encoding
        while (M && (M & 1) == 0) { M >>= 1; ++e; }

        // Encode mantissa big-endian, minimal bytes
        uint8_t mbuf[8];
        int mlen = 0;
        uint64_t tmp = M;
        while (tmp) { mbuf[mlen++] = static_cast<uint8_t>(tmp & 0xFF); tmp >>= 8; }
        std::reverse(mbuf, mbuf + mlen);

        // Encode exponent signed big-endian, minimal bytes
        uint8_t ebuf[3];
        int elen;
        {
            uint32_t u = static_cast<uint32_t>(e);
            for (int i = 2; i >= 0; --i) { ebuf[i] = static_cast<uint8_t>(u & 0xFF); u >>= 8; }
            int start = 0;
            while (start < 2 && ebuf[start] == (e < 0 ? 0xFF : 0x00)
                   && (ebuf[start + 1] & 0x80) == (e < 0 ? 0x80 : 0x00))
                ++start;
            elen = 3 - start;
            std::memmove(ebuf, ebuf + start, elen);
        }
        if (elen > 3) elen = 3;
        info |= static_cast<uint8_t>((elen - 1) & 0x03);

        std::vector<uint8_t> val;
        val.push_back(info);
        val.insert(val.end(), ebuf, ebuf + elen);
        val.insert(val.end(), mbuf, mbuf + mlen);
        w.write_primitive(tag(), val);
    }

    static Expected<Real, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Real, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Real, DecodeError>(
                DecodeError(std::format("expected REAL tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    /// @brief Decode REAL contents octets; see detail::decode_real_contents.
    static Expected<Real, DecodeError> decode_value(std::span<const uint8_t> value) {
        auto d = detail::decode_real_contents(value);
        if (!d) return make_unexpected<Real, DecodeError>(d.error());
        return Real{*d};
    }
};

} // namespace asn1
