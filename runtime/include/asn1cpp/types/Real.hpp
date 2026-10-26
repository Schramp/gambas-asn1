#pragma once
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <asn1cpp/compat/format.hpp>
#include <limits>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

/// @brief ASN.1 REAL: an abstract value mantissa × base^exponent with base 2
///        or 10 (X.680 §20.3–20.5), held in one of three storage classes:
///        - \c Double: an IEEE 754 double, base 2 (the default and the
///          common case; no allocation);
///        - \c Binary: base 2 with an arbitrary mantissa, for a BER binary
///          value a double cannot hold exactly;
///        - \c Decimal: base 10 with an arbitrary digit string, from the BER
///          decimal form or JER \c {"base10Value": n}.
///        value() is exact for \c Double and the nearest double (or ±∞ / ±0
///        beyond the double range) otherwise. Base-2 and base-10 values are
///        distinct abstract values (X.680 §20.5 NOTE 1), so a \c Decimal never
///        equals a \c Double.
/// @see X.680 §20 — REAL type; X.690 §8.5 / §11.3 — BER and CER/DER encoding.
class Real : public Asn1Object {
public:
    enum class Storage : uint8_t { Double, Binary, Decimal };

    /// @brief Exact components of a \c Binary or \c Decimal value:
    ///        (negative ? −1 : 1) × mantissa × base^exponent, base 2 for
    ///        \c Binary and 10 for \c Decimal.
    /// \c Binary: mantissa is big-endian octets, odd (X.690 §11.3.1).
    /// \c Decimal: mantissa is ASCII digits, neither first nor last digit 0
    /// (X.690 §11.3.2.4). Both forms are therefore unique per abstract value.
    struct Exact {
        Storage     storage = Storage::Binary;
        bool        negative = false;
        std::string mantissa;
        int64_t     exponent = 0;
        bool operator==(const Exact&) const = default;
    };

private:
    // A \c Double carries no Exact, so the common case stays two words and
    // allocation-free; copying a \c Binary / \c Decimal deep-copies it.
    double value_{0.0};
    std::unique_ptr<const Exact> exact_;

public:
    Real() = default;
    explicit Real(double v) : value_(v) {}
    Real(const Real& o) : value_(o.value_), exact_(o.exact_ ? std::make_unique<const Exact>(*o.exact_) : nullptr) {}
    Real(Real&&) noexcept = default;
    Real& operator=(const Real& o) {
        if (this != &o) {
            value_ = o.value_;
            exact_ = o.exact_ ? std::make_unique<const Exact>(*o.exact_) : nullptr;
        }
        return *this;
    }
    Real& operator=(Real&&) noexcept = default;

    /// @brief A base-2 value S × N × 2^e2. A value a double holds exactly
    ///        becomes \c Double; any other becomes \c Binary.
    /// @param negative  S = −1.
    /// @param mantissa  N, big-endian, any number of leading zero octets.
    /// @param exponent  Binary exponent of N's least significant bit.
    /// @return The value; zero mantissa gives ±0.
    /// @see X.690 §8.5.7.
    static Real binary(bool negative, std::span<const uint8_t> mantissa, int64_t exponent);

    /// @brief A base-10 value S × digits × 10^exponent, stored as \c Decimal.
    /// @param negative  S = −1.
    /// @param digits    ASCII decimal digits; leading and trailing zeros allowed.
    /// @param exponent  Decimal exponent of the last digit.
    /// @return The value; all-zero digits give ±0 (\c Double).
    /// @see X.680 §20.5; X.690 §8.5.8.
    static Real decimal(bool negative, std::string_view digits, int64_t exponent);

    /// @brief Return the value as a double: exact for \c Double, the nearest
    ///        double otherwise.
    double value() const { return value_; }
    /// @brief Set a base-2 \c Double value.
    void   set(double v)   { value_ = v; exact_.reset(); }
    operator double() const { return value_; }

    /// @brief The storage class.
    Storage storage() const { return exact_ ? exact_->storage : Storage::Double; }
    /// @brief 10 for \c Decimal, 2 otherwise.
    int base() const { return storage() == Storage::Decimal ? 10 : 2; }
    /// @brief Exact components; null for \c Double.
    const Exact* exact() const { return exact_.get(); }

    /// @brief Equality of REAL abstract values: storage class (base) and exact
    ///        components must match. For \c Double, minus zero and plus zero
    ///        differ and NOT-A-NUMBER equals itself, since X.690 §8.5.9 gives
    ///        each its own encoding.
    /// @see X.680 §20.5 NOTE 1 — base-2 and base-10 values are distinct.
    bool operator==(const Real& o) const {
        if (exact_ || o.exact_) return exact_ && o.exact_ && *exact_ == *o.exact_;
        if (std::isnan(value_) || std::isnan(o.value_)) return std::isnan(value_) && std::isnan(o.value_);
        return value_ == o.value_ && std::signbit(value_) == std::signbit(o.value_);
    }
    /// @brief Numeric equality at double precision, ignoring the base:
    ///        compares value(), with -0 equal to +0 and NaN unequal to itself.
    bool numerically_equal(const Real& o) const { return value_ == o.value_; }

    /// @brief Exact text of a \c Decimal value, `[-]digitsE<exp>` or
    ///        `[-]digits` when the exponent is 0: a JSON number (X.697 §23.4)
    ///        and an X.680 realnumber. Empty for other storage classes.
    std::string decimal_text() const;

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

namespace detail {
/// @brief Decode the contents octets of a BER REAL (Real.cpp).
/// @see X.690 §8.5.
Expected<Real, DecodeError> decode_real_contents(std::span<const uint8_t> value);
/// @brief Contents octets of a \c Binary or \c Decimal REAL in their CER/DER
///        form (Real.cpp).
/// @see X.690 §11.3.
std::vector<uint8_t> encode_real_exact(const Real& v);
/// @brief Parse `[-]digits[.digits][(e|E)[+-]digits]` (a JSON number, X.697
///        §23.4) exactly into a \c Decimal (Real.cpp).
Expected<Real, DecodeError> parse_decimal_number(std::string_view text);
} // namespace detail

template<>
struct BerTraits<Real> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Real, false); }

    /// @brief Encode a REAL as a BER TLV: \c Binary / \c Decimal in their
    ///        CER/DER form (detail::encode_real_exact), \c Double as the
    ///        base-2 binary form with an odd mantissa.
    /// @see X.690 §8.5, §11.3.
    static void encode(BerWriter& w, const Real& v) {
        if (v.storage() != Real::Storage::Double) {
            w.write_primitive(tag(), detail::encode_real_exact(v));
            return;
        }
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
        return detail::decode_real_contents(value);
    }
};

} // namespace asn1
