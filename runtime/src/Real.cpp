#include <asn1cpp/types/Real.hpp>

#include <bit>

namespace asn1::detail {

namespace {

DecodeError real_error(const char* what) { return DecodeError(std::string("REAL: ") + what); }

/// @brief Bit i (0 = least significant) of the unsigned big-endian
///        integer held in m.
bool bit_at(std::span<const uint8_t> m, int64_t i) {
    return (m[m.size() - 1 - static_cast<std::size_t>(i / 8)] >> (i % 8)) & 1;
}

} // namespace

/// @brief Convert S × N × 2^e2 to the nearest double, rounding half to even.
/// @param negative  S = −1.
/// @param n         N as an unsigned big-endian integer, leading zero octets
///                  stripped, not empty, first octet non-zero.
/// @param e2        Binary exponent of N's least significant bit.
/// @return The double, or an error when the value is beyond the double range:
///         its magnitude rounds to infinity, or to zero although N is non-zero.
/// @see X.690 §8.5.7 (binary form); IEEE 754 round-to-nearest-even.
static Expected<double, DecodeError> real_from_binary(bool negative, std::span<const uint8_t> n, int64_t e2) {
    const int64_t bits_n = static_cast<int64_t>(n.size() - 1) * 8 + std::bit_width(n[0]);
    const int64_t e_msb = e2 + bits_n - 1;
    if (e_msb > 1023)
        return make_unexpected<double, DecodeError>(real_error("value outside the double range"));
    if (e_msb < -1076)
        return make_unexpected<double, DecodeError>(real_error("value outside the double range"));

    // Unit of the result's last significand bit: 53 significant bits for a
    // normal double, fewer below 2^-1022 (subnormal, unit 2^-1074).
    int64_t unit = std::max<int64_t>(e_msb - 52, -1074);
    const int64_t shift = unit - e2;
    uint64_t kept = 0;
    if (shift <= 0) {
        for (int64_t i = bits_n - 1; i >= 0; --i)
            kept = (kept << 1) | static_cast<uint64_t>(bit_at(n, i));
        kept <<= -shift;
    } else {
        for (int64_t i = bits_n - 1; i >= shift; --i)
            kept = (kept << 1) | static_cast<uint64_t>(bit_at(n, i));
        bool round = bit_at(n, shift - 1);
        bool sticky = false;
        for (int64_t i = 0; i < shift - 1 && !sticky; ++i)
            sticky = bit_at(n, i);
        if (round && (sticky || (kept & 1))) ++kept;
    }
    if (kept == (uint64_t{1} << 53)) { kept >>= 1; ++unit; }
    if (kept == 0)
        return make_unexpected<double, DecodeError>(real_error("value outside the double range"));

    uint64_t bits;
    if (kept < (uint64_t{1} << 52)) {
        bits = kept;  // subnormal: unit is 2^-1074
    } else {
        const int64_t biased = unit + 52 + 1023;
        if (biased >= 2047)
            return make_unexpected<double, DecodeError>(real_error("value outside the double range"));
        bits = (static_cast<uint64_t>(biased) << 52) | (kept & ((uint64_t{1} << 52) - 1));
    }
    if (negative) bits |= uint64_t{1} << 63;
    double d;
    std::memcpy(&d, &bits, sizeof d);
    return d;
}

/// @brief Decode the contents octets of a BER REAL into a double.
/// @param value  Contents octets (no tag or length).
/// @return The value, or an error for a reserved or malformed encoding and
///         for a value beyond the double range.
/// @see X.690 §8.5 — §8.5.2 plus zero, §8.5.7 binary form (exponent formats
///      a–d of §8.5.7.4, unnormalized mantissa of §8.5.7.5 NOTE 1),
///      §8.5.9 special values.
Expected<double, DecodeError> decode_real_contents(std::span<const uint8_t> value) {
    if (value.empty()) return 0.0;

    const uint8_t info = value[0];
    if ((info & 0xC0) == 0x40) {
        if (value.size() != 1)
            return make_unexpected<double, DecodeError>(real_error("special value with extra contents octets"));
        switch (info) {
        case 0x40: return std::numeric_limits<double>::infinity();
        case 0x41: return -std::numeric_limits<double>::infinity();
        case 0x42: return std::numeric_limits<double>::quiet_NaN();
        case 0x43: return -0.0;
        default:
            return make_unexpected<double, DecodeError>(real_error("reserved special value"));
        }
    }
    if (!(info & 0x80))
        return make_unexpected<double, DecodeError>(DecodeError("decimal REAL encoding not supported"));

    const bool negative = (info & 0x40) != 0;
    if (((info >> 4) & 0x03) != 0)
        return make_unexpected<double, DecodeError>(DecodeError("only base-2 REAL supported"));
    const int scaling = (info >> 2) & 0x03;

    auto rest = value.subspan(1);
    std::size_t exp_len;
    if ((info & 0x03) == 0x03) {
        if (rest.empty())
            return make_unexpected<double, DecodeError>(real_error("truncated exponent length"));
        exp_len = rest[0];
        rest = rest.subspan(1);
        if (exp_len == 0)
            return make_unexpected<double, DecodeError>(real_error("exponent length 0"));
    } else {
        exp_len = (info & 0x03) + 1u;
    }
    if (rest.size() < exp_len)
        return make_unexpected<double, DecodeError>(DecodeError("truncated REAL exponent"));
    auto exp = rest.first(exp_len);
    auto n = rest.subspan(exp_len);

    while (!n.empty() && n[0] == 0) n = n.subspan(1);
    if (n.empty()) return negative ? -0.0 : 0.0;

    // Two's-complement exponent; redundant sign octets carry no value.
    const uint8_t sign = (exp[0] & 0x80) ? 0xFF : 0x00;
    std::size_t k = 0;
    while (k + 1 < exp.size() && exp[k] == sign && (exp[k + 1] & 0x80) == (sign & 0x80)) ++k;
    if (exp.size() - k > 7)
        return make_unexpected<double, DecodeError>(real_error("value outside the double range"));
    int64_t e = sign ? -1 : 0;
    for (std::size_t i = k; i < exp.size(); ++i)
        e = static_cast<int64_t>((static_cast<uint64_t>(e) << 8) | exp[i]);

    return real_from_binary(negative, n, e + scaling);
}

} // namespace asn1::detail
