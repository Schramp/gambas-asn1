#include <asn1cpp/types/Real.hpp>

#include <bit>
#include <cstdlib>
#include <string>

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

/// @brief Parse an ISO 6093 number (X.690 §8.5.8) into a double.
/// @param form  NR form from bits 6–1 of the first contents octet: 1, 2 or 3.
/// @param text  The field following the first contents octet.
/// @return The nearest double, or an error for text that is not an NR\p form
///         number and for a value beyond the double range.
///
/// Accepted: leading spaces, an optional sign, digits; NR2 and NR3 add a
/// decimal mark (`.` or `,`) with at least one digit on either side of it;
/// NR3 adds `E`/`e`, an optional sign and exponent digits. The decimal mark
/// is optional in NR3. The text is rewritten with `.` and parsed by
/// strtod, which rounds correctly.
static Expected<double, DecodeError> real_from_decimal(int form, std::span<const uint8_t> text) {
    auto bad = [] { return make_unexpected<double, DecodeError>(real_error("malformed ISO 6093 number")); };
    std::size_t i = 0;
    while (i < text.size() && text[i] == ' ') ++i;
    std::string norm;
    if (i < text.size() && (text[i] == '+' || text[i] == '-')) norm += static_cast<char>(text[i++]);
    bool digits = false, nonzero = false, mark = false;
    for (; i < text.size(); ++i) {
        const uint8_t c = text[i];
        if (c >= '0' && c <= '9') {
            digits = true;
            nonzero |= c != '0';
            norm += static_cast<char>(c);
        } else if ((c == '.' || c == ',') && !mark && form >= 2) {
            mark = true;
            norm += '.';
        } else {
            break;
        }
    }
    if (!digits || (form == 2 && !mark)) return bad();
    if (form == 3) {
        if (i >= text.size() || (text[i] != 'E' && text[i] != 'e')) return bad();
        norm += 'e';
        ++i;
        if (i < text.size() && (text[i] == '+' || text[i] == '-')) norm += static_cast<char>(text[i++]);
        const std::size_t exp_start = i;
        for (; i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i) norm += static_cast<char>(text[i]);
        if (i == exp_start) return bad();
    }
    if (i != text.size()) return bad();

    const double d = std::strtod(norm.c_str(), nullptr);
    if (std::isinf(d) || (d == 0.0 && nonzero))
        return make_unexpected<double, DecodeError>(real_error("value outside the double range"));
    return d;
}

/// @brief Decode the contents octets of a BER REAL into a double.
/// @param value  Contents octets (no tag or length).
/// @return The value, or an error for a reserved or malformed encoding and
///         for a value beyond the double range.
/// @see X.690 §8.5 — §8.5.2 plus zero, §8.5.7 binary form (exponent formats
///      a–d of §8.5.7.4, bases 2/8/16 of §8.5.7.2, unnormalized mantissa of
///      §8.5.7.5 NOTE 1), §8.5.8 decimal form, §8.5.9 special values.
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
    if (!(info & 0x80)) {
        const int form = info & 0x3F;
        if (form < 1 || form > 3)
            return make_unexpected<double, DecodeError>(real_error("reserved decimal number representation"));
        return real_from_decimal(form, value.subspan(1));
    }

    const bool negative = (info & 0x40) != 0;
    // B' = 2, 8 or 16: one, three or four binary digits per exponent step.
    static constexpr int kLog2Base[] = {1, 3, 4, 0};
    const int log2_base = kLog2Base[(info >> 4) & 0x03];
    if (log2_base == 0)
        return make_unexpected<double, DecodeError>(real_error("reserved base"));
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

    return real_from_binary(negative, n, e * log2_base + scaling);
}

} // namespace asn1::detail
