#include <asn1cpp/types/Real.hpp>

#include <bit>
#include <cstdlib>
#include <optional>
#include <string>

namespace asn1 {

namespace {

DecodeError real_error(const char* what) { return DecodeError(std::string("REAL: ") + what); }

/// @brief Bit i (0 = least significant) of the unsigned big-endian
///        integer held in m.
bool bit_at(std::span<const uint8_t> m, int64_t i) {
    return (m[m.size() - 1 - static_cast<std::size_t>(i / 8)] >> (i % 8)) & 1;
}

} // namespace

/// @brief Nearest double to a base-2 value, and whether it is exact.
struct NearestDouble {
    double d;
    bool   exact;
};

/// @brief Convert S × N × 2^e2 to the nearest double, rounding half to even.
/// @param negative  S = −1.
/// @param n         N as an unsigned big-endian integer, leading zero octets
///                  stripped, not empty, first octet non-zero.
/// @param e2        Binary exponent of N's least significant bit.
/// @return The double and whether it equals the value. A magnitude beyond the
///         double range gives ±∞ or ±0, inexact.
/// @see X.690 §8.5.7 (binary form); IEEE 754 round-to-nearest-even.
static NearestDouble real_from_binary(bool negative, std::span<const uint8_t> n, int64_t e2) {
    constexpr double inf = std::numeric_limits<double>::infinity();
    const int64_t bits_n = static_cast<int64_t>(n.size() - 1) * 8 + std::bit_width(n[0]);
    const int64_t e_msb = e2 + bits_n - 1;
    if (e_msb > 1023)  return {negative ? -inf : inf, false};
    if (e_msb < -1075) return {negative ? -0.0 : 0.0, false};  // below half of 2^-1074

    // Unit of the result's last significand bit: 53 significant bits for a
    // normal double, fewer below 2^-1022 (subnormal, unit 2^-1074).
    int64_t unit = std::max<int64_t>(e_msb - 52, -1074);
    const int64_t shift = unit - e2;
    uint64_t kept = 0;
    bool exact = true;
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
        exact = !round && !sticky;
        if (round && (sticky || (kept & 1))) ++kept;
    }
    if (kept == (uint64_t{1} << 53)) { kept >>= 1; ++unit; }
    if (kept == 0) return {negative ? -0.0 : 0.0, false};

    uint64_t bits;
    if (kept < (uint64_t{1} << 52)) {
        bits = kept;  // subnormal: unit is 2^-1074
    } else {
        const int64_t biased = unit + 52 + 1023;
        if (biased >= 2047) return {negative ? -inf : inf, false};
        bits = (static_cast<uint64_t>(biased) << 52) | (kept & ((uint64_t{1} << 52) - 1));
    }
    if (negative) bits |= uint64_t{1} << 63;
    double d;
    std::memcpy(&d, &bits, sizeof d);
    return {d, exact};
}

/// @brief Parse optionally-signed decimal digits as an int64.
/// @return The value, or nullopt when empty, non-digit or beyond 64 bits.
static std::optional<int64_t> parse_exponent(std::string_view t) {
    bool neg = false;
    if (!t.empty() && (t[0] == '+' || t[0] == '-')) { neg = t[0] == '-'; t.remove_prefix(1); }
    if (t.empty()) return std::nullopt;
    uint64_t v = 0;
    for (char c : t) {
        if (c < '0' || c > '9') return std::nullopt;
        if (v > (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - (c - '0')) / 10) return std::nullopt;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    return neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
}

/// @brief Build a Decimal from its digit string and the exponent of the last
///        digit, after a fraction of @p frac_len digits was folded in.
static Expected<Real, DecodeError> decimal_value(bool negative, std::string_view digits,
                                                 int64_t exponent, std::size_t frac_len) {
    if (exponent < std::numeric_limits<int64_t>::min() + static_cast<int64_t>(frac_len))
        return make_unexpected<Real, DecodeError>(real_error("decimal exponent beyond 64 bits"));
    return Real::decimal(negative, digits, exponent - static_cast<int64_t>(frac_len));
}

/// @brief Parse an ISO 6093 number (X.690 §8.5.8) into a base-10 value.
/// @param form  NR form from bits 6–1 of the first contents octet: 1, 2 or 3.
/// @param text  The field following the first contents octet.
/// @return The \c Decimal value (±0 for zero digits), or an error for text
///         that is not an NR\p form number and for an exponent beyond 64 bits.
///
/// Accepted: leading spaces, an optional sign, digits; NR2 and NR3 add a
/// decimal mark (`.` or `,`); NR3 adds `E`/`e`, an optional sign and exponent
/// digits. The decimal mark is optional in NR3.
static Expected<Real, DecodeError> real_from_decimal(int form, std::span<const uint8_t> text) {
    auto bad = [] { return make_unexpected<Real, DecodeError>(real_error("malformed ISO 6093 number")); };
    std::size_t i = 0;
    while (i < text.size() && text[i] == ' ') ++i;
    bool negative = false;
    if (i < text.size() && (text[i] == '+' || text[i] == '-')) negative = text[i++] == '-';
    std::string digits;
    std::size_t frac_len = 0;
    bool mark = false;
    for (; i < text.size(); ++i) {
        const uint8_t c = text[i];
        if (c >= '0' && c <= '9') {
            digits += static_cast<char>(c);
            if (mark) ++frac_len;
        } else if ((c == '.' || c == ',') && !mark && form >= 2) {
            mark = true;
        } else {
            break;
        }
    }
    if (digits.empty() || (form == 2 && !mark)) return bad();
    int64_t exponent = 0;
    if (form == 3) {
        if (i >= text.size() || (text[i] != 'E' && text[i] != 'e')) return bad();
        ++i;
        const std::size_t exp_start = i;
        if (i < text.size() && (text[i] == '+' || text[i] == '-')) ++i;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') ++i;
        std::string_view et(reinterpret_cast<const char*>(text.data()) + exp_start, i - exp_start);
        if (et.empty() || et == "+" || et == "-") return bad();
        auto e = parse_exponent(et);
        if (!e) return make_unexpected<Real, DecodeError>(real_error("decimal exponent beyond 64 bits"));
        exponent = *e;
    }
    if (i != text.size()) return bad();
    return decimal_value(negative, digits, exponent, frac_len);
}

/// @brief Append @p v as minimal two's-complement big-endian octets.
static void put_signed(std::vector<uint8_t>& out, int64_t v) {
    uint8_t buf[8];
    for (int i = 7; i >= 0; --i) { buf[i] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
    int start = 0;
    while (start < 7 && ((buf[start] == 0x00 && !(buf[start + 1] & 0x80)) ||
                         (buf[start] == 0xFF && (buf[start + 1] & 0x80))))
        ++start;
    out.insert(out.end(), buf + start, buf + 8);
}


Real Real::binary(bool negative, std::span<const uint8_t> mantissa, int64_t exponent) {
    while (!mantissa.empty() && mantissa[0] == 0) mantissa = mantissa.subspan(1);
    if (mantissa.empty()) return Real{negative ? -0.0 : 0.0};
    // Odd mantissa (X.690 §11.3.1): trailing zero bits move into the exponent.
    std::size_t zero_octets = 0;
    while (mantissa[mantissa.size() - 1 - zero_octets] == 0) ++zero_octets;
    mantissa = mantissa.first(mantissa.size() - zero_octets);
    const int r = std::countr_zero(mantissa.back());
    std::string m;
    m.reserve(mantissa.size());
    uint8_t carry = 0;
    for (uint8_t b : mantissa) {
        m += static_cast<char>(r ? ((b >> r) | carry) : b);
        carry = r ? static_cast<uint8_t>(b << (8 - r)) : 0;
    }
    if (m.size() > 1 && m[0] == 0) m.erase(0, 1);
    exponent += static_cast<int64_t>(zero_octets) * 8 + r;

    auto bytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m.data()), m.size());
    const NearestDouble nd = real_from_binary(negative, bytes, exponent);
    Real out{nd.d};
    if (nd.exact) return out;
    out.exact_ = std::make_unique<const Exact>(Exact{Storage::Binary, negative, std::move(m), exponent});
    return out;
}

Real Real::decimal(bool negative, std::string_view digits, int64_t exponent) {
    while (!digits.empty() && digits.front() == '0') digits.remove_prefix(1);
    if (digits.empty()) return Real{negative ? -0.0 : 0.0};
    // Last digit non-zero (X.690 §11.3.2.4): trailing zeros move into the exponent.
    while (digits.back() == '0') {
        digits.remove_suffix(1);
        if (exponent < std::numeric_limits<int64_t>::max()) ++exponent;
    }
    std::string text = std::string(negative ? "-" : "") + std::string(digits) + "e" + std::to_string(exponent);
    Real out{std::strtod(text.c_str(), nullptr)};
    out.exact_ = std::make_unique<const Exact>(Exact{Storage::Decimal, negative, std::string(digits), exponent});
    return out;
}

std::string Real::decimal_text() const {
    if (storage() != Storage::Decimal) return {};
    std::string t = exact_->negative ? "-" : "";
    t += exact_->mantissa;
    if (exact_->exponent != 0) t += "E" + std::to_string(exact_->exponent);
    return t;
}

namespace detail {

Expected<Real, DecodeError> parse_decimal_number(std::string_view t) {
    auto bad = [&] { return make_unexpected<Real, DecodeError>(real_error("malformed decimal number")); };
    std::size_t i = 0;
    bool negative = false;
    if (i < t.size() && (t[i] == '+' || t[i] == '-')) negative = t[i++] == '-';
    std::string digits;
    std::size_t frac_len = 0;
    for (; i < t.size() && t[i] >= '0' && t[i] <= '9'; ++i) digits += t[i];
    if (digits.empty()) return bad();
    if (i < t.size() && t[i] == '.') {
        ++i;
        const std::size_t start = i;
        for (; i < t.size() && t[i] >= '0' && t[i] <= '9'; ++i) digits += t[i];
        frac_len = i - start;
    }
    int64_t exponent = 0;
    if (i < t.size() && (t[i] == 'e' || t[i] == 'E')) {
        auto e = parse_exponent(t.substr(i + 1));
        if (!e) return bad();
        exponent = *e;
        i = t.size();
    }
    if (i != t.size()) return bad();
    return decimal_value(negative, digits, exponent, frac_len);
}

std::vector<uint8_t> encode_real_exact(const Real& v) {
    const Real::Exact& x = *v.exact();
    std::vector<uint8_t> out;
    if (v.storage() == Real::Storage::Decimal) {
        // NR3 (X.690 §11.3.2): [-]digits.E<exp>, exponent "+0" when zero.
        out.push_back(0x03);
        std::string t = x.negative ? "-" : "";
        t += x.mantissa;
        t += ".E";
        t += x.exponent == 0 ? std::string("+0") : std::to_string(x.exponent);
        out.insert(out.end(), t.begin(), t.end());
        return out;
    }
    // Binary, base 2, F = 0, odd mantissa, fewest octets (X.690 §11.3.1).
    std::vector<uint8_t> exp;
    put_signed(exp, x.exponent);
    uint8_t info = 0x80 | (x.negative ? 0x40 : 0x00);
    if (exp.size() <= 3) {
        out.push_back(info | static_cast<uint8_t>(exp.size() - 1));
    } else {
        out.push_back(info | 0x03);
        out.push_back(static_cast<uint8_t>(exp.size()));
    }
    out.insert(out.end(), exp.begin(), exp.end());
    out.insert(out.end(), x.mantissa.begin(), x.mantissa.end());
    return out;
}

/// @brief Decode the contents octets of a BER REAL.
/// @param value  Contents octets (no tag or length).
/// @return The value: \c Double when a double holds it exactly, \c Binary for
///         any other binary-form value, \c Decimal for the decimal form. An
///         error for a reserved or malformed encoding and for an exponent
///         beyond 56 bits (binary) or 64 bits (decimal).
/// @see X.690 §8.5 — §8.5.2 plus zero, §8.5.7 binary form (exponent formats
///      a–d of §8.5.7.4, bases 2/8/16 of §8.5.7.2, unnormalized mantissa of
///      §8.5.7.5 NOTE 1), §8.5.8 decimal form, §8.5.9 special values.
Expected<Real, DecodeError> decode_real_contents(std::span<const uint8_t> value) {
    if (value.empty()) return Real{0.0};

    const uint8_t info = value[0];
    if ((info & 0xC0) == 0x40) {
        if (value.size() != 1)
            return make_unexpected<Real, DecodeError>(real_error("special value with extra contents octets"));
        switch (info) {
        case 0x40: return Real{std::numeric_limits<double>::infinity()};
        case 0x41: return Real{-std::numeric_limits<double>::infinity()};
        case 0x42: return Real{std::numeric_limits<double>::quiet_NaN()};
        case 0x43: return Real{-0.0};
        default:
            return make_unexpected<Real, DecodeError>(real_error("reserved special value"));
        }
    }
    if (!(info & 0x80)) {
        const int form = info & 0x3F;
        if (form < 1 || form > 3)
            return make_unexpected<Real, DecodeError>(real_error("reserved decimal number representation"));
        return real_from_decimal(form, value.subspan(1));
    }

    const bool negative = (info & 0x40) != 0;
    // B' = 2, 8 or 16: one, three or four binary digits per exponent step.
    static constexpr int kLog2Base[] = {1, 3, 4, 0};
    const int log2_base = kLog2Base[(info >> 4) & 0x03];
    if (log2_base == 0)
        return make_unexpected<Real, DecodeError>(real_error("reserved base"));
    const int scaling = (info >> 2) & 0x03;

    auto rest = value.subspan(1);
    std::size_t exp_len;
    if ((info & 0x03) == 0x03) {
        if (rest.empty())
            return make_unexpected<Real, DecodeError>(real_error("truncated exponent length"));
        exp_len = rest[0];
        rest = rest.subspan(1);
        if (exp_len == 0)
            return make_unexpected<Real, DecodeError>(real_error("exponent length 0"));
    } else {
        exp_len = (info & 0x03) + 1u;
    }
    if (rest.size() < exp_len)
        return make_unexpected<Real, DecodeError>(DecodeError("truncated REAL exponent"));
    auto exp = rest.first(exp_len);
    auto n = rest.subspan(exp_len);

    while (!n.empty() && n[0] == 0) n = n.subspan(1);
    if (n.empty()) return Real{negative ? -0.0 : 0.0};

    // Two's-complement exponent; redundant sign octets carry no value.
    const uint8_t sign = (exp[0] & 0x80) ? 0xFF : 0x00;
    std::size_t k = 0;
    while (k + 1 < exp.size() && exp[k] == sign && (exp[k + 1] & 0x80) == (sign & 0x80)) ++k;
    if (exp.size() - k > 7)
        return make_unexpected<Real, DecodeError>(real_error("binary exponent beyond 56 bits"));
    int64_t e = sign ? -1 : 0;
    for (std::size_t i = k; i < exp.size(); ++i)
        e = static_cast<int64_t>((static_cast<uint64_t>(e) << 8) | exp[i]);

    const int64_t e2 = e * log2_base + scaling;
    if (n.size() <= 8) {
        // Common case, a value a double holds exactly: at most 53 significant
        // bits and a scale inside the double range (normal or subnormal).
        uint64_t m = 0;
        for (uint8_t b : n) m = (m << 8) | b;
        const int tz = std::countr_zero(m);
        m >>= tz;
        const int64_t lsb = e2 + tz;
        const int64_t msb = lsb + std::bit_width(m) - 1;
        const int width = std::bit_width(m);
        if (width <= 53 && lsb >= -1074 && msb <= 1023) {
            uint64_t bits = msb >= -1022
                ? (static_cast<uint64_t>(msb + 1023) << 52) | ((m << (53 - width)) & ((uint64_t{1} << 52) - 1))
                : m << (lsb + 1074);  // subnormal: unit 2^-1074
            if (negative) bits |= uint64_t{1} << 63;
            double d;
            std::memcpy(&d, &bits, sizeof d);
            return Real{d};
        }
    }
    return Real::binary(negative, n, e2);
}

} // namespace detail
} // namespace asn1
