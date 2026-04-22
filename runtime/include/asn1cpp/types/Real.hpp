#pragma once
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <format>
#include <limits>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

class Real {
    double value_{0.0};
public:
    Real() = default;
    explicit Real(double v) : value_(v) {}
    double value() const { return value_; }
    operator double() const { return value_; }
    bool operator==(const Real&) const = default;
};

template<>
struct BerTraits<Real> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Real, false); }

    static void encode(BerWriter& w, const Real& v) {
        double d = v.value();
        if (d == 0.0) {
            // Zero: zero-length content
            w.write_primitive(tag(), {});
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
        // ISO 6093 NR3 decimal form — simplest portable encoding
        // Use base-2 binary encoding (X.690 §8.5.7)
        uint8_t info = 0x80;  // binary, base 2, sign positive
        if (d < 0) { info |= 0x40; d = -d; }

        int exp2;
        double mant = std::frexp(d, &exp2);
        // mant in [0.5, 1.0), shift to get integer mantissa
        uint64_t M = 0;
        for (int i = 0; i < 52; ++i) {
            mant *= 2.0;
            M = (M << 1) | (mant >= 1.0 ? 1 : 0);
            if (mant >= 1.0) mant -= 1.0;
        }
        exp2 -= 52;

        // Remove trailing zero bits from mantissa
        while (M && (M & 1) == 0) { M >>= 1; ++exp2; }

        // Encode mantissa (big-endian, minimal)
        uint8_t mbuf[8];
        int mlen = 0;
        uint64_t tmp = M;
        while (tmp) { mbuf[mlen++] = tmp & 0xFF; tmp >>= 8; }
        std::reverse(mbuf, mbuf + mlen);

        // Encode exponent
        uint8_t ebuf[3];
        int elen = 0;
        int32_t e = exp2;
        {
            uint32_t u = static_cast<uint32_t>(e);
            for (int i = 2; i >= 0; --i) { ebuf[i] = u & 0xFF; u >>= 8; }
            // Minimal: drop leading sign-extension bytes
            int start = 0;
            while (start < 2 && ebuf[start] == (e < 0 ? 0xFF : 0x00)
                   && (ebuf[start+1] & 0x80) == (e < 0 ? 0x80 : 0x00))
                ++start;
            elen = 3 - start;
            std::memmove(ebuf, ebuf + start, elen);
        }

        // info byte: exponent length encoded as 0=1byte, 1=2bytes, 2=3bytes
        if (elen > 3) elen = 3;
        info |= (elen - 1) & 0x03;

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
        if (tlv->value.empty()) return Real{0.0};

        uint8_t info = tlv->value[0];
        if (info == 0x40) return Real{std::numeric_limits<double>::infinity()};
        if (info == 0x41) return Real{-std::numeric_limits<double>::infinity()};
        if (info == 0x42) return Real{std::numeric_limits<double>::quiet_NaN()};

        if (!(info & 0x80))
            return make_unexpected<Real, DecodeError>(DecodeError("decimal REAL encoding not supported"));

        bool negative = (info & 0x40) != 0;
        int base_bits = (info >> 4) & 0x03;
        if (base_bits != 0)
            return make_unexpected<Real, DecodeError>(DecodeError("only base-2 REAL supported"));

        int scaling   = (info >> 2) & 0x03;
        int exp_len   = (info & 0x03) + 1;

        auto bytes = tlv->value.subspan(1);
        if (static_cast<int>(bytes.size()) < exp_len)
            return make_unexpected<Real, DecodeError>(DecodeError("truncated REAL exponent"));

        // Decode exponent (signed, big-endian)
        int32_t e = (bytes[0] & 0x80) ? -1 : 0;
        for (int i = 0; i < exp_len; ++i)
            e = (e << 8) | bytes[i];
        e += scaling;
        bytes = bytes.subspan(exp_len);

        // Decode mantissa
        uint64_t M = 0;
        for (uint8_t b : bytes)
            M = (M << 8) | b;

        double d = std::ldexp(static_cast<double>(M), e);
        if (negative) d = -d;
        return Real{d};
    }
};

} // namespace asn1
