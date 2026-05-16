#pragma once
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <format>
#include <limits>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

class Real : public Asn1Object {
    double value_{0.0};
public:
    Real() = default;
    explicit Real(double v) : value_(v) {}
    double value() const { return value_; }
    void   set(double v)   { value_ = v; }
    operator double() const { return value_; }
    bool operator==(const Real&) const = default;
};

template<>
struct BerTraits<Real> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Real, false); }

    static void encode(BerWriter& w, const Real& v) {
        double d = v.value();
        if (d == 0.0) {
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

    static Expected<Real, DecodeError> decode_value(std::span<const uint8_t> value) {
        if (value.empty()) return Real{0.0};

        uint8_t info = value[0];
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

        auto bytes = value.subspan(1);
        if (static_cast<int>(bytes.size()) < exp_len)
            return make_unexpected<Real, DecodeError>(DecodeError("truncated REAL exponent"));

        int32_t e = (bytes[0] & 0x80) ? -1 : 0;
        for (int i = 0; i < exp_len; ++i)
            e = (e << 8) | bytes[i];
        e += scaling;
        bytes = bytes.subspan(exp_len);

        uint64_t M = 0;
        for (uint8_t b : bytes)
            M = (M << 8) | b;

        double d = std::ldexp(static_cast<double>(M), e);
        if (negative) d = -d;
        return Real{d};
    }
};

} // namespace asn1
