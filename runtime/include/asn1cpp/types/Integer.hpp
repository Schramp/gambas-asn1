#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include <format>
#include "../Tag.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"
#include "../codec/BerWriter.hpp"
#include "../codec/BerReader.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/PerConstraints.hpp"

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

// Integer wraps int64_t (sufficient for all ETSI LI integers in practice).
// The compiler can specialise this for constrained ranges.
class Integer {
    int64_t value_{0};
public:
    Integer() = default;
    explicit Integer(int64_t v) : value_(v) {}
    int64_t value() const { return value_; }
    operator int64_t() const { return value_; }
    bool operator==(const Integer&) const = default;

    // Returns 0 when value_ satisfies the constraint, otherwise a signed
    // delta such that (value_ + delta) lands at the nearest valid bound:
    //   positive — value_ is below lower_bound; delta = lower_bound - value_
    //   negative — value_ is above upper_bound; delta = upper_bound - value_
    // Caller convention (RandomFiller): +delta raises sampling min; -delta
    // lowers sampling max.
    // EXTENSIBLE ranges are open (returns 0 for any value).
    int64_t validate(const PerConstraints& c) const {
        if (c.flags & PerConstraints::EXTENSIBLE) return 0;
        if (c.flags & PerConstraints::CONSTRAINED) {
            if (value_ < c.lower_bound) return c.lower_bound - value_;
            if (value_ > c.upper_bound) return c.upper_bound - value_;
            return 0;
        }
        if (c.flags & PerConstraints::SEMI_CONSTRAINED) {
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

} // namespace asn1
