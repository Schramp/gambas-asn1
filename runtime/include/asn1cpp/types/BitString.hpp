#pragma once
#include <vector>
#include <span>
#include <format>
#include <stdexcept>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/PerConstraints.hpp"

namespace asn1 {

class BitString {
    std::vector<uint8_t> bytes_;  // raw bytes (excluding unused-bits byte)
    uint8_t unused_bits_{0};      // 0-7 unused bits in the last byte

public:
    BitString() = default;
    BitString(std::vector<uint8_t> b, uint8_t unused = 0)
        : bytes_(std::move(b)), unused_bits_(unused) {
        if (unused > 7) throw std::invalid_argument("unused_bits must be 0-7");
    }

    std::span<const uint8_t> bytes() const { return bytes_; }
    uint8_t unused_bits()            const { return unused_bits_; }
    std::size_t bit_count()          const {
        return bytes_.empty() ? 0 : bytes_.size() * 8 - unused_bits_;
    }

    bool operator==(const BitString&) const = default;

    // SIZE(...) on BIT STRING is in bits. Returns 0 when valid, otherwise
    // signed distance (bits) to the nearest valid count.
    int64_t validate(const PerConstraints& c) const {
        if (!(c.flags & PerConstraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & PerConstraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(bit_count());
        if (n < c.size_lower) return n - c.size_lower;
        if (n > c.size_upper) return n - c.size_upper;
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
        if (tlv->value.empty())
            return make_unexpected<BitString, DecodeError>(DecodeError("BIT STRING value is empty (need at least unused-bits byte)"));
        uint8_t unused = tlv->value[0];
        if (unused > 7)
            return make_unexpected<BitString, DecodeError>(
                DecodeError(std::format("BIT STRING unused bits out of range: {}", unused)));
        auto payload = tlv->value.subspan(1);
        return BitString{std::vector<uint8_t>(payload.begin(), payload.end()), unused};
    }
};

} // namespace asn1
