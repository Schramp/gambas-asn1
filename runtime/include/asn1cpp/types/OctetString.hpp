#pragma once
#include <vector>
#include <span>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/PerConstraints.hpp"

namespace asn1 {

class OctetString {
    std::vector<uint8_t> bytes_;
public:
    OctetString() = default;
    explicit OctetString(std::vector<uint8_t> b) : bytes_(std::move(b)) {}
    OctetString(std::span<const uint8_t> b) : bytes_(b.begin(), b.end()) {}
    OctetString(const uint8_t* p, std::size_t n) : bytes_(p, p + n) {}

    std::span<const uint8_t> bytes() const { return bytes_; }
    std::size_t size()              const { return bytes_.size(); }
    bool empty()                    const { return bytes_.empty(); }

    bool operator==(const OctetString& o) const = default;

    // Returns 0 when size satisfies SIZE(...), otherwise signed delta such
    // that (size + delta) lands at the nearest valid bound:
    //   positive — too short; delta = size_lower - n
    //   negative — too long;  delta = size_upper - n
    int64_t validate(const PerConstraints& c) const {
        if (!(c.flags & PerConstraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & PerConstraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(bytes_.size());
        if (n < c.size_lower) return c.size_lower - n;
        if (n > c.size_upper) return c.size_upper - n;
        return 0;
    }
};

template<>
struct BerTraits<OctetString> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::OctetString, false); }

    static void encode(BerWriter& w, const OctetString& v) {
        w.write_primitive(tag(), v.bytes());
    }

    static Expected<OctetString, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<OctetString, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<OctetString, DecodeError>(
                DecodeError(std::format("expected OCTET STRING tag, got number {}", tlv->tag.number)));
        return OctetString{tlv->value};
    }
};

} // namespace asn1
