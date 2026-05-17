#pragma once
#include <string>
#include <span>
#include <vector>
#include <format>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

class OctetString : public Asn1Object {
    std::string bytes_; // binary-safe; SSO avoids heap for short strings
public:
    OctetString() = default;
    explicit OctetString(std::vector<uint8_t> b)
        : bytes_(reinterpret_cast<const char*>(b.data()), b.size()) {}
    OctetString(std::span<const uint8_t> b)
        : bytes_(reinterpret_cast<const char*>(b.data()), b.size()) {}
    OctetString(const uint8_t* p, std::size_t n)
        : bytes_(reinterpret_cast<const char*>(p), n) {}

    void set(std::vector<uint8_t> b)
        { bytes_.assign(reinterpret_cast<const char*>(b.data()), b.size()); }
    void set(std::span<const uint8_t> b)
        { bytes_.assign(reinterpret_cast<const char*>(b.data()), b.size()); }
    void set(const uint8_t* p, std::size_t n)
        { bytes_.assign(reinterpret_cast<const char*>(p), n); }

    std::span<const uint8_t> bytes() const {
        return {reinterpret_cast<const uint8_t*>(bytes_.data()), bytes_.size()};
    }
    std::size_t size()              const { return bytes_.size(); }
    bool empty()                    const { return bytes_.empty(); }

    bool operator==(const OctetString& o) const = default;

    // Returns 0 when size satisfies SIZE(...), otherwise signed delta such
    // that (size + delta) lands at the nearest valid bound:
    //   positive — too short; delta = size_lower - n
    //   negative — too long;  delta = size_upper - n
    int64_t validate(const Constraints& c) const {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & Constraints::EXTENSIBLE) return 0;
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
