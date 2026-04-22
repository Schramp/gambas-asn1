#pragma once
#include <vector>
#include <span>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

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
