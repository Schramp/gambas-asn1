#pragma once
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

struct Null {
    bool operator==(const Null&) const = default;
};

template<>
struct BerTraits<Null> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Null, false); }

    static void encode(BerWriter& w, const Null&) {
        w.write_primitive(tag(), {});
    }

    static Expected<Null, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Null, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Null, DecodeError>(
                DecodeError(std::format("expected NULL tag, got number {}", tlv->tag.number)));
        return Null{};
    }
};

} // namespace asn1
