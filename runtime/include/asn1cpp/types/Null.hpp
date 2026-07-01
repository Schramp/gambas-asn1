#pragma once
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

/// @brief ASN.1 NULL — carries no data; used as a CHOICE alternative marker.
/// @see X.680 §23 — NULL type; X.690 §8.8 — BER encoding (empty value field).
struct Null : public Asn1Object {
    bool operator==(const Null&) const = default;
    static const TypeDescriptor& asn_DEF;
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
