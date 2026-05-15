#pragma once
#include <vector>
#include <string>
#include <span>
#include <format>
#include "../Tag.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

class Oid {
    std::vector<uint32_t> arcs_;
public:
    Oid() = default;
    explicit Oid(std::vector<uint32_t> a) : arcs_(std::move(a)) {}

    void set(std::vector<uint32_t> a) { arcs_ = std::move(a); }

    const std::vector<uint32_t>& arcs() const { return arcs_; }
    std::size_t size()                  const { return arcs_.size(); }

    std::string to_string() const {
        std::string s;
        for (std::size_t i = 0; i < arcs_.size(); ++i) {
            if (i) s += '.';
            s += std::to_string(arcs_[i]);
        }
        return s;
    }

    bool operator==(const Oid&) const = default;
};

class RelativeOid {
    std::vector<uint32_t> arcs_;
public:
    RelativeOid() = default;
    explicit RelativeOid(std::vector<uint32_t> a) : arcs_(std::move(a)) {}
    void set(std::vector<uint32_t> a) { arcs_ = std::move(a); }
    const std::vector<uint32_t>& arcs() const { return arcs_; }
    bool operator==(const RelativeOid&) const = default;
};

namespace detail {
// Encode a single OID arc in base-128 (BER OID component encoding)
inline void encode_arc(std::vector<uint8_t>& out, uint32_t arc) {
    uint8_t tmp[5];
    int n = 0;
    do {
        tmp[n++] = arc & 0x7F;
        arc >>= 7;
    } while (arc);
    for (int i = n - 1; i >= 0; --i)
        out.push_back(tmp[i] | (i ? 0x80 : 0x00));
}

// Decode one base-128 arc from bytes, advancing idx
inline Expected<uint32_t, DecodeError>
decode_arc(std::span<const uint8_t> bytes, std::size_t& idx) {
    uint32_t v = 0;
    for (int i = 0; i < 5; ++i) {
        if (idx >= bytes.size())
            return make_unexpected<uint32_t, DecodeError>(DecodeError("truncated OID arc"));
        uint8_t b = bytes[idx++];
        v = (v << 7) | (b & 0x7F);
        if (!(b & 0x80)) return v;
    }
    return make_unexpected<uint32_t, DecodeError>(DecodeError("OID arc overflow"));
}
} // namespace detail

template<>
struct BerTraits<Oid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Oid, false); }

    static void encode(BerWriter& w, const Oid& v) {
        const auto& a = v.arcs();
        std::vector<uint8_t> val;
        if (a.size() >= 2) {
            // First two arcs combined: first*40 + second
            detail::encode_arc(val, a[0] * 40 + a[1]);
            for (std::size_t i = 2; i < a.size(); ++i)
                detail::encode_arc(val, a[i]);
        } else if (a.size() == 1) {
            detail::encode_arc(val, a[0] * 40);
        }
        w.write_primitive(tag(), val);
    }

    static Expected<Oid, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Oid, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Oid, DecodeError>(
                DecodeError(std::format("expected OID tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    static Expected<Oid, DecodeError> decode_value(std::span<const uint8_t> bytes) {
        if (bytes.empty()) return Oid{};
        std::vector<uint32_t> arcs;
        std::size_t i = 0;
        auto first = detail::decode_arc(bytes, i);
        if (!first) return make_unexpected<Oid, DecodeError>(first.error());
        // Unpack first two arcs
        uint32_t f = *first;
        arcs.push_back(f / 40);
        arcs.push_back(f % 40);
        while (i < bytes.size()) {
            auto arc = detail::decode_arc(bytes, i);
            if (!arc) return make_unexpected<Oid, DecodeError>(arc.error());
            arcs.push_back(*arc);
        }
        return Oid{std::move(arcs)};
    }
};

template<>
struct BerTraits<RelativeOid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::RelativeOid, false); }

    static void encode(BerWriter& w, const RelativeOid& v) {
        std::vector<uint8_t> val;
        for (uint32_t a : v.arcs())
            detail::encode_arc(val, a);
        w.write_primitive(tag(), val);
    }

    static Expected<RelativeOid, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<RelativeOid, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<RelativeOid, DecodeError>(
                DecodeError(std::format("expected RELATIVE-OID tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    static Expected<RelativeOid, DecodeError> decode_value(std::span<const uint8_t> value) {
        std::vector<uint32_t> arcs;
        std::size_t i = 0;
        while (i < value.size()) {
            auto arc = detail::decode_arc(value, i);
            if (!arc) return make_unexpected<RelativeOid, DecodeError>(arc.error());
            arcs.push_back(*arc);
        }
        return RelativeOid{std::move(arcs)};
    }
};

} // namespace asn1
