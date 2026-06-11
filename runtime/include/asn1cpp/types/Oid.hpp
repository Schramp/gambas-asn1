#pragma once

// Maximum OID arcs decoded into a stack buffer before falling back to heap.
// X.680 sets no formal limit; real-world OIDs are typically < 20 arcs.
#define ASN1CPP_OID_STACK_ARCS 64
#include <vector>
#include <string>
#include <span>
#include <format>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../Hints.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

class Oid : public Asn1Object {
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

class RelativeOid : public Asn1Object {
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
        if (ASN1CPP_UNLIKELY(idx >= bytes.size()))
            return make_unexpected<uint32_t, DecodeError>(DecodeError("truncated OID arc"));
        uint8_t b = bytes[idx++];
        v = (v << 7) | (b & 0x7F);
        if (ASN1CPP_LIKELY(!(b & 0x80))) return v;  // last byte of arc (most arcs fit in 1-2 bytes)
    }
    return make_unexpected<uint32_t, DecodeError>(DecodeError("OID arc overflow"));
}
} // namespace detail

template<>
struct BerTraits<Oid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Oid, false); }

    static void encode(BerWriter& w, const Oid& v) {
        // Write OID value bytes directly into w to avoid a heap-allocated temp vector.
        // Each arc encodes to at most 5 bytes; OIDs have at most ~128 arcs in practice.
        // Use an inline stack buffer: 128 arcs × 5 bytes = 640 bytes max.
        // write_primitive needs a span, so accumulate into fixed stack storage.
        const auto& a = v.arcs();
        uint8_t stack_buf[640];
        std::size_t len = 0;
        auto push_arc = [&](uint32_t arc) {
            uint8_t tmp[5]; int n = 0;
            do { tmp[n++] = arc & 0x7F; arc >>= 7; } while (arc);
            for (int i = n - 1; i >= 0; --i)
                stack_buf[len++] = tmp[i] | (i ? 0x80u : 0x00u);
        };
        if (a.size() >= 2) {
            push_arc(a[0] * 40 + a[1]);
            for (std::size_t i = 2; i < a.size(); ++i) push_arc(a[i]);
        } else if (a.size() == 1) {
            push_arc(a[0] * 40);
        }
        w.write_primitive(tag(), {stack_buf, len});
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
        // Fast path: decode into a stack buffer to avoid heap allocation.
        // Falls back to vector if arc count exceeds ASN1CPP_OID_STACK_ARCS.
        uint32_t stack_arcs[ASN1CPP_OID_STACK_ARCS]; std::size_t n = 0;
        std::size_t i = 0;
        auto first = detail::decode_arc(bytes, i);
        if (!first) return make_unexpected<Oid, DecodeError>(first.error());
        uint32_t f = *first;
        stack_arcs[n++] = f / 40;
        stack_arcs[n++] = f % 40;
        while (ASN1CPP_LIKELY(i < bytes.size())) {
            auto arc = detail::decode_arc(bytes, i);
            if (ASN1CPP_UNLIKELY(!arc)) return make_unexpected<Oid, DecodeError>(arc.error());
            if (ASN1CPP_UNLIKELY(n >= ASN1CPP_OID_STACK_ARCS)) {
                // Overflow: finish decoding into a heap vector.
                std::vector<uint32_t> arcs(stack_arcs, stack_arcs + n);
                arcs.push_back(*arc);
                while (i < bytes.size()) {
                    auto a2 = detail::decode_arc(bytes, i);
                    if (ASN1CPP_UNLIKELY(!a2)) return make_unexpected<Oid, DecodeError>(a2.error());
                    arcs.push_back(*a2);
                }
                return Oid{std::move(arcs)};
            }
            stack_arcs[n++] = *arc;
        }
        return Oid{std::vector<uint32_t>(stack_arcs, stack_arcs + n)};
    }
};

template<>
struct BerTraits<RelativeOid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::RelativeOid, false); }

    static void encode(BerWriter& w, const RelativeOid& v) {
        uint8_t stack_buf[640]; std::size_t len = 0;
        for (uint32_t arc : v.arcs()) {
            uint8_t tmp[5]; int n = 0;
            do { tmp[n++] = arc & 0x7F; arc >>= 7; } while (arc);
            for (int i = n - 1; i >= 0; --i)
                stack_buf[len++] = tmp[i] | (i ? 0x80u : 0x00u);
        }
        w.write_primitive(tag(), {stack_buf, len});
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
        uint32_t stack_arcs[ASN1CPP_OID_STACK_ARCS]; std::size_t n = 0;
        std::size_t i = 0;
        while (ASN1CPP_LIKELY(i < value.size())) {
            auto arc = detail::decode_arc(value, i);
            if (ASN1CPP_UNLIKELY(!arc)) return make_unexpected<RelativeOid, DecodeError>(arc.error());
            if (ASN1CPP_UNLIKELY(n >= ASN1CPP_OID_STACK_ARCS)) {
                std::vector<uint32_t> arcs(stack_arcs, stack_arcs + n);
                arcs.push_back(*arc);
                while (i < value.size()) {
                    auto a2 = detail::decode_arc(value, i);
                    if (ASN1CPP_UNLIKELY(!a2)) return make_unexpected<RelativeOid, DecodeError>(a2.error());
                    arcs.push_back(*a2);
                }
                return RelativeOid{std::move(arcs)};
            }
            stack_arcs[n++] = *arc;
        }
        return RelativeOid{std::vector<uint32_t>(stack_arcs, stack_arcs + n)};
    }
};

} // namespace asn1
