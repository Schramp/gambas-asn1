#pragma once

#include <optional>
#include <vector>
#include <string>
#include <span>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../Hints.hpp"
#include "../codec/BerTraits.hpp"

namespace asn1 {

/// @brief ASN.1 OBJECT IDENTIFIER — sequence of non-negative integer arcs.
///
/// Stored as a \c vector<uint32_t> of decoded arc values.  The first two arcs
/// (X.680 §32.3: first*40+second on the wire) are already split by the decoder.
///
/// @see X.680 §32 — OBJECT IDENTIFIER type; X.690 §8.19 — BER encoding.
class Oid : public Asn1Object {
    std::vector<uint32_t> arcs_;
public:
    Oid() = default;
    explicit Oid(std::vector<uint32_t> a) : arcs_(std::move(a)) {}

    /// @brief Replace the arc list.
    void set(std::vector<uint32_t> a) { arcs_ = std::move(a); }

    /// @brief Access the arc list.
    const std::vector<uint32_t>& arcs() const { return arcs_; }
    /// @brief Number of arcs.
    std::size_t size()                  const { return arcs_.size(); }

    /// @brief Return a dotted-decimal string representation (e.g. \c "2.5.4.3").
    std::string to_string() const {
        std::string s;
        for (std::size_t i = 0; i < arcs_.size(); ++i) {
            if (i) s += '.';
            s += std::to_string(arcs_[i]);
        }
        return s;
    }

    bool operator==(const Oid&) const = default;

    static const TypeDescriptor& asn_DEF;
};

/// @brief ASN.1 RELATIVE-OID — like \c Oid but without the first-two-arc encoding trick.
/// @see X.680 §33 — RELATIVE-OID type; X.690 §8.20 — BER encoding.
class RelativeOid : public Asn1Object {
    std::vector<uint32_t> arcs_;
public:
    RelativeOid() = default;
    explicit RelativeOid(std::vector<uint32_t> a) : arcs_(std::move(a)) {}
    /// @brief Replace the arc list.
    void set(std::vector<uint32_t> a) { arcs_ = std::move(a); }
    /// @brief Access the arc list.
    const std::vector<uint32_t>& arcs() const { return arcs_; }
    bool operator==(const RelativeOid&) const = default;

    static const TypeDescriptor& asn_DEF;
};

namespace detail {
/// @brief Largest arc value either OID type holds (\c uint32_t storage, the
///        same range asn1c's \c asn_oid_arc_t accepts).
inline constexpr uint64_t kMaxOidArc = 0xFFFFFFFFu;

/// @brief Write one subidentifier, base-128, most significant group first,
///        bit 8 set on every octet but the last.
/// @param out  Output position; advanced past the octets written (at most 10).
/// @param v    Subidentifier value; 64 bits wide so the combined first
///             subidentifier of an OID (X*40+Y) never wraps.
/// @return The new output position.
/// @see X.690 §8.19.2 — subidentifier encoding.
inline uint8_t* encode_subid(uint8_t* out, uint64_t v) {
    uint8_t tmp[10];
    int n = 0;
    do {
        tmp[n++] = v & 0x7F;
        v >>= 7;
    } while (v);
    for (int i = n - 1; i >= 0; --i)
        *out++ = tmp[i] | (i ? 0x80 : 0x00);
    return out;
}

/// @brief Contents octets of an OID or RELATIVE-OID, built on the stack when
///        they fit (5 octets per 32-bit arc) and on the heap otherwise.
class SubidBuffer {
    uint8_t stack_[640];
    std::vector<uint8_t> heap_;
    uint8_t* begin_;
    uint8_t* end_;
public:
    /// @param subids  Number of subidentifiers that will be written.
    explicit SubidBuffer(std::size_t subids) {
        if (subids * 5 > sizeof(stack_)) heap_.resize(subids * 5);
        begin_ = end_ = heap_.empty() ? stack_ : heap_.data();
    }
    /// @brief Append one subidentifier (see encode_subid()).
    void push(uint64_t v) { end_ = encode_subid(end_, v); }
    std::span<const uint8_t> span() const { return {begin_, end_}; }
};

/// @brief Read one subidentifier, advancing \p idx past it.
/// @param bytes  Contents octets of an OBJECT IDENTIFIER or RELATIVE-OID.
/// @param idx    Read position, updated on success.
/// @param max    Largest value the caller can store; a larger one is an error.
/// @return The subidentifier, or a DecodeError when it is truncated or exceeds \p max.
/// @see X.690 §8.19.2 — subidentifier encoding.
inline Expected<uint64_t, DecodeError>
decode_subid(std::span<const uint8_t> bytes, std::size_t& idx, uint64_t max) {
    uint64_t v = 0;
    while (true) {
        if (ASN1CPP_UNLIKELY(idx >= bytes.size()))
            return make_unexpected<uint64_t, DecodeError>(DecodeError("truncated OID arc"));
        uint8_t b = bytes[idx++];
        if (ASN1CPP_UNLIKELY(v > (max >> 7)))
            return make_unexpected<uint64_t, DecodeError>(DecodeError("OID arc overflow"));
        v = (v << 7) | (b & 0x7F);
        if (ASN1CPP_LIKELY(!(b & 0x80))) {  // last octet; most arcs fit in 1-2 octets
            if (ASN1CPP_UNLIKELY(v > max))
                return make_unexpected<uint64_t, DecodeError>(DecodeError("OID arc overflow"));
            return v;
        }
    }
}

/// @brief Decode a run of subidentifiers, each one an arc, onto \p arcs.
/// @param bytes  Contents octets.
/// @param idx    Position of the first subidentifier to read.
/// @param arcs   Arc list to append to.
/// @return Empty on success, else the error of the first malformed subidentifier.
inline std::optional<DecodeError>
decode_arcs(std::span<const uint8_t> bytes, std::size_t idx, std::vector<uint32_t>& arcs) {
    while (ASN1CPP_LIKELY(idx < bytes.size())) {
        auto arc = decode_subid(bytes, idx, kMaxOidArc);
        if (ASN1CPP_UNLIKELY(!arc)) return arc.error();
        arcs.push_back(static_cast<uint32_t>(*arc));
    }
    return std::nullopt;
}
} // namespace detail

template<>
struct BerTraits<Oid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::Oid, false); }

    /// @brief BER-encode the value as a primitive TLV with tag \p t.
    /// @param t  Tag to write: the universal tag by default, or the tag of a
    ///           type assignment (X.680 §31.2) such as `T ::= [APPLICATION 1] ...`.
    /// @see X.690 §8.19 — the first two arcs share one subidentifier, X*40+Y (§8.19.4).
    static void encode(BerWriter& w, const Oid& v, Tag t = tag()) {
        const auto& a = v.arcs();
        detail::SubidBuffer buf(a.size());
        if (a.size() >= 2) {
            buf.push(uint64_t{a[0]} * 40 + a[1]);
            for (std::size_t i = 2; i < a.size(); ++i) buf.push(a[i]);
        } else if (a.size() == 1) {
            buf.push(uint64_t{a[0]} * 40);
        }
        w.write_primitive(t, buf.span());
    }

    static Expected<Oid, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<Oid, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<Oid, DecodeError>(
                DecodeError(std::format("expected OID tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    /// @brief Decode OBJECT IDENTIFIER contents octets into arcs.
    /// @param bytes  Contents octets (no tag or length).
    /// @return The OID, or a DecodeError for a truncated or out-of-range arc.
    /// @see X.690 §8.19.4 — the first subidentifier is X*40+Y; X is 0 or 1 when
    ///      it is below 80, otherwise X is 2 and Y is the remainder.
    static Expected<Oid, DecodeError> decode_value(std::span<const uint8_t> bytes) {
        if (bytes.empty()) return Oid{};
        std::size_t i = 0;
        auto first = detail::decode_subid(bytes, i, detail::kMaxOidArc + 80);
        if (!first) return make_unexpected<Oid, DecodeError>(first.error());
        uint64_t f = *first;
        uint64_t x = f < 80 ? f / 40 : 2;
        std::vector<uint32_t> arcs;
        arcs.reserve(bytes.size() + 1);
        arcs.push_back(static_cast<uint32_t>(x));
        arcs.push_back(static_cast<uint32_t>(f - x * 40));
        if (auto err = detail::decode_arcs(bytes, i, arcs))
            return make_unexpected<Oid, DecodeError>(std::move(*err));
        return Oid{std::move(arcs)};
    }
};

template<>
struct BerTraits<RelativeOid> {
    static constexpr Tag tag() { return Tag::universal(UniversalTag::RelativeOid, false); }

    /// @brief BER-encode the value as a primitive TLV with tag \p t.
    /// @param t  Tag to write: the universal tag by default, or the tag of a
    ///           type assignment (X.680 §31.2) such as `T ::= [APPLICATION 1] ...`.
    /// @see X.690 §8.20.
    static void encode(BerWriter& w, const RelativeOid& v, Tag t = tag()) {
        detail::SubidBuffer buf(v.arcs().size());
        for (uint32_t arc : v.arcs()) buf.push(arc);
        w.write_primitive(t, buf.span());
    }

    static Expected<RelativeOid, DecodeError> decode(BerReader& r) {
        auto tlv = r.read_tlv();
        if (!tlv) return make_unexpected<RelativeOid, DecodeError>(tlv.error());
        if (tlv->tag != tag())
            return make_unexpected<RelativeOid, DecodeError>(
                DecodeError(std::format("expected RELATIVE-OID tag, got number {}", tlv->tag.number)));
        return decode_value(tlv->value);
    }

    /// @brief Decode RELATIVE-OID contents octets: one arc per subidentifier.
    /// @param value  Contents octets (no tag or length).
    /// @return The RELATIVE-OID, or a DecodeError for a truncated or out-of-range arc.
    /// @see X.690 §8.20.2.
    static Expected<RelativeOid, DecodeError> decode_value(std::span<const uint8_t> value) {
        std::vector<uint32_t> arcs;
        arcs.reserve(value.size());
        if (auto err = detail::decode_arcs(value, 0, arcs))
            return make_unexpected<RelativeOid, DecodeError>(std::move(*err));
        return RelativeOid{std::move(arcs)};
    }
};

} // namespace asn1
