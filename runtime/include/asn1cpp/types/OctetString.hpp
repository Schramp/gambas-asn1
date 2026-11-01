#pragma once
#include <string>
#include <span>
#include <vector>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

/// @brief ASN.1 OCTET STRING — arbitrary binary data.
///
/// Stored internally as \c std::string for binary-safe SSO (avoids heap for
/// short octet strings).  All public accessors use \c std::span<const uint8_t>
/// so callers don't see the internal string representation.
///
/// @see X.680 §22 — OCTET STRING type; X.690 §8.7 — BER encoding.
class OctetString : public Asn1Object {
    std::string bytes_; // binary-safe; SSO avoids heap for short strings
public:
    OctetString() = default;
    /// @brief Construct from a byte vector.
    explicit OctetString(std::vector<uint8_t> b)
        : bytes_(reinterpret_cast<const char*>(b.data()), b.size()) {}
    /// @brief Construct from a byte span.
    OctetString(std::span<const uint8_t> b)
        : bytes_(reinterpret_cast<const char*>(b.data()), b.size()) {}
    /// @brief Construct from a raw pointer + length.
    OctetString(const uint8_t* p, std::size_t n)
        : bytes_(reinterpret_cast<const char*>(p), n) {}

    /// @brief Replace contents with \p b.
    void set(std::vector<uint8_t> b)
        { bytes_.assign(reinterpret_cast<const char*>(b.data()), b.size()); }
    /// @brief Replace contents with \p b.
    void set(std::span<const uint8_t> b)
        { bytes_.assign(reinterpret_cast<const char*>(b.data()), b.size()); }
    /// @brief Replace contents with \p n bytes from \p p.
    void set(const uint8_t* p, std::size_t n)
        { bytes_.assign(reinterpret_cast<const char*>(p), n); }

    /// @brief View the stored bytes (zero-copy).
    std::span<const uint8_t> bytes() const {
        return {reinterpret_cast<const uint8_t*>(bytes_.data()), bytes_.size()};
    }
    /// @brief Number of bytes stored.
    std::size_t size()  const { return bytes_.size(); }
    /// @brief True if no bytes are stored.
    bool empty()        const { return bytes_.empty(); }

    bool operator==(const OctetString& o) const = default;

    static const TypeDescriptor& asn_DEF;

    /// @brief Return 0 when size satisfies the SIZE constraint, otherwise signed delta
    /// such that \c (size+delta) lands at the nearest valid bound.
    /// Positive = too short; negative = too long. A \c SIZE(lb..MAX) (SIZE_LOWER_BOUND)
    /// only has a lower bound.
    /// @param c  The type's Constraints (SIZE_CONSTRAINED / SIZE_LOWER_BOUND / EXTENSIBLE).
    /// @return 0 when valid, else the signed delta.
    /// @see X.680 §51.5.
    int64_t validate(const Constraints& c) const {
        if ((c.flags & Constraints::SIZE_LOWER_BOUND) && !(c.flags & Constraints::EXTENSIBLE)) {
            auto n = static_cast<int64_t>(bytes_.size());
            return n < c.size_lower ? c.size_lower - n : 0;
        }
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

    /// @brief BER-encode the value as a primitive TLV with tag \p t.
    /// @param t  Tag to write: the universal tag by default, or the tag of a
    ///           type assignment (X.680 §31.2) such as `T ::= [APPLICATION 1] ...`.
    /// @see X.690 §8.7.
    static void encode(BerWriter& w, const OctetString& v, Tag t = tag()) {
        w.write_primitive(t, v.bytes());
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
