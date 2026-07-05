#pragma once
#include <algorithm>
#include <string>
#include <span>
#include <variant>
#include <vector>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../codec/BerTraits.hpp"
#include "../codec/Constraints.hpp"

namespace asn1 {

/// @brief ASN.1 OCTET STRING — arbitrary binary data.
///
/// Storage is a \c std::variant of an owned \c std::string (binary-safe, SSO)
/// or a non-owning \c std::span view (EXPERIMENTAL zero-copy decode). All public
/// accessors return \c std::span<const uint8_t>, so callers don't see which mode
/// is active. \c set() always produces owned storage; \c borrow() installs a
/// view. A borrowed value is only valid while the viewed buffer lives — no
/// use-after-free protection is provided.
///
/// @see X.680 §22 — OCTET STRING type; X.690 §8.7 — BER encoding.
class OctetString : public Asn1Object {
    // index 0 = owned bytes, index 1 = borrowed view into an external buffer.
    std::variant<std::string, std::span<const uint8_t>> store_{std::string{}};

    static std::span<const uint8_t> as_span(const std::string& s) {
        return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
    }
public:
    OctetString() = default;
    /// @brief Construct from a byte vector (owned).
    explicit OctetString(std::vector<uint8_t> b)
        : store_(std::string(reinterpret_cast<const char*>(b.data()), b.size())) {}
    /// @brief Construct from a byte span (owned copy).
    OctetString(std::span<const uint8_t> b)
        : store_(std::string(reinterpret_cast<const char*>(b.data()), b.size())) {}
    /// @brief Construct from a raw pointer + length (owned copy).
    OctetString(const uint8_t* p, std::size_t n)
        : store_(std::string(reinterpret_cast<const char*>(p), n)) {}

    /// @brief Replace contents with \p b (owned copy).
    void set(std::vector<uint8_t> b)
        { store_ = std::string(reinterpret_cast<const char*>(b.data()), b.size()); }
    /// @brief Replace contents with \p b (owned copy).
    void set(std::span<const uint8_t> b)
        { store_ = std::string(reinterpret_cast<const char*>(b.data()), b.size()); }
    /// @brief Replace contents with \p n bytes from \p p (owned copy).
    void set(const uint8_t* p, std::size_t n)
        { store_ = std::string(reinterpret_cast<const char*>(p), n); }

    /// @brief EXPERIMENTAL: view \p b without copying. The object borrows \p b,
    /// which must outlive this object. Any \c set() reverts to owned storage.
    void borrow(std::span<const uint8_t> b) { store_ = b; }
    /// @brief True if the contents are a borrowed view (not owned).
    bool is_borrowed() const { return store_.index() == 1; }

    /// @brief View the stored bytes (zero-copy).
    std::span<const uint8_t> bytes() const {
        if (auto* s = std::get_if<std::string>(&store_)) return as_span(*s);
        return std::get<std::span<const uint8_t>>(store_);
    }
    /// @brief Number of bytes stored.
    std::size_t size()  const { return bytes().size(); }
    /// @brief True if no bytes are stored.
    bool empty()        const { return bytes().empty(); }

    bool operator==(const OctetString& o) const {
        auto a = bytes(), b = o.bytes();
        return std::equal(a.begin(), a.end(), b.begin(), b.end());
    }

    static const TypeDescriptor& asn_DEF;

    /// @brief Return 0 when size satisfies the SIZE constraint, otherwise signed delta
    /// such that \c (size+delta) lands at the nearest valid bound.
    /// Positive = too short; negative = too long.
    int64_t validate(const Constraints& c) const {
        if (!(c.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (c.flags & Constraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(size());
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
