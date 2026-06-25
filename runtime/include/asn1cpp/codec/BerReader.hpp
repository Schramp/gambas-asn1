#pragma once
#include <span>
#include <cstdint>
#include <cstddef>
#include <asn1cpp/compat/format.hpp>
#include "../Tag.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"
#include "../Hints.hpp"

namespace asn1 {

/// @brief Cursor over a read-only byte span for BER/DER parsing.
///
/// Provides low-level TLV access.  The typical entry point is \c read_tlv();
/// use \c peek_tag() when you need to inspect the next tag without consuming it
/// (e.g. CHOICE dispatch).
///
/// Construction:
/// @code
/// std::span<const uint8_t> data = ...;
/// asn1::BerReader r{data};
/// asn1::BerDecodeStream s{r};
/// asn1::BerCodec::instance().decode(s, MyType::asn_DEF, &obj);
/// @endcode
///
/// @see X.690 §8 — BER TLV structure.
class BerReader {
    std::span<const uint8_t> data_;
    std::size_t pos_{0};

public:
    /// @brief Construct a reader over \p data.
    /// @param data  Byte span to read from; must outlive this object.
    explicit BerReader(std::span<const uint8_t> data) : data_(data) {}

    /// @brief Return true when all input has been consumed.
    bool at_end()  const { return pos_ >= data_.size(); }
    /// @brief Number of unread bytes remaining.
    std::size_t remaining() const { return pos_ < data_.size() ? data_.size() - pos_ : 0; }
    /// @brief Current read position (byte offset from start of \p data).
    std::size_t pos()   const { return pos_; }

    /// @brief Peek at up to \p n bytes starting at the current position without advancing.
    std::span<const uint8_t> peek(std::size_t n) const {
        std::size_t avail = std::min(n, remaining());
        return data_.subspan(pos_, avail);
    }

    /// @brief Peek at the next TLV tag without consuming it.
    /// Use for CHOICE dispatch: inspect the tag, then call \c read_tlv() to consume.
    /// @return Parsed tag, or sentinel \c Tag{Context,~0u,false} at end or on error.
    [[nodiscard]] ASN1CPP_ALWAYS_INLINE Tag peek_tag() const {
        if (ASN1CPP_UNLIKELY(pos_ >= data_.size()))
            return Tag{TagClass::Context, ~0u, false};
        std::size_t p = pos_;
        return parse_tag_at(data_, p);
    }

    /// @brief Read and consume the next tag.
    /// @return Parsed tag, or \c DecodeError if the stream is empty or malformed.
    [[nodiscard]] ASN1CPP_ALWAYS_INLINE Expected<Tag, DecodeError> read_tag() {
        if (at_end())
            return make_unexpected<Tag, DecodeError>(DecodeError("unexpected end of data reading tag", pos_));
        Tag t = parse_tag_at(data_, pos_);
        if (ASN1CPP_UNLIKELY(t.number == ~0u))
            return make_unexpected<Tag, DecodeError>(DecodeError("truncated or oversized long-form tag", pos_));
        return t;
    }

    /// @brief Pair of decoded length + indefinite-length flag.
    struct LengthResult {
        std::size_t len;       ///< Definite length in bytes (0 when \c indefinite is true).
        bool indefinite;       ///< True for indefinite-length (0x80 form, X.690 §8.1.3.2).
    };

    /// @brief Read and consume the length octets of a TLV.
    /// @return \c LengthResult, or \c DecodeError on truncation or unsupported encoding.
    /// @see X.690 §8.1.3 — Length octets.
    [[nodiscard]] ASN1CPP_ALWAYS_INLINE Expected<LengthResult, DecodeError> read_length() {
        if (at_end())
            return make_unexpected<LengthResult, DecodeError>(DecodeError("unexpected end of data reading length", pos_));

        uint8_t first = data_[pos_++];
        if (first == 0x80)
            return LengthResult{0, true};
        if (!(first & 0x80))
            return LengthResult{first, false};

        // Long-form definite
        int n = first & 0x7F;
        if (n > 8 || n == 0)
            return make_unexpected<LengthResult, DecodeError>(
                DecodeError(std::format("unsupported length encoding ({} bytes)", n), pos_ - 1));
        if (remaining() < static_cast<std::size_t>(n))
            return make_unexpected<LengthResult, DecodeError>(DecodeError("truncated length field", pos_));

        std::size_t len = 0;
        for (int i = 0; i < n; ++i)
            len = (len << 8) | data_[pos_++];
        return LengthResult{len, false};
    }

    /// @brief Read and consume exactly \p n bytes.
    /// @return Span into the underlying buffer, or \c DecodeError if fewer bytes remain.
    Expected<std::span<const uint8_t>, DecodeError> read_bytes(std::size_t n) {
        if (remaining() < n)
            return make_unexpected<std::span<const uint8_t>, DecodeError>(
                DecodeError(std::format("need {} bytes but only {} remain", n, remaining()), pos_));
        auto s = data_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    /// @brief Decoded TLV returned by \c read_tlv().
    struct TLV {
        Tag tag;                          ///< Parsed tag (class, number, constructed bit).
        std::span<const uint8_t> value;   ///< Value bytes (zero-copy view into input).
                                          ///< For indefinite-length encodings the EOC octets (00 00)
                                          ///< are consumed by \c read_tlv() but excluded here; check \c indefinite.
        bool indefinite;                  ///< True if encoded with indefinite length (X.690 §8.1.3.2).
    };

    /// @brief Read and consume one complete TLV.
    /// Handles 1-byte tags, long-form tags, definite and indefinite lengths.
    /// The fast path (1-byte tag + short definite length) is inlined.
    /// @return \c TLV with the value bytes, or \c DecodeError on any parse failure.
    /// @see X.690 §8.1 — Structure of an encoding.
    [[nodiscard]] ASN1CPP_ALWAYS_INLINE Expected<TLV, DecodeError> read_tlv() {
        // Fast path: 1-byte tag (number < 31) + definite short/long length.
        // Covers the vast majority of ETSI BER TLVs without function-call overhead.
        const std::size_t avail = data_.size() - pos_;
        if (ASN1CPP_LIKELY(avail >= 2)) {
            const uint8_t tb = data_[pos_];
            if (ASN1CPP_LIKELY((tb & 0x1F) != 0x1F)) {
                // 1-byte tag
                const uint8_t lb = data_[pos_ + 1];
                if (ASN1CPP_LIKELY(!(lb & 0x80))) {
                    // 1-byte definite length
                    const std::size_t vlen = lb;
                    if (ASN1CPP_LIKELY(avail >= 2 + vlen)) {
                        Tag tag{static_cast<TagClass>((tb >> 6) & 0x03),
                                static_cast<uint32_t>(tb & 0x1F),
                                (tb & 0x20) != 0};
                        auto val = data_.subspan(pos_ + 2, vlen);
                        pos_ += 2 + vlen;
                        return TLV{tag, val, false};
                    }
                } else if (lb != 0x80 && (lb & 0x7F) <= 4) {
                    // Long-form definite (1-4 extra length bytes, no indefinite)
                    const int nb = lb & 0x7F;
                    if (ASN1CPP_LIKELY(avail >= 2u + nb)) {
                        std::size_t vlen = 0;
                        for (int k = 0; k < nb; ++k)
                            vlen = (vlen << 8) | data_[pos_ + 2 + k];
                        if (ASN1CPP_LIKELY(avail >= 2u + nb + vlen)) {
                            Tag tag{static_cast<TagClass>((tb >> 6) & 0x03),
                                    static_cast<uint32_t>(tb & 0x1F),
                                    (tb & 0x20) != 0};
                            auto val = data_.subspan(pos_ + 2 + nb, vlen);
                            pos_ += 2 + nb + vlen;
                            return TLV{tag, val, false};
                        }
                    }
                }
            }
        }
        // Slow path: multi-byte tag, indefinite length, or truncated input.
        auto tag_r = read_tag();
        if (!tag_r) return make_unexpected<TLV, DecodeError>(tag_r.error());
        Tag tag = *tag_r;

        auto len_r = read_length();
        if (!len_r) return make_unexpected<TLV, DecodeError>(len_r.error());

        if (len_r->indefinite) {
            // X.690 §8.1.3.2: indefinite-length is only valid for constructed encodings.
            if (!tag.constructed)
                return make_unexpected<TLV, DecodeError>(
                    DecodeError("indefinite-length encoding on primitive type", pos_ - 1));
            std::size_t start = pos_;
            // Constructed: walk nested TLVs tracking depth
            std::size_t depth = 1;
            while (depth > 0) {
                if (remaining() < 2)
                    return make_unexpected<TLV, DecodeError>(DecodeError("unterminated indefinite-length encoding", pos_));
                if (data_[pos_] == 0x00 && data_[pos_ + 1] == 0x00) {
                    pos_ += 2;
                    --depth;
                } else {
                    auto inner_tag = read_tag();
                    if (!inner_tag) return make_unexpected<TLV, DecodeError>(inner_tag.error());
                    auto inner_len = read_length();
                    if (!inner_len) return make_unexpected<TLV, DecodeError>(inner_len.error());
                    if (inner_len->indefinite) {
                        if (!inner_tag->constructed)
                            return make_unexpected<TLV, DecodeError>(
                                DecodeError("indefinite-length encoding on primitive type", pos_ - 1));
                        ++depth;
                    } else {
                        if (remaining() < inner_len->len)
                            return make_unexpected<TLV, DecodeError>(DecodeError("truncated nested value", pos_));
                        pos_ += inner_len->len;
                    }
                }
            }
            std::size_t end = pos_ - 2;
            return TLV{tag, data_.subspan(start, end - start), true};
        }

        auto val_r = read_bytes(len_r->len);
        if (!val_r) return make_unexpected<TLV, DecodeError>(val_r.error());
        return TLV{tag, *val_r, false};
    }

    /// @brief Read a complete TLV and return the full encoding (tag + length + value bytes).
    /// Unlike \c read_tlv(), the returned span includes the tag and length octets.
    Expected<std::span<const uint8_t>, DecodeError> read_raw_tlv() {
        std::size_t start = pos_;
        auto tlv = read_tlv();
        if (!tlv) return make_unexpected<std::span<const uint8_t>, DecodeError>(tlv.error());
        return data_.subspan(start, pos_ - start);
    }

    /// @brief Create a reader over \p slice (used to recurse into a TLV's value bytes).
    /// @param slice  Typically \c TLV::value from a prior \c read_tlv() call.
    BerReader sub(std::span<const uint8_t> slice) const {
        return BerReader{slice};
    }

private:
    // Decode one tag from data[pos], advancing pos.
    // Handles 1-byte tags (fast) and long-form multi-byte tags.
    // Returns sentinel Tag{Context, ~0u, false} if the stream is truncated or
    // the tag number overflows 5 base-128 bytes — callers must check number != ~0u.
    [[nodiscard]] static ASN1CPP_ALWAYS_INLINE Tag parse_tag_at(std::span<const uint8_t> data, std::size_t& pos) noexcept {
        uint8_t first  = data[pos++];
        TagClass cls   = static_cast<TagClass>((first >> 6) & 0x03);
        bool     constr = (first & 0x20) != 0;
        uint32_t num   = first & 0x1F;
        if (ASN1CPP_LIKELY(num != 0x1F)) return Tag{cls, num, constr};
        // Long-form tag: base-128 continuation bytes (up to 5)
        num = 0;
        for (int i = 0; i < 5; ++i) {
            if (ASN1CPP_UNLIKELY(pos >= data.size()))
                return Tag{TagClass::Context, ~0u, false};
            uint8_t b = data[pos++];
            num = (num << 7) | (b & 0x7F);
            if (ASN1CPP_LIKELY(!(b & 0x80))) return Tag{cls, num, constr};
        }
        return Tag{TagClass::Context, ~0u, false}; // > 5 continuation bytes
    }
};

} // namespace asn1
