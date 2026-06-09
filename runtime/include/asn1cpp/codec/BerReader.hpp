#pragma once
#include <span>
#include <cstdint>
#include <cstddef>
#include <format>
#include "../Tag.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"

#if defined(__GNUC__) || defined(__clang__)
#  define ASN1CPP_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define ASN1CPP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define ASN1CPP_LIKELY(x)   (x)
#  define ASN1CPP_UNLIKELY(x) (x)
#endif

namespace asn1 {

class BerReader {
    std::span<const uint8_t> data_;
    std::size_t pos_{0};

public:
    explicit BerReader(std::span<const uint8_t> data) : data_(data) {}

    bool at_end()  const { return pos_ >= data_.size(); }
    std::size_t remaining() const { return pos_ < data_.size() ? data_.size() - pos_ : 0; }
    std::size_t pos()   const { return pos_; }

    // Peek at data without consuming
    std::span<const uint8_t> peek(std::size_t n) const {
        std::size_t avail = std::min(n, remaining());
        return data_.subspan(pos_, avail);
    }

    // Peek at the next TLV tag without advancing pos_.
    // Returns nullopt (as a Tag with number=~0u) on failure.
    Tag peek_tag() const {
        std::size_t save = pos_;
        // We need mutable access to call read_tag, so use a temp reader.
        BerReader tmp{data_.subspan(save)};
        auto r = tmp.read_tag();
        if (!r) return Tag{TagClass::Context, ~0u, false};
        return *r;
    }

    Expected<Tag, DecodeError> read_tag() {
        if (at_end())
            return make_unexpected<Tag, DecodeError>(DecodeError("unexpected end of data reading tag", pos_));

        uint8_t first = data_[pos_++];
        TagClass cls   = static_cast<TagClass>((first >> 6) & 0x03);
        bool constr    = (first & 0x20) != 0;
        uint32_t num   = first & 0x1F;

        if (num == 0x1F) {
            // Long-form tag
            num = 0;
            for (int i = 0; i < 5; ++i) {
                if (at_end())
                    return make_unexpected<Tag, DecodeError>(DecodeError("truncated long-form tag", pos_));
                uint8_t b = data_[pos_++];
                num = (num << 7) | (b & 0x7F);
                if (!(b & 0x80)) break;
                if (i == 4)
                    return make_unexpected<Tag, DecodeError>(DecodeError("long-form tag too large", pos_));
            }
        }
        return Tag{cls, num, constr};
    }

    struct LengthResult {
        std::size_t len;
        bool indefinite;
    };

    Expected<LengthResult, DecodeError> read_length() {
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

    // Read and consume exactly n bytes.
    Expected<std::span<const uint8_t>, DecodeError> read_bytes(std::size_t n) {
        if (remaining() < n)
            return make_unexpected<std::span<const uint8_t>, DecodeError>(
                DecodeError(std::format("need {} bytes but only {} remain", n, remaining()), pos_));
        auto s = data_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    // Read a complete TLV returning a sub-reader over the value bytes.
    // For indefinite-length, reads until the EOC marker.
    struct TLV {
        Tag tag;
        std::span<const uint8_t> value; // empty for indefinite-length (use value_reader)
        bool indefinite;
    };

    Expected<TLV, DecodeError> read_tlv() {
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

    // Read a complete TLV and return the full byte span (tag + length + value).
    Expected<std::span<const uint8_t>, DecodeError> read_raw_tlv() {
        std::size_t start = pos_;
        auto tlv = read_tlv();
        if (!tlv) return make_unexpected<std::span<const uint8_t>, DecodeError>(tlv.error());
        return data_.subspan(start, pos_ - start);
    }

    // Create a sub-reader over a slice of the current data (for recursing into value bytes)
    BerReader sub(std::span<const uint8_t> slice) const {
        return BerReader{slice};
    }
};

} // namespace asn1
