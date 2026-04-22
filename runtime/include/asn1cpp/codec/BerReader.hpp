#pragma once
#include <span>
#include <cstdint>
#include <cstddef>
#include <format>
#include "../Tag.hpp"
#include "../Error.hpp"
#include "../Expected.hpp"

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
        auto tag_r = read_tag();
        if (!tag_r) return make_unexpected<TLV, DecodeError>(tag_r.error());
        Tag tag = *tag_r;

        auto len_r = read_length();
        if (!len_r) return make_unexpected<TLV, DecodeError>(len_r.error());

        if (len_r->indefinite) {
            std::size_t start = pos_;
            if (!tag.constructed) {
                // Primitive indefinite-length: scan raw bytes for EOC (00 00)
                while (pos_ + 1 < data_.size()) {
                    if (data_[pos_] == 0x00 && data_[pos_ + 1] == 0x00) {
                        std::size_t end = pos_;
                        pos_ += 2;
                        return TLV{tag, data_.subspan(start, end - start), true};
                    }
                    ++pos_;
                }
                return make_unexpected<TLV, DecodeError>(DecodeError("unterminated indefinite-length encoding", pos_));
            }
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

    // Create a sub-reader over a slice of the current data (for recursing into value bytes)
    BerReader sub(std::span<const uint8_t> slice) const {
        return BerReader{slice};
    }
};

} // namespace asn1
