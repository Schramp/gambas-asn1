#pragma once
#include <vector>
#include <span>
#include <cstdint>
#include <cstring>
#include <concepts>
#include "../Tag.hpp"

namespace asn1 {

/// @brief Output sink for BER/DER encoding — appends to a \c std::vector<uint8_t>.
///
/// Provides helpers for writing individual TLV components.  The high-level entry
/// points are \c write_primitive() and \c write_constructed(); lower-level
/// \c write_tag() / \c write_length() are used by the codec internally.
///
/// Usage:
/// @code
/// std::vector<uint8_t> buf;
/// asn1::BerWriter w{buf};
/// asn1::BerEncodeStream s{w};
/// asn1::BerCodec::instance().encode(s, MyType::asn_DEF, &obj);
/// // buf now holds the complete BER encoding of obj
/// @endcode
///
/// @see X.690 §8.1 — TLV structure; §8.1.2 — Identifier (tag) octets;
///      §8.1.3 — Length octets.
class BerWriter {
    std::vector<uint8_t>& buf_;

public:
    /// @brief Wrap \p buf for BER output.  \p buf must outlive this writer.
    explicit BerWriter(std::vector<uint8_t>& buf) : buf_(buf) {}

    /// @brief Encode and append the tag octets for \p t.
    /// Handles short-form (tag.number < 31) and long-form (base-128) tags.
    /// @see X.690 §8.1.2 — Identifier octets.
    void write_tag(Tag t) {
        uint8_t first = (static_cast<uint8_t>(t.cls) << 6)
                      | (t.constructed ? 0x20 : 0x00);
        if (t.number < 31) {
            buf_.push_back(first | static_cast<uint8_t>(t.number));
        } else {
            buf_.push_back(first | 0x1F);
            // Encode tag number in base-128 (big-endian, MSB set on all but last)
            uint8_t tmp[5];
            int i = 0;
            uint32_t n = t.number;
            do {
                tmp[i++] = n & 0x7F;
                n >>= 7;
            } while (n);
            for (int j = i - 1; j >= 0; --j)
                buf_.push_back(tmp[j] | (j ? 0x80 : 0x00));
        }
    }

    /// @brief Encode and append the length octets for \p len bytes.
    /// Uses short form (1 byte) for len < 128, long form otherwise.
    /// @see X.690 §8.1.3 — Length octets.
    void write_length(std::size_t len) {
        if (len < 128) {
            buf_.push_back(static_cast<uint8_t>(len));
        } else {
            uint8_t tmp[8];
            int i = 0;
            std::size_t n = len;
            while (n) { tmp[i++] = n & 0xFF; n >>= 8; }
            buf_.push_back(0x80 | static_cast<uint8_t>(i));
            for (int j = i - 1; j >= 0; --j)
                buf_.push_back(tmp[j]);
        }
    }

    /// @brief Append \p data verbatim (no tag or length).
    void append(std::span<const uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    /// @brief Append a single byte.
    void append_byte(uint8_t b) { buf_.push_back(b); }

    /// @brief Return the byte offset at which the next write will land.
    /// Use this to record a position before writing, then \c replace_at() to back-fill.
    std::size_t pos() const { return buf_.size(); }

    /// @brief Read a previously-written byte at absolute offset \p i.
    uint8_t at(std::size_t i) const { return buf_[i]; }

    /// @brief Overwrite \p old_n bytes at offset \p p with \p new_data[0..\p new_n-1].
    /// Same size: memcpy.  Shrink: memcpy + memmove.  Grow: insert (rare, used when a
    /// pre-reserved 3-byte length field turns out to need 4 bytes).
    void replace_at(std::size_t p, std::size_t old_n,
                    const uint8_t* new_data, std::size_t new_n) {
        if (old_n == new_n) {
            std::memcpy(buf_.data() + p, new_data, new_n);
        } else if (new_n < old_n) {
            std::memcpy(buf_.data() + p, new_data, new_n);
            const std::size_t tail = buf_.size() - p - old_n;
            std::memmove(buf_.data() + p + new_n, buf_.data() + p + old_n, tail);
            buf_.resize(buf_.size() - (old_n - new_n));
        } else {
            buf_.insert(buf_.begin() + static_cast<std::ptrdiff_t>(p + old_n),
                        new_n - old_n, 0x00);
            std::memcpy(buf_.data() + p, new_data, new_n);
        }
    }

    /// @brief Write a primitive TLV: tag octets + length octets + \p value bytes.
    /// @param t      Tag to encode.
    /// @param value  Raw value bytes to append after the length.
    void write_primitive(Tag t, std::span<const uint8_t> value) {
        write_tag(t);
        write_length(value.size());
        append(value);
    }

    /// @brief Write a constructed TLV: tag + length (back-filled) + content.
    /// Reserves 3 bytes for the length, calls \p fn to emit content into this writer,
    /// then back-fills the actual length.  For content ≤ 65535 bytes a \c memmove
    /// closes the pre-reserved gap without heap allocation.
    ///
    /// Usage:
    /// @code
    /// w.write_constructed(Tag{TagClass::Universal, 16, true}, [&](BerWriter& w) {
    ///     w.write_primitive(Tag{TagClass::Universal, 2, false}, int_bytes);
    /// });
    /// @endcode
    ///
    /// @param t   Tag for the constructed TLV.
    /// @param fn  Callable \c void(BerWriter&) that writes the content elements.
    template<std::invocable<BerWriter&> Fn>
    void write_constructed(Tag t, Fn&& fn) {
        write_tag(t);

        // Reserve 3 bytes for the length field (covers 0..65535 without shifting).
        const std::size_t len_pos      = buf_.size();
        buf_.resize(len_pos + 3);
        const std::size_t content_start = buf_.size();

        fn(*this);

        const std::size_t content_size = buf_.size() - content_start;

        if (content_size < 128) {
            // 1-byte length: shift content left by 2
            std::memmove(&buf_[content_start - 2], &buf_[content_start], content_size);
            buf_.resize(len_pos + 1 + content_size);
            buf_[len_pos] = static_cast<uint8_t>(content_size);
        } else if (content_size < 256) {
            // 2-byte length: shift content left by 1
            std::memmove(&buf_[content_start - 1], &buf_[content_start], content_size);
            buf_.resize(len_pos + 2 + content_size);
            buf_[len_pos]     = 0x81;
            buf_[len_pos + 1] = static_cast<uint8_t>(content_size);
        } else if (content_size < 65536) {
            // 3-byte length: no shift, fill in place
            buf_[len_pos]     = 0x82;
            buf_[len_pos + 1] = static_cast<uint8_t>(content_size >> 8);
            buf_[len_pos + 2] = static_cast<uint8_t>(content_size);
        } else {
            // >65535 bytes (up to 16MB): 4-byte length (0x83 + 3 bytes).
            // Insert one extra byte before content to extend the reserved 3→4 bytes.
            buf_.insert(buf_.begin() + (std::ptrdiff_t)content_start, 0x00);
            buf_[len_pos]     = 0x83;
            buf_[len_pos + 1] = static_cast<uint8_t>(content_size >> 16);
            buf_[len_pos + 2] = static_cast<uint8_t>(content_size >> 8);
            buf_[len_pos + 3] = static_cast<uint8_t>(content_size);
        }
    }
};

} // namespace asn1
