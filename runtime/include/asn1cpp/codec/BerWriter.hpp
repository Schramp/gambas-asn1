#pragma once
#include <vector>
#include <span>
#include <cstdint>
#include <concepts>
#include "../Tag.hpp"

namespace asn1 {

class BerWriter {
    std::vector<uint8_t>& buf_;

public:
    explicit BerWriter(std::vector<uint8_t>& buf) : buf_(buf) {}

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

    void append(std::span<const uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    void append_byte(uint8_t b) { buf_.push_back(b); }

    // Write a primitive TLV: tag + length + raw value bytes.
    void write_primitive(Tag t, std::span<const uint8_t> value) {
        write_tag(t);
        write_length(value.size());
        append(value);
    }

    // Write a constructed TLV: encode value into a temp buffer, then emit.
    // Fn signature: void(BerWriter&)
    template<std::invocable<BerWriter&> Fn>
    void write_constructed(Tag t, Fn&& fn) {
        std::vector<uint8_t> tmp;
        BerWriter inner(tmp);
        fn(inner);
        write_tag(t);
        write_length(tmp.size());
        append(tmp);
    }
};

} // namespace asn1
