#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <vector>
#include <span>
#include "ICodec.hpp"
#include "Constraints.hpp"
#include "Debug.hpp"
#include "../Tag.hpp"
#include "../Asn1Object.hpp"
#include "../SeqOfBase.hpp"
#include "../types/Real.hpp"
#include "../types/BitString.hpp"
#include "../types/OctetString.hpp"
#include "../types/Oid.hpp"
#include "../types/Strings.hpp"
#include "../codec/BerWriter.hpp"
#include "../codec/BerReader.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// Bit-level stream wrappers for PER (UPER / APER)

class PerEncodeStream : public IEncodeStream {
    std::vector<uint8_t>& buf_;
    uint8_t current_{0};
    int     bits_{0};

    void put_bits_impl(uint64_t value, int n) {
        for (int i = n - 1; i >= 0; --i) {
            int bit = (value >> i) & 1;
            current_ |= static_cast<uint8_t>(bit << (7 - bits_));
            if (++bits_ == 8) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
        }
    }
public:
    explicit PerEncodeStream(std::vector<uint8_t>& buf) : buf_(buf) {}

    int bit_pos() const { return static_cast<int>(buf_.size()) * 8 + bits_; }

    // put_bits(val, n) — unnamed: basic DBG_PER trace (offset + bits + value).
    void put_bits(uint64_t value, int n) {
        if (n > 0 && (debug_flags() & DBG_PER)) {
            int off = bit_pos();
            std::fprintf(stderr, "[PER-ENC] @%4d +%2d ", off, n);
            for (int i = n-1; i >= 0; --i) std::fprintf(stderr, "%d", (int)((value>>i)&1));
            std::fprintf(stderr, " (%llu)\n", (unsigned long long)value);
        }
        put_bits_impl(value, n);
    }

    // put_bits(val, n, field_name) — named overload.
    // Compile with -DASN1CPP_PER_TRACE to include field-name logging (runtime-gated by DBG_PER).
    // Without ASN1CPP_PER_TRACE: field_name discarded, delegates to put_bits(val, n).
    void put_bits(uint64_t value, int n, const char* field_name) {
#ifdef ASN1CPP_PER_TRACE
        if (n > 0 && (debug_flags() & DBG_PER)) {
            int off = bit_pos();
            std::fprintf(stderr, "[PER-ENC] @%4d +%2d %-24s ", off, n, field_name);
            for (int i = n-1; i >= 0; --i) std::fprintf(stderr, "%d", (int)((value>>i)&1));
            std::fprintf(stderr, " (%llu)\n", (unsigned long long)value);
        }
        put_bits_impl(value, n);
#else
        (void)field_name;
        put_bits(value, n);
#endif
    }

    void flush() {
        if (bits_ > 0 || buf_.empty()) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
    }

    std::vector<uint8_t>& buf() { return buf_; }
};

class PerDecodeStream : public IDecodeStream {
    std::span<const uint8_t> buf_;
    int byte_pos_{0};
    int bit_pos_{0};
    int skipped_ext_count_{0};
public:
    explicit PerDecodeStream(std::span<const uint8_t> buf) : buf_(buf) {}

    // Number of unknown extension members skipped during the last decode call.
    // Nonzero means the stream contained a newer schema version than ours.
    int  skipped_extensions() const { return skipped_ext_count_; }
    void reset_skipped_extensions()  { skipped_ext_count_ = 0; }
    // Called by skip_open_type() in PerCodec.cpp — not for general use.
    void increment_skipped_extensions() { ++skipped_ext_count_; }

    bool at_end() const override {
        return byte_pos_ >= static_cast<int>(buf_.size());
    }

    int bit_pos() const { return byte_pos_ * 8 + bit_pos_; }
    int total_bits() const { return static_cast<int>(buf_.size()) * 8; }

    Expected<uint64_t, DecodeError> get_bits(int n) {
        int off = bit_pos();
        uint64_t result = 0;
        for (int i = 0; i < n; ++i) {
            if (byte_pos_ >= static_cast<int>(buf_.size())) {
                if (debug_flags() & DBG_PER)
                    std::fprintf(stderr, "[PER-DEC] @%4d +%2d EOF (total=%d)\n",
                                 off, n, total_bits());
                return make_unexpected<uint64_t, DecodeError>(
                    DecodeError("PER: unexpected end of data"));
            }
            int bit = (buf_[byte_pos_] >> (7 - bit_pos_)) & 1;
            result = (result << 1) | static_cast<uint64_t>(bit);
            if (++bit_pos_ == 8) { ++byte_pos_; bit_pos_ = 0; }
        }
        if (debug_flags() & DBG_PER) {
            std::fprintf(stderr, "[PER-DEC] @%4d +%2d ", off, n);
            for (int i = n-1; i >= 0; --i) std::fprintf(stderr, "%d", (int)((result>>i)&1));
            std::fprintf(stderr, " (%llu)\n", (unsigned long long)result);
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// PER inline helpers (accessible to handler classes and callers)

namespace per_detail {

inline void put_length(PerEncodeStream& stream, std::size_t n) {
    if (n <= 127) {
        stream.put_bits(n, 8);
    } else if (n <= 16383) {
        stream.put_bits(0x80 | (n >> 8), 8);
        stream.put_bits(n & 0xFF, 8);
    }
}

inline Expected<std::size_t, DecodeError> get_length(PerDecodeStream& stream) {
    auto first = stream.get_bits(8);
    if (!first) return make_unexpected<std::size_t, DecodeError>(first.error());
    if (!(*first & 0x80)) return static_cast<std::size_t>(*first);
    if ((*first & 0xC0) == 0x80) {
        auto second = stream.get_bits(8);
        if (!second) return make_unexpected<std::size_t, DecodeError>(second.error());
        return static_cast<std::size_t>((*first & 0x3F) << 8 | *second);
    }
    return make_unexpected<std::size_t, DecodeError>(
        DecodeError("PER: fragmented length not implemented"));
}

inline Expected<std::vector<uint8_t>, DecodeError> read_bytes(PerDecodeStream& stream, std::size_t n) {
    std::vector<uint8_t> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        auto b = stream.get_bits(8);
        if (!b) return make_unexpected<std::vector<uint8_t>, DecodeError>(b.error());
        out.push_back(static_cast<uint8_t>(*b));
    }
    return out;
}

template<typename T>
inline void encode_ber_content(PerEncodeStream& stream, const Asn1Object* src) {
    std::vector<uint8_t> ber;
    { BerWriter w{ber}; BerTraits<T>::encode(w, *static_cast<const T*>(src)); }
    uint8_t content_len = ber[1];
    put_length(stream, content_len);
    for (int i = 0; i < content_len; ++i) stream.put_bits(ber[2 + i], 8);
}

template<typename T>
inline DecodeResult decode_ber_content(PerDecodeStream& stream, Asn1Object* dest) {
    auto len_r = get_length(stream);
    if (!len_r) return decode_err(len_r.error());
    auto content = read_bytes(stream, *len_r);
    if (!content) return decode_err(content.error());
    std::vector<uint8_t> ber;
    const auto tag = BerTraits<T>::tag();
    ber.push_back(static_cast<uint8_t>(tag.number));
    ber.push_back(static_cast<uint8_t>(*len_r));
    ber.insert(ber.end(), content->begin(), content->end());
    BerReader r{ber};
    auto v = BerTraits<T>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<T*>(dest) = *v;
    return decode_ok();
}

} // namespace per_detail

// ---------------------------------------------------------------------------
// Per-type handler interface

class PerCodec;

struct IPerTypeHandler {
    virtual ~IPerTypeHandler() = default;
    virtual void encode(const PerCodec& codec, PerEncodeStream& stream,
                        const TypeDescriptor& def, const Asn1Object* src) const = 0;
    virtual DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                                const TypeDescriptor& def, Asn1Object* dest) const = 0;
};

// ---------------------------------------------------------------------------
// PerCodec — generic PER encode/decode driven by TypeDescriptor tables

class PerCodec : public ICodec {
public:
    static PerCodec& instance() {
        static PerCodec inst;
        return inst;
    }

    const char* name() const override { return "PER"; }

    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const Asn1Object* src) const override;

    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        Asn1Object* dest) const override;

};

} // namespace asn1
