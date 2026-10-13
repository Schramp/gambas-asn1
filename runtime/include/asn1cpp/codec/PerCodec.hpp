#pragma once
#include <algorithm>
#include <cassert>
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

/// @brief \c IEncodeStream adapter for PER — writes bit-by-bit into a \c std::vector<uint8_t>.
///
/// Construct on the stack, pass by reference to \c PerCodec::encode().
/// @code
/// std::vector<uint8_t> buf;
/// asn1::PerEncodeStream s{buf};
/// asn1::PerCodec::instance().encode(s, MyType::asn_DEF, &obj);
/// s.flush();  // pad final byte
/// @endcode
/// @see X.691 — Packed Encoding Rules (PER).
class PerEncodeStream : public IEncodeStream {
    std::vector<uint8_t>& buf_;
    uint8_t current_{0};
    int     bits_{0};
    bool    encode_failed_{false};

    void put_bits_impl(uint64_t value, int n) {
        for (int i = n - 1; i >= 0; --i) {
            int bit = (value >> i) & 1;
            current_ |= static_cast<uint8_t>(bit << (7 - bits_));
            if (++bits_ == 8) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
        }
    }
public:
    /// @brief Construct wrapping \p buf.  \p buf must outlive this stream.
    explicit PerEncodeStream(std::vector<uint8_t>& buf) : buf_(buf) {}

    /// @brief Current write position in bits (committed bytes × 8 + pending bits).
    int bit_pos() const { return static_cast<int>(buf_.size()) * 8 + bits_; }

    /// @brief Write the low \p n bits of \p value MSB-first.
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

    /// @brief Pad and flush the current partial byte to the buffer.
    /// Must be called after the last \c put_bits() to ensure the final byte is committed.
    void flush() {
        if (bits_ > 0 || buf_.empty()) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
    }

    /// @brief Signal a constraint violation during encode.
    /// The caller must return immediately after calling this; bits already in the buffer
    /// are discarded by the call site on encode failure.
    void set_encode_failed(const char* reason) {
        encode_failed_ = true;
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-ENC] constraint violation: %s\n", reason);
    }
    /// @return True if any constraint violation was signalled during this encode.
    bool encode_failed() const { return encode_failed_; }

    std::vector<uint8_t>& buf() { return buf_; }
};

/// @brief \c IDecodeStream adapter for PER — reads bit-by-bit from a byte span.
///
/// Construct on the stack, pass by reference to \c PerCodec::decode().
/// @code
/// asn1::PerDecodeStream s{data_span};
/// MyType obj{};
/// auto ok = asn1::PerCodec::instance().decode(s, MyType::asn_DEF, &obj);
/// @endcode
/// @see X.691 — Packed Encoding Rules (PER).
class PerDecodeStream : public IDecodeStream {
    std::span<const uint8_t> buf_;
    int byte_pos_{0};
    int bit_pos_{0};
    int skipped_ext_count_{0};
public:
    /// @brief Construct over \p buf.  \p buf must outlive this stream.
    explicit PerDecodeStream(std::span<const uint8_t> buf) : buf_(buf) {}

    /// @brief Number of extension alternatives skipped since the last \c reset_skipped_extensions().
    /// Non-zero indicates a version skew between encoder and decoder schemas.
    int  skipped_extensions() const { return skipped_ext_count_; }
    /// @brief Reset the skipped-extension counter to zero.
    void reset_skipped_extensions()  { skipped_ext_count_ = 0; }

    /// @brief Return true when all input bits have been consumed.
    bool at_end() const override {
        return byte_pos_ >= static_cast<int>(buf_.size());
    }

    /// @brief Read and consume \p n bits, returning them as a \c uint64_t (MSB-first).
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

private:
    friend class PerCodec;
    int  bit_pos()    const { return byte_pos_ * 8 + bit_pos_; }
    int  total_bits() const { return static_cast<int>(buf_.size()) * 8; }
    DecodeResult skip_open_type();          // defined in PerCodec.cpp
    void increment_skipped_extensions() { ++skipped_ext_count_; }
};

// ---------------------------------------------------------------------------
// PER inline helpers (accessible to handler classes and callers)

namespace per_detail {

/// Fragment granularity of X.691 §10.9.3.8: 16K items.
inline constexpr std::size_t kFragmentUnit = 16384;

/// @brief X.691 §10.9.3.6–10.9.3.7 length determinant for \p n < 16K:
///        short form (≤127, one octet) or long form (two octets, top bits
///        0b10). A count of 16K or more is only valid together with its
///        items, through put_length_and_items().
inline void put_length(PerEncodeStream& stream, std::size_t n) {
    assert(n < kFragmentUnit && "lengths >= 16K need put_length_and_items");
    if (n <= 127) {
        stream.put_bits(n, 8);
    } else {
        stream.put_bits(0x80 | (n >> 8), 8);
        stream.put_bits(n & 0xFF, 8);
    }
}

/// @brief Decode counterpart of put_length(); a fragment header (0b11) is
///        an error here, since only get_length_and_items() consumes fragments.
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
        DecodeError("PER: fragmented length where a single length is required"));
}

/// @brief Writes a general length determinant for \p n items followed by
///        the items, fragmenting at 16K (X.691 §10.9.3.5–10.9.3.8).
/// @param n     Total item count (octets, bits, characters or components).
/// @param items Callable `(std::size_t from, std::size_t to)` writing the
///              items with indices in [from, to).
/// @note While 16K or more items remain, a header octet 0b11000kkk
///       announces k (1..4) blocks of 16K items, then the remaining count is
///       encoded the same way; a remainder of 0 yields the trailing 00 octet
///       of the §10.9.3.8.3 note.
template<typename WriteItems>
inline void put_length_and_items(PerEncodeStream& stream, std::size_t n, WriteItems&& items) {
    std::size_t start = 0;
    for (;;) {
        std::size_t rem = n - start;
        if (rem < kFragmentUnit) {
            put_length(stream, rem);
            items(start, n);
            return;
        }
        std::size_t k = std::min<std::size_t>(rem / kFragmentUnit, 4);
        stream.put_bits(0xC0 | k, 8);
        items(start, start + k * kFragmentUnit);
        start += k * kFragmentUnit;
    }
}

/// @brief Decode counterpart of put_length_and_items(): reads every
///        fragment, handing each item count to \p items.
/// @param items Callable `(std::size_t m) -> DecodeResult` reading m items.
/// @return The total item count.
template<typename ReadItems>
inline Expected<std::size_t, DecodeError> get_length_and_items(PerDecodeStream& stream, ReadItems&& items) {
    std::size_t total = 0;
    for (;;) {
        auto first = stream.get_bits(8);
        if (!first) return make_unexpected<std::size_t, DecodeError>(first.error());
        if ((*first & 0xC0) == 0xC0) {
            std::size_t k = *first & 0x3F;
            if (k < 1 || k > 4)
                return make_unexpected<std::size_t, DecodeError>(
                    DecodeError("PER: fragment multiplier outside 1..4"));
            if (auto r = items(k * kFragmentUnit); !r)
                return make_unexpected<std::size_t, DecodeError>(r.error());
            total += k * kFragmentUnit;
            continue;
        }
        std::size_t n = *first;
        if (*first & 0x80) {
            auto second = stream.get_bits(8);
            if (!second) return make_unexpected<std::size_t, DecodeError>(second.error());
            n = ((*first & 0x3F) << 8) | *second;
        }
        if (auto r = items(n); !r)
            return make_unexpected<std::size_t, DecodeError>(r.error());
        return total + n;
    }
}

/// @brief General length plus octets (open types, OID/REAL contents).
inline void put_octets(PerEncodeStream& stream, const uint8_t* data, std::size_t n) {
    put_length_and_items(stream, n, [&](std::size_t from, std::size_t to) {
        for (std::size_t i = from; i < to; ++i) stream.put_bits(data[i], 8);
    });
}

/// @brief Decode counterpart of put_octets().
inline Expected<std::vector<uint8_t>, DecodeError> get_octets(PerDecodeStream& stream) {
    std::vector<uint8_t> out;
    auto n = get_length_and_items(stream, [&](std::size_t m) -> DecodeResult {
        out.reserve(out.size() + m);
        for (std::size_t i = 0; i < m; ++i) {
            auto b = stream.get_bits(8);
            if (!b) return decode_err(b.error());
            out.push_back(static_cast<uint8_t>(*b));
        }
        return decode_ok();
    });
    if (!n) return make_unexpected<std::vector<uint8_t>, DecodeError>(n.error());
    return out;
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

/// @brief Internal per-type PER handler interface.
/// Not part of the public API — use \c PerCodec directly.
struct IPerTypeHandler {
    virtual ~IPerTypeHandler() = default;
    virtual void encode(const PerCodec& codec, PerEncodeStream& stream,
                        const TypeDescriptor& def, const Asn1Object* src) const = 0;
    virtual DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                                const TypeDescriptor& def, Asn1Object* dest) const = 0;
};

// ---------------------------------------------------------------------------
// PerCodec — generic PER encode/decode driven by TypeDescriptor tables

/// @brief PER codec singleton (UPER / APER — aligned flag in the descriptor).
///
/// The interface mirrors \c BerCodec and \c XerCodec; all encode/decode logic is
/// table-driven.  The singleton is stateless and thread-safe.
///
/// **Note:** PER support is fully implemented for all SEQUENCE, CHOICE, SEQUENCE OF,
/// ENUMERATED, INTEGER (constrained), and common string types.  Verify constraint
/// coverage for your schema before using in production.
///
/// @see X.691 — Packed Encoding Rules; \c BerCodec — BER equivalent.
class PerCodec : public ICodec {
public:
    /// @brief Return the process-wide \c PerCodec singleton.
    static PerCodec& instance() {
        static PerCodec inst;
        return inst;
    }

    /// @brief Return \c "PER".
    const char* name() const override { return "PER"; }

    /// @brief PER-encode \p src into the \c PerEncodeStream wrapped by \p dst.
    /// Call \c PerEncodeStream::flush() after encode to commit the final partial byte.
    /// @param dst  Must be a \c PerEncodeStream.
    /// @param def  TypeDescriptor of the value.
    /// @param src  Source object; must not be null.
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const Asn1Object* src) const override;

    /// @brief PER-decode from \p src into \p dest.
    /// \p dest must be default-constructed before the call.
    /// @param src   Must be a \c PerDecodeStream.
    /// @param def   TypeDescriptor of the expected type.
    /// @param dest  Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — check with \c .has_value().
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        Asn1Object* dest) const override;

    // Codec-internal helpers — for use by PerCodec handler classes only.
    static int           stream_bit_pos(const PerEncodeStream& s) { return s.bit_pos(); }
    static int           stream_bit_pos(const PerDecodeStream& s) { return s.bit_pos(); }
    static int           stream_total_bits(const PerDecodeStream& s) { return s.total_bits(); }
    static DecodeResult  skip_ext(PerDecodeStream& s) { return s.skip_open_type(); }
};

} // namespace asn1
