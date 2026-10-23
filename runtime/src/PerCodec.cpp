#include <cassert>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <asn1cpp/codec/DecodeDepth.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/ContainedDecoders.hpp>
#include <asn1cpp/codec/Alphabets.hpp>
#include <asn1cpp/codec/Validation.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/Integer.hpp>

namespace asn1 {

// X.691 §10.2 — skip unknown open-type field by length-prefixed byte count.
DecodeResult PerDecodeStream::skip_open_type() {
    auto bytes_r = per_detail::get_octets(*this);
    if (!bytes_r) return decode_err(bytes_r.error());
    increment_skipped_extensions();
    return decode_ok();
}

// Unnamed namespace: limits symbol visibility to this translation unit (equivalent to static
// for free functions in C++). Intentional — these helpers are internal codec primitives.
namespace {

// ---------------------------------------------------------------------------
// Utility functions
// Standard reference: ITU-T Rec. X.691 (1997) — Packed Encoding Rules (PER)
// File: asn1-docs/X.691-199712.txt  Grep: grep -n "<title>" X.691-199712.txt

// X.691 §10.9.3.4 / §10.6 short-form bit-field width and value range shared by
// "normally small length" (nslength) and "normally small non-negative whole
// number" (nsnn) — both pack a short-form value into this many bits, falling
// back to a general length determinant (per_detail::put_length) above it.
static constexpr int kShortFormBits   = 6;
static constexpr int kNsLengthMax     = 64; // nslength short-form: n in [1..64], stored as n-1
static constexpr int kNsnnMax         = 63; // nsnn short-form: n in [0..63], stored as-is

// X.691 §10.9.3.4 "Where the length determinant is a normally small length and
// "n" is less than or equal to 64, a single-bit bit-field [...]"
// Flag=0: n in [1..64], encode n-1 in kShortFormBits bits. Flag=1: delegate to put_length().
static void put_nslength(PerEncodeStream& stream, std::size_t n) {
    if (n >= 1 && n <= kNsLengthMax) { stream.put_bits(0, 1); stream.put_bits(n - 1, kShortFormBits); }
    else { stream.put_bits(1, 1); per_detail::put_length(stream, n); }
}

// X.691 §10.9.3.4 — see put_nslength above.
static Expected<std::size_t, DecodeError> get_nslength(PerDecodeStream& stream) {
    auto b = stream.get_bits(1);
    if (!b) return make_unexpected<std::size_t, DecodeError>(b.error());
    if (*b == 0) {
        auto v = stream.get_bits(kShortFormBits);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return *v + 1;
    }
    return per_detail::get_length(stream);
}


// X.691 §10.6 "Encoding of a normally small non-negative whole number"
// Flag=0: value in [0..63], encode in kShortFormBits bits. Flag=1: delegate to put_length().
static void put_nsnn(PerEncodeStream& stream, int n) {
    if (n <= kNsnnMax) { stream.put_bits(0, 1); stream.put_bits(static_cast<uint64_t>(n), kShortFormBits); }
    else { stream.put_bits(1, 1); per_detail::put_length(stream, static_cast<std::size_t>(n)); }
}

// X.691 §10.6 — see put_nsnn above.
static Expected<int, DecodeError> get_nsnn(PerDecodeStream& stream) {
    auto b = stream.get_bits(1);
    if (!b) return make_unexpected<int, DecodeError>(b.error());
    if (*b == 0) {
        auto v = stream.get_bits(kShortFormBits);
        if (!v) return make_unexpected<int, DecodeError>(v.error());
        return static_cast<int>(*v);
    }
    auto len = per_detail::get_length(stream);
    if (!len) return make_unexpected<int, DecodeError>(len.error());
    return static_cast<int>(*len);
}

// X.691 §10.5.6 "In the case of the UNALIGNED variant the value ("n" - "lb") shall be
// encoded as a non-negative binary-integer in a bit-field [...] with the minimum number
// of bits necessary to represent the range."
// Returns the minimum bit width to represent values in [0 .. range-1].
static int range_bits(int64_t range) {
    if (range <= 1) return 0;
    int bits = 0;
    for (int64_t r = range - 1; r > 0; r >>= 1) ++bits;
    return bits;
}

/// @brief True when a SIZE constraint selects the constrained-count form of
///        the length (X.691 §10.9.4.1, UNALIGNED): constrained with ub < 64K,
///        the rule asn1c applies. Otherwise the general, fragmentable length.
static bool size_count_is_constrained(const Constraints& pc) {
    return (pc.flags & Constraints::SIZE_CONSTRAINED) && pc.size_upper < 65536;
}

/// @brief Writes a SIZE length determinant for \p n items, then the items
///        (X.691 §10.9): nothing for a fixed size, the offset from the lower
///        bound for a constrained size with ub < 64K, otherwise the general
///        length with 16K fragmentation (per_detail::put_length_and_items).
/// @param items Callable `(std::size_t from, std::size_t to)` writing items.
template<typename WriteItems>
static void encode_size_and_items(PerEncodeStream& stream, const Constraints& pc,
                                  std::size_t n, WriteItems&& items) {
    if (size_count_is_constrained(pc)) {
        if (pc.size_range_bits > 0)
            stream.put_bits(n - static_cast<std::size_t>(pc.size_lower), pc.size_range_bits, "SIZE");
        items(std::size_t{0}, n);
    } else {
        per_detail::put_length_and_items(stream, n, items);
    }
}

/// @brief Decode counterpart of encode_size_and_items().
/// @param items Callable `(std::size_t m) -> DecodeResult` reading m items.
/// @return The total item count.
template<typename ReadItems>
static Expected<std::size_t, DecodeError> decode_size_and_items(PerDecodeStream& stream,
                                                                const Constraints& pc,
                                                                ReadItems&& items) {
    if (!size_count_is_constrained(pc)) return per_detail::get_length_and_items(stream, items);
    std::size_t n = static_cast<std::size_t>(pc.size_lower);
    if (pc.size_range_bits > 0) {
        auto v = stream.get_bits(pc.size_range_bits);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        n += static_cast<std::size_t>(*v);
    }
    if (auto r = items(n); !r) return make_unexpected<std::size_t, DecodeError>(r.error());
    return n;
}

/// @brief encode_size_and_items() for OCTET STRING (X.691 §17.3), BIT STRING
///        (§16.6) and SEQUENCE OF / SET OF (§20.4), whose extensible SIZE
///        adds one bit first: 0 and the root form when \p n is within the
///        root, otherwise 1 and the general length (§10.9).
template<typename WriteItems>
static void encode_ext_size_and_items(PerEncodeStream& stream, const Constraints& pc,
                                      std::size_t n, WriteItems&& items) {
    if ((pc.flags & Constraints::EXTENSIBLE) && (pc.flags & Constraints::SIZE_CONSTRAINED)) {
        const auto sn = static_cast<int64_t>(n);
        const bool in_root = sn >= pc.size_lower && sn <= pc.size_upper;
        stream.put_bits(in_root ? 0 : 1, 1, "SIZE.ext");
        if (!in_root) {
            per_detail::put_length_and_items(stream, n, items);
            return;
        }
    }
    encode_size_and_items(stream, pc, n, items);
}

/// @brief Decode counterpart of encode_ext_size_and_items().
template<typename ReadItems>
static Expected<std::size_t, DecodeError> decode_ext_size_and_items(PerDecodeStream& stream,
                                                                    const Constraints& pc,
                                                                    ReadItems&& items) {
    if ((pc.flags & Constraints::EXTENSIBLE) && (pc.flags & Constraints::SIZE_CONSTRAINED)) {
        auto ext = stream.get_bits(1);
        if (!ext) return make_unexpected<std::size_t, DecodeError>(ext.error());
        if (*ext) return per_detail::get_length_and_items(stream, items);
    }
    return decode_size_and_items(stream, pc, items);
}

// X.691 §10.8 "Encoding of an unconstrained whole number"
// 2's-complement, minimum octets, preceded by 8-bit octet count.
static void encode_unconstrained_int(PerEncodeStream& stream, int64_t value) {
    uint8_t buf[8]; int len = 0;
    if (value == 0) { buf[0] = 0; len = 1; }
    else {
        uint64_t u = static_cast<uint64_t>(value);
        for (int i = 7; i >= 0; --i) { buf[i] = u & 0xFF; u >>= 8; }
        int start = 0;
        if (value > 0) {
            while (start < 7 && buf[start] == 0x00 && !(buf[start+1] & 0x80)) ++start;
        } else {
            while (start < 7 && buf[start] == 0xFF && (buf[start+1] & 0x80)) ++start;
        }
        len = 8 - start;
        std::memmove(buf, buf + start, len);
    }
    stream.put_bits(static_cast<uint64_t>(len), 8);
    for (int i = 0; i < len; ++i) stream.put_bits(buf[i], 8);
}

// X.691 §10.8 — see encode_unconstrained_int above.
static DecodeResult decode_unconstrained_int(PerDecodeStream& stream, int64_t* dest) {
    auto len_bits = stream.get_bits(8);
    if (!len_bits) return decode_err(len_bits.error());
    int len = static_cast<int>(*len_bits);
    if (len == 0 || len > 8)
        return decode_err(DecodeError("PER: INTEGER length out of range"));
    int64_t value = 0;
    for (int i = 0; i < len; ++i) {
        auto b = stream.get_bits(8);
        if (!b) return decode_err(b.error());
        if (i == 0 && (*b & 0x80)) value = -1;
        value = (value << 8) | static_cast<int64_t>(*b);
    }
    *dest = value;
    return decode_ok();
}

// X.691 §26.5 "This subclause applies to known-multiplier character strings"
// NumericString: space=0, '0'-'9'=1-10 (4 bits per character).
static uint8_t encode_numeric_char(char c) {
    if (c == ' ') return 0;
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 1);
    return 0;
}

// X.691 §26.5 — see encode_numeric_char above.
static char decode_numeric_char(uint8_t v) {
    if (v == 0) return ' ';
    if (v >= 1 && v <= 10) return static_cast<char>('0' + (v - 1));
    return '?';
}

// X.691 §26.5 "This subclause applies to known-multiplier character strings"
// Returns {bits_per_char, bytes_per_char} for each string type:
//   NumericString: {4,1}, PrintableString/VisibleString/UTCTime/GeneralizedTime: {7,1},
//   BMPString: {8,2}, UniversalString: {8,4}, default: {8,1}.
// Used only when TypeDescriptor has no FROM alphabet (pc.alphabet_bits == 0).
static std::tuple<int,int> string_params(uint32_t tag_num) {
    switch (tag_num) {
        case UniversalTag::NumericString:   return {4, 1};
        case UniversalTag::PrintableString: return {7, 1};
        case UniversalTag::BmpString:       return {8, 2};
        case UniversalTag::UniversalString: return {8, 4};
        case UniversalTag::Ia5String:       return {7, 1};  // 128-char alphabet → 7 bits/char
        case UniversalTag::UtcTime:
        case UniversalTag::GeneralizedTime:
        case UniversalTag::VisibleString:   return {7, 1};
        default:                            return {8, 1};
    }
}

// X.691 §22.6: alternatives emitted in canonical (tag-ascending) order by Generator.cpp.
// Runtime needs no sorting — array index IS the canonical index.

// X.691 §10.2 "Open type fields"
// Encodes value to temporary buffer; prepends octet-aligned length determinant.
static void encode_open_type(const PerCodec& codec, PerEncodeStream& stream,
                              const TypeDescriptor& mdef, const Asn1Object* mptr) {
    std::vector<uint8_t> tmp;
    PerEncodeStream tmp_s{tmp};
    IEncodeStream& es = tmp_s;
    codec.encode(es, mdef, mptr);
    if (tmp_s.encode_failed()) stream.set_encode_failed("open type contents");
    tmp_s.flush();
    per_detail::put_octets(stream, tmp.data(), tmp.size());
}

// X.691 §10.2 — see encode_open_type above.
static DecodeResult decode_open_type(const PerCodec& codec, PerDecodeStream& stream,
                                     const TypeDescriptor& mdef, Asn1Object* mptr) {
    auto bytes_r = per_detail::get_octets(stream);
    if (!bytes_r) return decode_err(bytes_r.error());
    PerDecodeStream tmp_s = stream.sub(std::span<const uint8_t>{bytes_r->data(), bytes_r->size()});
    IDecodeStream& ds = tmp_s;
    return codec.decode(ds, mdef, mptr);
}

// ---------------------------------------------------------------------------
// Handler classes

/// @brief Fallback for a dispatch-table slot with no PER codec. Encode
///        flags the stream as failed, decode returns an error, so a schema
///        construct the runtime cannot handle fails one record instead of
///        aborting the process.
class ErrorPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object*) const override {
        std::string reason = std::string("PerCodec: unsupported: ") + def.name;
        stream.set_encode_failed(reason.c_str());
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream&,
                        const TypeDescriptor& def, Asn1Object*) const override {
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-DEC] unsupported: %s\n", def.name);
        return decode_err(DecodeError(std::string("PerCodec: unsupported: ") + def.name));
    }
};

class AnyPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        per_detail::put_octets(stream, bytes.data(), bytes.size());
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto bytes_r = per_detail::get_octets(stream);
        if (!bytes_r) return decode_err(bytes_r.error());
        *static_cast<OctetString*>(dest) = OctetString(*bytes_r);
        return decode_ok();
    }
};

class BooleanPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        bool v = static_cast<const Boolean*>(src)->value();
        stream.put_bits(v ? 1 : 0, 1);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto bit = stream.get_bits(1);
        if (!bit) return decode_err(bit.error());
        static_cast<Boolean*>(dest)->set(*bit != 0);
        return decode_ok();
    }
};

/// @brief PER handler for INTEGER with signed 64-bit storage.
/// @see X.691 §13 — constrained (§11.5.6), semi-constrained (§11.7) and
///      unconstrained (§11.8) whole numbers, with the extensible escape (§13.2.2).
class IntegerPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const Constraints& pc = def.constraints;
        int64_t svalue = static_cast<const Integer*>(src)->value();

        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (svalue >= pc.lower_bound && svalue <= pc.upper_bound);
                stream.put_bits(in_root ? 0 : 1, 1, "INT.ext");
                if (!in_root) { encode_unconstrained_int(stream, svalue); return; }
            }
            // X.691 §11.5.6 UPER: value − lb in minimum bits, no length prefix.
            // Unsigned arithmetic: a range of up to 2^64 values exceeds int64_t.
            uint64_t encoded = static_cast<uint64_t>(svalue) - static_cast<uint64_t>(pc.lower_bound);
            stream.put_bits(encoded, pc.range_bits, "INT.value");
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (svalue >= pc.lower_bound);
                stream.put_bits(in_root ? 0 : 1, 1, "INT.ext");
                if (!in_root) { encode_unconstrained_int(stream, svalue); return; }
            }
            encode_unconstrained_int(stream, svalue - pc.lower_bound);
        } else {
            encode_unconstrained_int(stream, svalue);
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const Constraints& pc = def.constraints;
        auto* idest = static_cast<Integer*>(dest);

        auto read_raw_s = [&](int64_t& out) { return decode_unconstrained_int(stream, &out); };

        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = stream.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) {
                    int64_t v = 0;
                    auto r = read_raw_s(v);
                    if (r) idest->set(v);
                    return r;
                }
            }
            auto bits = stream.get_bits(pc.range_bits);
            if (!bits) return decode_err(bits.error());
            idest->set(static_cast<int64_t>(static_cast<uint64_t>(pc.lower_bound) + *bits));
            return decode_ok();
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = stream.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) {
                    int64_t v = 0;
                    auto r = read_raw_s(v);
                    if (r) idest->set(v);
                    return r;
                }
            }
            int64_t adjusted = 0;
            auto r = read_raw_s(adjusted);
            if (!r) return r;
            idest->set(adjusted + pc.lower_bound);
            return decode_ok();
        } else {
            int64_t v = 0;
            auto r = read_raw_s(v);
            if (r) idest->set(v);
            return r;
        }
    }
};

class UIntegerPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const Constraints& pc = def.constraints;
        uint64_t uvalue = static_cast<const UInteger*>(src)->value();

        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (uvalue >= pc.lower_u64 && uvalue <= pc.upper_u64);
                stream.put_bits(in_root ? 0 : 1, 1, "INT.ext");
                if (!in_root) { encode_unconstrained_int(stream, static_cast<int64_t>(uvalue)); return; }
            }
            uint64_t encoded = uvalue - pc.lower_u64;
            stream.put_bits(encoded, pc.range_bits, "INT.value");
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (uvalue >= pc.lower_u64);
                stream.put_bits(in_root ? 0 : 1, 1, "INT.ext");
                if (!in_root) { encode_unconstrained_int(stream, static_cast<int64_t>(uvalue)); return; }
            }
            encode_unconstrained_int(stream, static_cast<int64_t>(uvalue - pc.lower_u64));
        } else {
            encode_unconstrained_int(stream, static_cast<int64_t>(uvalue));
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const Constraints& pc = def.constraints;
        auto* udest = static_cast<UInteger*>(dest);

        auto read_raw_s = [&](int64_t& out) { return decode_unconstrained_int(stream, &out); };

        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = stream.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) {
                    int64_t v = 0;
                    auto r = read_raw_s(v);
                    if (r) udest->set(static_cast<uint64_t>(v));
                    return r;
                }
            }
            auto bits = stream.get_bits(pc.range_bits);
            if (!bits) return decode_err(bits.error());
            udest->set(*bits + pc.lower_u64);
            return decode_ok();
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = stream.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) {
                    int64_t v = 0;
                    auto r = read_raw_s(v);
                    if (r) udest->set(static_cast<uint64_t>(v));
                    return r;
                }
            }
            int64_t adjusted = 0;
            auto r = read_raw_s(adjusted);
            if (!r) return r;
            udest->set(static_cast<uint64_t>(adjusted) + pc.lower_u64);
            return decode_ok();
        } else {
            int64_t v = 0;
            auto r = read_raw_s(v);
            if (r) udest->set(static_cast<uint64_t>(v));
            return r;
        }
    }
};

class NullPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream&,
                const TypeDescriptor&, const Asn1Object*) const override {
        // NULL: zero bits (X.691 §18.1)
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream&,
                        const TypeDescriptor&, Asn1Object*) const override {
        return decode_ok();
    }
};

class RealPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const Real& real_val = *static_cast<const Real*>(src);
        // PLUS-ZERO (not MINUS-ZERO -- that has a real, non-empty BER
        // content byte 0x43, see BerTraits<Real>::encode) used to skip
        // the open-type wrapper entirely here. decode() always reads one
        // via per_detail::decode_ber_content regardless of value, so
        // this desynced the bit stream for every field after a
        // PLUS-ZERO REAL -- confirmed via a cpp-encoded PER stream that
        // cpp's own decoder then rejected. The zero-length case below
        // (content_len == 0) still needs its length-prefix written, same
        // as every other content_len.
        std::vector<uint8_t> ber;
        { BerWriter ber_writer{ber}; BerTraits<Real>::encode(ber_writer, real_val); }
        std::size_t content_len = ber[1];
        per_detail::put_length(stream, content_len);
        for (std::size_t i = 0; i < content_len; ++i) stream.put_bits(ber[2 + i], 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        return per_detail::decode_ber_content<Real>(stream, dest);
    }
};

class BitStringPerHandler final : public IPerTypeHandler {
public:
    /// @brief Encode a BIT STRING: length determinant in bits, then the bits.
    ///        A NamedBitList type is sent with trailing 0 bits removed and
    ///        padded with 0 bits up to the SIZE lower bound.
    /// @param stream  Bit-level output.
    /// @param def     Type descriptor; \c constraints carries SIZE and \c NAMED_BITS.
    /// @param src     The \c BitString value.
    /// @see X.691 §15.2, §15.3 (NamedBitList), §15.5–15.10 (length and bits).
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const BitString& v = *static_cast<const BitString*>(src);
        std::size_t bit_count = (def.constraints.flags & Constraints::NAMED_BITS)
            ? v.named_bits_length(def.constraints) : v.bit_count();
        encode_ext_size_and_items(stream, def.constraints, bit_count, [&](std::size_t from, std::size_t to) {
            for (std::size_t i = from; i < to; ++i)
                stream.put_bits(v.bit(i), 1);
        });
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        std::vector<uint8_t> bytes;
        std::size_t nbits = 0;
        auto len_r = decode_ext_size_and_items(stream, def.constraints, [&](std::size_t m) -> DecodeResult {
            for (std::size_t i = 0; i < m; ++i, ++nbits) {
                auto b = stream.get_bits(1);
                if (!b) return decode_err(b.error());
                if (nbits % 8 == 0) bytes.push_back(0);
                bytes.back() |= static_cast<uint8_t>(*b << (7 - nbits % 8));
            }
            return decode_ok();
        });
        if (!len_r) return decode_err(len_r.error());
        std::size_t bit_count = *len_r;
        if (bit_count == 0) { *static_cast<BitString*>(dest) = BitString{}; return decode_ok(); }
        uint8_t unused = static_cast<uint8_t>((8 - bit_count % 8) % 8);
        *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
        return decode_ok();
    }
};

class OctetStringPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        encode_ext_size_and_items(stream, def.constraints, bytes.size(), [&](std::size_t from, std::size_t to) {
            for (std::size_t i = from; i < to; ++i) stream.put_bits(bytes[i], 8);
        });
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        std::vector<uint8_t> bytes;
        auto len_r = decode_ext_size_and_items(stream, def.constraints, [&](std::size_t m) -> DecodeResult {
            bytes.reserve(bytes.size() + m);
            for (std::size_t i = 0; i < m; ++i) {
                auto b = stream.get_bits(8);
                if (!b) return decode_err(b.error());
                bytes.push_back(static_cast<uint8_t>(*b));
            }
            return decode_ok();
        });
        if (!len_r) return decode_err(len_r.error());
        *static_cast<OctetString*>(dest) = OctetString{std::move(bytes)};
        return decode_ok();
    }
};

/// @brief OCTET STRING whose bytes are the encoding of another type
///        (\c Containing<T>, X.682 §11): the OCTET STRING encoding of the
///        raw bytes (X.691 §17). The enclosing SEQUENCE/SET or CHOICE decodes
///        the inner value; a modified inner value is re-encoded on write.
class ContainedPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        std::vector<uint8_t> scratch;
        std::string err;
        auto bytes = contained_wire_bytes(def, *static_cast<const ContainedBase*>(src),
                                          ContainedEncoding::PerUnaligned, stream.contained(), scratch, err);
        if (!err.empty()) stream.set_encode_failed(err.c_str());
        encode_ext_size_and_items(stream, def.constraints, bytes.size(), [&](std::size_t from, std::size_t to) {
            for (std::size_t i = from; i < to; ++i) stream.put_bits(bytes[i], 8);
        });
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        std::vector<uint8_t> bytes;
        auto len_r = decode_ext_size_and_items(stream, def.constraints, [&](std::size_t m) -> DecodeResult {
            bytes.reserve(bytes.size() + m);
            for (std::size_t i = 0; i < m; ++i) {
                auto b = stream.get_bits(8);
                if (!b) return decode_err(b.error());
                bytes.push_back(static_cast<uint8_t>(*b));
            }
            return decode_ok();
        });
        if (!len_r) return decode_err(len_r.error());
        static_cast<ContainedBase*>(dest)->set_raw_from_wire(bytes, ContainedEncoding::PerUnaligned);
        return decode_ok();
    }
};

class OidPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        per_detail::encode_ber_content<Oid>(stream, src);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        return per_detail::decode_ber_content<Oid>(stream, dest);
    }
};

class RelOidPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        per_detail::encode_ber_content<RelativeOid>(stream, src);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        return per_detail::decode_ber_content<RelativeOid>(stream, dest);
    }
};

/// PER handler for all known-multiplier character strings (X.691 §26).
/// Handles IA5String, VisibleString, NumericString, PrintableString, BMPString,
/// UniversalString, and others. Validates SIZE and FROM alphabet constraints on encode;
/// rejects violations via `PerEncodeStream::set_encode_failed`.
class StringPerHandler final : public IPerTypeHandler {
public:
    /// @brief Encode a known-multiplier character string to UPER bit stream.
    /// @param stream  Output bit stream; `encode_failed()` set on constraint violation.
    /// @param def     TypeDescriptor carrying SIZE/alphabet constraints (from generated table).
    /// @param src     `AsnStringBase*` holding the string value to encode.
    /// @see X.691 §26.5 (known-multiplier character string encoding); §12 (size constraints).
    void encode(const PerCodec& codec, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const std::string& str = static_cast<const AsnStringBase*>(src)->str();
        const Constraints& pc = def.constraints;
        auto [bits, bpc] = string_params(def.tag.number);
        // alphabet_bits > 0 means FROM constraint — index != char value, must use encode_table.
        // Built-in types may also have encode_table (for validate) but alphabet_bits == 0;
        // they use the string_params() bit-width path instead.
        bool has_alpha = pc.alphabet_bits > 0 && pc.encode_table != nullptr;
        // char_count is always code-point count (str.size() / bpc).
        // For bpc=1 this equals str.size(); for bpc=2 (BMPString) and bpc=4 (UniversalString)
        // it is the number of wide characters, not the byte length.
        std::size_t char_count = str.size() / static_cast<std::size_t>(bpc);
        if (pc.flags & Constraints::EXTENSIBLE) {
            // For wide-char types (bpc>1), iterate code points: all high bytes must be
            // 0x00 (Basic Latin) AND low byte must be in the FROM alphabet.
            auto alphabet_in_root = [&]() {
                if (bpc > 1) {
                    for (std::size_t i = 0; i + static_cast<std::size_t>(bpc) <= str.size(); i += bpc) {
                        for (int b = 0; b < bpc - 1; ++b)
                            if (static_cast<unsigned char>(str[i + b]) != 0) return false;
                        unsigned char lo = static_cast<unsigned char>(str[i + bpc - 1]);
                        if (pc.encode_table[lo] == 0xFFFFu) return false;
                    }
                } else {
                    for (unsigned char c : str)
                        if (pc.encode_table[c] == 0xFFFFu) return false;
                }
                return true;
            };
            bool in_root = true;
            if (pc.flags & Constraints::SIZE_CONSTRAINED) {
                in_root = (char_count >= static_cast<std::size_t>(pc.size_lower) &&
                           char_count <= static_cast<std::size_t>(pc.size_upper));
            }
            // Both SIZE and FROM can be present and extensible at once (X.691 §26.5.7):
            // a value is only in-root when it satisfies size AND alphabet.
            if (in_root && has_alpha) in_root = alphabet_in_root();
            stream.put_bits(in_root ? 0 : 1, 1);
            if (!in_root) {
                // X.691 §26.4: outside the extension root the value is encoded
                // as if there were neither an effective size constraint nor an
                // effective PermittedAlphabet constraint: the general length and
                // the type's own character width.
                TypeDescriptor plain = def;
                plain.constraints = Constraints{};
                encode(codec, stream, plain, src);
                return;
            }
        }
        // Validate SIZE constraint (non-extensible or extensible root).
        // Only fixed-size (lower==upper) violations are caught here; range violations
        if ((pc.flags & Constraints::SIZE_CONSTRAINED) &&
            !(pc.flags & Constraints::EXTENSIBLE) &&
            (char_count < static_cast<std::size_t>(pc.size_lower) ||
             char_count > static_cast<std::size_t>(pc.size_upper))) {
            stream.set_encode_failed("string length violates SIZE constraint");
            return;
        }
        // Validate type-intrinsic character sets (no FROM constraint needed).
        // X.691 §26.5.3: NumericString canonical set is space + '0'..'9'.
        if (!has_alpha && !(pc.flags & Constraints::EXTENSIBLE)) {
            if (def.tag.number == UniversalTag::NumericString) {
                for (unsigned char c : str) {
                    if (c != ' ' && (c < '0' || c > '9')) {
                        stream.set_encode_failed("character not in NumericString natural alphabet");
                        return;
                    }
                }
            } else if (def.tag.number == UniversalTag::Ia5String) {
                // X.691 §26.5.6: IA5String canonical set is 0x00..0x7F.
                for (unsigned char c : str) {
                    if (c > 0x7F) {
                        stream.set_encode_failed("character not in IA5String natural alphabet");
                        return;
                    }
                }
            }
        }
        // FROM alphabet: every character is checked before anything is
        // written, since the fragment-aware writer below cannot fail part-way.
        // For wide-char types (BMPString bpc=2, UniversalString bpc=4): high
        // bytes must be 0x00 (Basic Latin plane); the low byte is the
        // alphabet index key.
        const std::size_t ubpc = static_cast<std::size_t>(bpc);
        if (has_alpha) {
            for (std::size_t i = 0; i + ubpc <= str.size(); i += ubpc) {
                for (std::size_t b = 0; b + 1 < ubpc; ++b) {
                    if (static_cast<unsigned char>(str[i + b]) != 0) {
                        stream.set_encode_failed("codepoint outside Basic Latin in FROM alphabet");
                        return;
                    }
                }
                if (pc.encode_table[static_cast<unsigned char>(str[i + ubpc - 1])] == 0xFFFFu) {
                    stream.set_encode_failed("character not in FROM alphabet");
                    return;
                }
            }
        }
        encode_size_and_items(stream, pc, char_count, [&](std::size_t from, std::size_t to) {
            for (std::size_t ci = from; ci < to; ++ci) {
                const std::size_t at = ci * ubpc;
                if (has_alpha) {
                    stream.put_bits(pc.encode_table[static_cast<unsigned char>(str[at + ubpc - 1])],
                                    pc.alphabet_bits);
                } else if (bpc > 1) {
                    for (std::size_t b = 0; b < ubpc; ++b)
                        stream.put_bits(static_cast<unsigned char>(str[at + b]), 8);
                } else if (bits == 4) {
                    stream.put_bits(encode_numeric_char(str[at]), 4);
                } else {
                    stream.put_bits(static_cast<uint8_t>(str[at]), bits);
                }
            }
        });
    }
    /// @brief Decode a known-multiplier character string from UPER bit stream.
    /// @param stream  Input bit stream.
    /// @param def     TypeDescriptor carrying SIZE/alphabet constraints.
    /// @param dest    `AsnStringBase*` to receive the decoded string.
    /// @see X.691 §26.5.
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const Constraints& pc = def.constraints;
        if (pc.flags & Constraints::EXTENSIBLE) {
            auto ext = stream.get_bits(1);
            if (!ext) return decode_err(ext.error());
            if (*ext) {
                // X.691 §26.4: out of root, decode as the unconstrained type.
                TypeDescriptor plain = def;
                plain.constraints = Constraints{};
                return decode(codec, stream, plain, dest);
            }
        }
        auto [bits, bpc] = string_params(def.tag.number);
        const bool has_alpha = pc.alphabet_bits > 0 && pc.alphabet != nullptr;
        std::string result;
        auto len_r = decode_size_and_items(stream, pc, [&](std::size_t m) -> DecodeResult {
            result.reserve(result.size() + m * static_cast<std::size_t>(bpc));
            for (std::size_t i = 0; i < m; ++i) {
                if (has_alpha) {
                    // Alphabet-indexed: (bpc-1) zero high bytes + the low byte
                    // from the alphabet table.
                    auto v = stream.get_bits(pc.alphabet_bits);
                    if (!v) return decode_err(v.error());
                    if (*v >= pc.alphabet_size)
                        return decode_err(DecodeError("PER: alphabet index out of range"));
                    for (int b = 0; b < bpc - 1; ++b) result.push_back('\0');
                    result.push_back(static_cast<char>(pc.alphabet[*v]));
                } else if (bpc > 1) {
                    for (int b = 0; b < bpc; ++b) {
                        auto v = stream.get_bits(8);
                        if (!v) return decode_err(v.error());
                        result.push_back(static_cast<char>(*v));
                    }
                } else if (bits == 4) {
                    auto v = stream.get_bits(4);
                    if (!v) return decode_err(v.error());
                    result.push_back(decode_numeric_char(static_cast<uint8_t>(*v)));
                } else {
                    auto v = stream.get_bits(bits);
                    if (!v) return decode_err(v.error());
                    result.push_back(static_cast<char>(*v));
                }
            }
            return decode_ok();
        });
        if (!len_r) return decode_err(len_r.error());
        static_cast<AsnStringBase*>(dest)->str() = std::move(result);
        return decode_ok();
    }
};

class EnumeratedPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        long value = static_cast<const EnumValue*>(src)->value();
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;
        // Binary search in entries (sorted by numeric value) to get sorted position.
        // This matches asn1c: PER ordinal = position in numerically-sorted value2enum,
        // not declaration order. Needed when extension values have lower numeric values
        // than root values (e.g. unknown(0) declared after "...").
        int lo = 0, hi = spec.count - 1, ordinal = -1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (spec.entries[mid].value == value) { ordinal = mid; break; }
            else if (spec.entries[mid].value < value) lo = mid + 1;
            else hi = mid - 1;
        }
        bool is_ext = (ordinal < 0) || (ordinal >= rcount);
        int ext_ordinal = (ordinal >= rcount) ? (ordinal - rcount) : 0;
        if (spec.extensible) stream.put_bits(is_ext ? 1 : 0, 1, "ENUM.ext");
        if (!is_ext) {
            stream.put_bits(static_cast<uint64_t>(ordinal), range_bits(rcount), "ENUM.value");
        } else {
            put_nsnn(stream, ext_ordinal);
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;
        bool is_ext = false;
        if (spec.extensible) {
            auto bit = stream.get_bits(1);
            if (!bit) return decode_err(bit.error());
            is_ext = (*bit != 0);
        }
        if (!is_ext) {
            int rb = range_bits(rcount);
            auto idx = stream.get_bits(rb);
            if (!idx) return decode_err(idx.error());
            if (*idx >= static_cast<uint64_t>(rcount))
                return decode_err(DecodeError("PER: ENUM index out of range"));
            // entries sorted by value; ordinal = sorted position (matches asn1c)
            static_cast<EnumValue*>(dest)->set(spec.entries[*idx].value);
            return decode_ok();
        } else {
            auto ord = get_nsnn(stream);
            if (!ord) return decode_err(ord.error());
            int ext_entry = rcount + *ord;
            if (ext_entry >= spec.count)
                return decode_err(DecodeError("PER: ENUM extension index out of range"));
            static_cast<EnumValue*>(dest)->set(spec.entries[ext_entry].value);
            return decode_ok();
        }
    }
};

class SeqOfPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec& codec, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.seq_of_spec;
        const SeqOfBase& seq = *static_cast<const SeqOfBase*>(src);
        std::size_t count = seq.count();
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-ENC] SOF %s count=%zu @%d\n",
                         def.name, count, PerCodec::stream_bit_pos(stream));
        const auto& sc = spec.size_constraints;
        std::size_t enc_count = count;
        if (size_count_is_constrained(sc) && !(sc.flags & Constraints::EXTENSIBLE) &&
            sc.size_lower != sc.size_upper && enc_count < static_cast<std::size_t>(sc.size_lower)) {
            // X.680 §47 SIZE lower bound violated by the actual element
            // count — caller's data is invalid for this type, not a
            // codec bug. PerCodec::encode's own validate_on_encode()
            // call already reports this exact delta through
            // ValidationReport (SeqOfSpec::validate uses the identical
            // size_lower - count formula) before this handler ever
            // runs — this clamp only needs to keep the encoded count
            // in bounds so the wire stays well-formed, not report a
            // second time. Missing elements then desync (caller's fault).
            enc_count = static_cast<std::size_t>(sc.size_lower);
        }
        const auto& edef = *spec.element;
        bool is_set_of = (def.tag.cls == TagClass::Universal &&
                          def.tag.number == UniversalTag::Set);
        std::vector<EncodedElement> sorted;
        if (is_set_of && count > 1) sorted = sorted_set_of_elements(codec, stream, edef, seq, count);
        IEncodeStream& es = stream;
        encode_ext_size_and_items(stream, sc, enc_count, [&](std::size_t from, std::size_t to) {
            for (std::size_t i = from; i < std::min(to, count); ++i) {
                if (sorted.empty()) {
                    codec.encode(es, edef, seq.get_const(i));
                    continue;
                }
                const auto& e = sorted[i];
                int full = e.bits / 8;
                for (int k = 0; k < full; ++k) stream.put_bits(e.bytes[k], 8);
                if (int rest = e.bits % 8)
                    stream.put_bits(e.bytes[full] >> (8 - rest), rest);
            }
        });
    }

    /// One SET OF element's own PER encoding and exact bit length.
    struct EncodedElement { std::vector<uint8_t> bytes; int bits; };

    /// @brief Encodes the first \p count elements of a SET OF and orders
    ///        them as X.691 §21.1 (CANONICAL-PER) defines: ascending by
    ///        component encoding, compared as bit strings zero-padded to an
    ///        octet boundary, the shorter one extended with 0-octets. The
    ///        only order the standard defines, and valid BASIC-PER too
    ///        (X.691 §8); it is also what asn1c emits.
    /// @param codec  Codec dispatching each element's own encoding.
    /// @param stream Destination; only receives an encode-failure flag here.
    /// @param edef   Element TypeDescriptor.
    /// @param seq    The SET OF value.
    /// @param count  Number of elements.
    /// @return The element encodings, in §21.1 order.
    /// @see X.691 §21.1, §21.2.
    static std::vector<EncodedElement> sorted_set_of_elements(const PerCodec& codec, PerEncodeStream& stream,
                                                              const TypeDescriptor& edef, const SeqOfBase& seq,
                                                              std::size_t count) {
        using Encoded = EncodedElement;
        std::vector<Encoded> elems;
        elems.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            Encoded e;
            PerEncodeStream es{e.bytes};
            IEncodeStream& ies = es;
            codec.encode(ies, edef, seq.get_const(i));
            e.bits = es.bit_pos();
            es.flush();
            if (es.encode_failed()) stream.set_encode_failed("SET OF element");
            elems.push_back(std::move(e));
        }
        auto padded_less = [](const Encoded& a, const Encoded& b) {
            std::size_t n = std::max(a.bytes.size(), b.bytes.size());
            for (std::size_t k = 0; k < n; ++k) {
                uint8_t x = k < a.bytes.size() ? a.bytes[k] : 0;
                uint8_t y = k < b.bytes.size() ? b.bytes[k] : 0;
                if (x != y) return x < y;
            }
            return false;
        };
        std::stable_sort(elems.begin(), elems.end(), padded_less);
        return elems;
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-DEC] SOF %s @%d/%d\n",
                         def.name, PerCodec::stream_bit_pos(stream), PerCodec::stream_total_bits(stream));
        const auto& spec = *def.seq_of_spec;
        const auto& sc = spec.size_constraints;
        SeqOfBase& seq = *static_cast<SeqOfBase*>(dest);
        seq.resize(0);
        const auto& edef = *spec.element;
        IDecodeStream& ds = stream;
        auto count_r = decode_ext_size_and_items(stream, sc, [&](std::size_t m) -> DecodeResult {
            std::size_t start = seq.count();
            seq.resize(start + m);
            for (std::size_t i = start; i < start + m; ++i) {
                auto r = codec.decode(ds, edef, seq.get_mut(i));
                if (!r) return r;
            }
            return decode_ok();
        });
        if (!count_r) return decode_err(count_r.error());
        return decode_ok();
    }
};

static DecodeResult decode_group_open_type(const PerCodec& codec, PerDecodeStream& stream,
                                           const SequenceSpec& spec, int begin, int end,
                                           Asn1Object* dest);

class SequencePerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec& codec, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.sequence_spec;
        int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-ENC] SEQ %s members=%d ext_at=%d @%d\n",
                         def.name, spec.count, spec.ext_at, PerCodec::stream_bit_pos(stream));
        bool has_ext = false;
        if (spec.ext_at >= 0) {
            for (int i = root_end; i < spec.count; ++i) {
                if (spec.members[i].optional_ops.is_present(src)) { has_ext = true; break; }
            }
            stream.put_bits(has_ext ? 1 : 0, 1, "SEQ.ext");
        }
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.optional) continue;
            bool suppress = mbr.has_default && mbr.is_default_equal &&
                           mbr.is_default_equal(src);
            bool present = mbr.optional_ops.is_present(src) && !suppress;
            stream.put_bits(present ? 1 : 0, 1, "SEQ.preamble");
        }
        IEncodeStream& es = stream;
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            if (mbr.has_default && mbr.is_default_equal &&
                mbr.is_default_equal(src)) continue;
            const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
            codec.encode(es, *mbr.type_descriptor, mptr);
        }
        if (has_ext) {
            const ExtUnits units{spec, root_end};
            put_nslength(stream, static_cast<std::size_t>(units.count()));
            for (int u = 0; u < units.count(); ++u)
                stream.put_bits(units.present(u, src) ? 1 : 0, 1, "SEQ.ext_bitmap");
            for (int u = 0; u < units.count(); ++u) {
                if (!units.present(u, src)) continue;
                if (units.is_group(u)) {
                    encode_group_open_type(codec, stream, spec, units.begin(u), units.end(u), src);
                    continue;
                }
                const auto& mbr = spec.members[units.begin(u)];
                if (!mbr.type_descriptor) continue;
                const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
                encode_open_type(codec, stream, *mbr.type_descriptor, mptr);
            }
        }
    }

    /// @brief The extension additions of a SEQUENCE/SET as PER units (X.691
    ///        §18.9), read from the SequenceSpec's precomputed unit table: a
    ///        plain extension member is one unit, an extension addition
    ///        group one unit. Without a table every member is its own unit.
    struct ExtUnits {
        const SequenceSpec& spec;
        int root_end;
        int count() const { return spec.ext_unit_count > 0 ? spec.ext_unit_count : spec.count - root_end; }
        int begin(int u) const {
            if (spec.ext_unit_count == 0) return root_end + u;
            return u == 0 ? root_end : spec.ext_unit_end[u - 1];
        }
        int end(int u) const { return spec.ext_unit_count == 0 ? root_end + u + 1 : spec.ext_unit_end[u]; }
        bool is_group(int u) const { return spec.ext_unit_count > 0 && spec.ext_unit_group[u]; }
        bool present(int u, const Asn1Object* src) const {
            for (int i = begin(u); i < end(u); ++i)
                if (spec.members[i].optional_ops.is_present(src)) return true;
            return false;
        }
    };

    /// @brief Encodes one present extension addition group as a sequence
    ///        type of its members (presence bitmap for the members declared
    ///        OPTIONAL/DEFAULT inside the group, then the present members)
    ///        inside one open type (X.691 §18.9).
    static void encode_group_open_type(const PerCodec& codec, PerEncodeStream& stream,
                                       const SequenceSpec& spec, int begin, int end,
                                       const Asn1Object* src) {
        std::vector<uint8_t> tmp;
        PerEncodeStream gs{tmp};
        for (int i = begin; i < end; ++i)
            if (spec.group_member_optional[i])
                gs.put_bits(spec.members[i].optional_ops.is_present(src) ? 1 : 0, 1, "GROUP.bitmap");
        IEncodeStream& es = gs;
        for (int i = begin; i < end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.optional_ops.is_present(src)) {
                // X.680 §24.12: a present group carries all its mandatory members.
                if (!spec.group_member_optional[i]) stream.set_encode_failed("extension group member absent");
                continue;
            }
            if (!mbr.type_descriptor) continue;
            codec.encode(es, *mbr.type_descriptor, mbr.optional_ops.member_ptr(src, mbr.offset));
        }
        if (gs.encode_failed()) stream.set_encode_failed("extension group member");
        gs.flush();
        per_detail::put_octets(stream, tmp.data(), tmp.size());
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto ok = decode_members(codec, stream, def, dest);
        if (!ok || !def.has_contained) return ok;
        std::string err;
        if (!decode_contained_members(def, dest, ContainedEncoding::PerUnaligned, stream.depth(),
                                          stream.contained(), err))
            return decode_err(DecodeError(std::string(def.name) + "." + err));
        return ok;
    }
    /// @brief Decode the members of a SEQUENCE/SET (X.691 §19).
    DecodeResult decode_members(const PerCodec& codec, PerDecodeStream& stream,
                                const TypeDescriptor& def, Asn1Object* dest) const {
        const auto& spec = *def.sequence_spec;
        int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-DEC] SEQ %s members=%d ext_at=%d @%d/%d\n",
                         def.name, spec.count, spec.ext_at, PerCodec::stream_bit_pos(stream), PerCodec::stream_total_bits(stream));
        bool ext_flag = false;
        if (spec.ext_at >= 0) {
            auto b = stream.get_bits(1);
            if (!b) return decode_err(b.error());
            ext_flag = (*b != 0);
        }
        // Precomputed at codegen time (Generator::emit_sequence_definition) —
        // the width of the root-level presence bitmap never depends on the
        // wire, only on the schema, so it's read here, not recounted.
        int roms = spec.roms_count;
        bool bitmap[64] = {};
        for (int i = 0; i < roms && i < 64; ++i) {
            auto bit = stream.get_bits(1);
            if (!bit) return decode_err(bit.error());
            bitmap[i] = (*bit != 0);
        }
        int opt_idx = 0;
        IDecodeStream& ds = stream;
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) {
                bool present = bitmap[opt_idx++];
                mbr.optional_ops.set_present(dest, present);
                if (!present) {
                    if (mbr.set_default) mbr.set_default(dest);
                    continue;
                }
            }
            Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
            auto r = codec.decode(ds, *mbr.type_descriptor, mptr);
            if (!r) return r;
        }
        if (spec.ext_at >= 0) {
            int known_ext = spec.count - root_end;
            if (!ext_flag) {
                for (int i = root_end; i < spec.count; ++i)
                    spec.members[i].optional_ops.set_present(dest, false);
            } else {
                auto n_ext_r = get_nslength(stream);
                if (!n_ext_r) return decode_err(n_ext_r.error());
                int n_ext = static_cast<int>(*n_ext_r);
                bool ext_bitmap[64] = {};
                for (int i = 0; i < n_ext && i < 64; ++i) {
                    auto b = stream.get_bits(1);
                    if (!b) return decode_err(b.error());
                    ext_bitmap[i] = (*b != 0);
                }
                const ExtUnits units{spec, root_end};
                for (int i = 0; i < n_ext; ++i) {
                    if (i >= units.count()) {
                        if (ext_bitmap[i])
                            if (auto r = PerCodec::skip_ext(stream); !r) return r;
                        continue;
                    }
                    if (!ext_bitmap[i]) {
                        for (int m = units.begin(i); m < units.end(i); ++m) {
                            const auto& absent = spec.members[m];
                            absent.optional_ops.set_present(dest, false);
                            if (absent.set_default) absent.set_default(dest);
                        }
                        continue;
                    }
                    if (units.is_group(i)) {
                        auto r = decode_group_open_type(codec, stream, spec, units.begin(i), units.end(i), dest);
                        if (!r) return r;
                        continue;
                    }
                    const auto& mbr = spec.members[units.begin(i)];
                    mbr.optional_ops.set_present(dest, true);
                    Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
                    auto r = decode_open_type(codec, stream, *mbr.type_descriptor, mptr);
                    if (!r) return r;
                }
                for (int i = n_ext; i < units.count(); ++i)
                    for (int m = units.begin(i); m < units.end(i); ++m)
                        spec.members[m].optional_ops.set_present(dest, false);
            }
        }
        return decode_ok();
    }
};

/// @brief Decode counterpart of SequencePerHandler::encode_group_open_type:
///        one extension addition group from its open type (X.691 §18.9).
static DecodeResult decode_group_open_type(const PerCodec& codec, PerDecodeStream& stream,
                                           const SequenceSpec& spec, int begin, int end,
                                           Asn1Object* dest) {
    auto bytes_r = per_detail::get_octets(stream);
    if (!bytes_r) return decode_err(bytes_r.error());
    PerDecodeStream gs = stream.sub(std::span<const uint8_t>{bytes_r->data(), bytes_r->size()});
    std::vector<bool> present(static_cast<std::size_t>(end - begin), true);
    for (int i = begin; i < end; ++i) {
        if (!spec.group_member_optional[i]) continue;
        auto b = gs.get_bits(1);
        if (!b) return decode_err(b.error());
        present[i - begin] = (*b != 0);
    }
    IDecodeStream& ds = gs;
    for (int i = begin; i < end; ++i) {
        const auto& mbr = spec.members[i];
        mbr.optional_ops.set_present(dest, present[i - begin]);
        if (!present[i - begin]) {
            if (mbr.set_default) mbr.set_default(dest);
            continue;
        }
        if (!mbr.type_descriptor) continue;
        auto r = codec.decode(ds, *mbr.type_descriptor, mbr.optional_ops.member_ptr(dest, mbr.offset));
        if (!r) return r;
    }
    return decode_ok();
}

class ChoicePerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec& codec, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = static_cast<const ChoiceInterface*>(src);
        int pr = ch->_present;
        if (pr <= 0 || pr > spec.count) {
            std::string reason = std::string("CHOICE ") + def.name + ": no alternative selected";
            stream.set_encode_failed(reason.c_str());
            return;
        }
        int def_idx = pr - 1;
        int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool in_ext = (spec.ext_at >= 0) && (def_idx >= root_count);
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-ENC] CHO %s pr=%d root=%d ext=%d @%d\n",
                         def.name, pr, root_count, (int)in_ext, PerCodec::stream_bit_pos(stream));
        if (spec.ext_at >= 0) stream.put_bits(in_ext ? 1 : 0, 1, "CHO.ext");
        if (!in_ext) {
            // Generator emits root alternatives in canonical tag order — def_idx IS canonical.
            // Precomputed by Generator (spec.range_bits) rather than
            // recomputed here — matches spec.constraints.range_bits exactly.
            int bits = spec.constraints.range_bits;
            if (bits > 0) stream.put_bits(static_cast<uint64_t>(def_idx), bits, "CHO.index");
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) { stream.set_encode_failed((std::string("CHOICE ") + def.name + ": alternative " + alt.name + " has no codec").c_str()); return; }
            IEncodeStream& es = stream;
            const Asn1Object* mptr = alt.get_const_fn(ch);
            codec.encode(es, *alt.type_descriptor, mptr);
        } else {
            int ext_idx = def_idx - root_count;
            // Generator emits extension alternatives in canonical tag order — ext_idx IS canonical.
            put_nsnn(stream, ext_idx);
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) { stream.set_encode_failed((std::string("CHOICE ") + def.name + ": alternative " + alt.name + " has no codec").c_str()); return; }
            const Asn1Object* mptr = alt.get_const_fn(ch);
            encode_open_type(codec, stream, *alt.type_descriptor, mptr);
        }
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto ok = decode_alternative(codec, stream, def, dest);
        if (!ok || !def.has_contained) return ok;
        std::string err;
        if (!decode_contained_alternative(def, dest, ContainedEncoding::PerUnaligned, stream.depth(),
                                          stream.contained(), err))
            return decode_err(DecodeError(std::string(def.name) + "." + err));
        return ok;
    }
    /// @brief Decode the CHOICE index and the selected alternative (X.691 §23).
    DecodeResult decode_alternative(const PerCodec& codec, PerDecodeStream& stream,
                                    const TypeDescriptor& def, Asn1Object* dest) const {
        const auto& spec = *def.choice_spec;
        ChoiceInterface* ch = static_cast<ChoiceInterface*>(dest);
        int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool in_ext = false;
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-DEC] CHO %s root=%d @%d/%d\n",
                         def.name, root_count, PerCodec::stream_bit_pos(stream), PerCodec::stream_total_bits(stream));
        if (spec.ext_at >= 0) {
            auto b = stream.get_bits(1);
            if (!b) return decode_err(b.error());
            in_ext = (*b != 0);
        }
        if (!in_ext) {
            // Generator emits root alternatives in canonical tag order — index IS canonical.
            int bits = spec.constraints.range_bits;
            int def_idx = 0;
            if (bits > 0) {
                auto v = stream.get_bits(bits);
                if (!v) return decode_err(v.error());
                def_idx = static_cast<int>(*v);
            }
            if (def_idx < 0 || def_idx >= root_count)
                return decode_err(DecodeError("CHOICE index out of range"));
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor)
                return decode_err(DecodeError("CHOICE alternative has no type descriptor"));
            if (ch->_present != def_idx + 1) {
                ch->emplace_alt(alt);
            }
            ch->_present = def_idx + 1;
            Asn1Object* mptr = alt.get_mut_fn(ch);
            IDecodeStream& ds = stream;
            auto r = codec.decode(ds, *alt.type_descriptor, mptr);
            if (!r) return r;
            return decode_ok();
        } else {
            // Generator emits extension alternatives in canonical tag order — index IS canonical.
            auto ext_idx_r = get_nsnn(stream);
            if (!ext_idx_r) return decode_err(ext_idx_r.error());
            int def_idx = root_count + *ext_idx_r;
            if (def_idx < spec.count) {
                const auto& alt = spec.alternatives[def_idx];
                if (alt.type_descriptor) {
                    if (ch->_present != def_idx + 1) {
                        ch->emplace_alt(alt);
                    }
                    ch->_present = def_idx + 1;
                    Asn1Object* mptr = alt.get_mut_fn(ch);
                    auto r = decode_open_type(codec, stream, *alt.type_descriptor, mptr);
                    if (!r) return r;
                } else {
                    if (auto r = PerCodec::skip_ext(stream); !r) return r;
                }
            } else {
                if (auto r = PerCodec::skip_ext(stream); !r) return r;
            }
            return decode_ok();
        }
    }
};

// ---------------------------------------------------------------------------
// Singletons

static const ErrorPerHandler      s_error;
static const AnyPerHandler        s_any;
static const BooleanPerHandler    s_boolean;
static const IntegerPerHandler    s_integer;
static const UIntegerPerHandler   s_uinteger;
static const NullPerHandler       s_null;
static const RealPerHandler       s_real;
static const BitStringPerHandler  s_bitstring;
static const OctetStringPerHandler s_octetstring;
static const ContainedPerHandler   s_contained;
static const OidPerHandler        s_oid;
static const RelOidPerHandler     s_reloid;
static const StringPerHandler     s_string;
static const EnumeratedPerHandler s_enumerated;
static const SeqOfPerHandler      s_seqof;
static const SequencePerHandler   s_sequence;
static const ChoicePerHandler     s_choice;

} // anonymous namespace

// Named references for TypeDescriptor::per_handler (declared in PerHandlers.hpp).
const IPerTypeHandler& per_any_handler         = s_any;
const IPerTypeHandler& per_boolean_handler     = s_boolean;
const IPerTypeHandler& per_integer_handler     = s_integer;
const IPerTypeHandler& per_uinteger_handler    = s_uinteger;
const IPerTypeHandler& per_null_handler        = s_null;
const IPerTypeHandler& per_real_handler        = s_real;
const IPerTypeHandler& per_bitstring_handler   = s_bitstring;
const IPerTypeHandler& per_octetstring_handler = s_octetstring;
const IPerTypeHandler& per_contained_handler   = s_contained;
const IPerTypeHandler& per_oid_handler         = s_oid;
const IPerTypeHandler& per_reloid_handler      = s_reloid;
const IPerTypeHandler& per_string_handler      = s_string;
const IPerTypeHandler& per_enumerated_handler  = s_enumerated;
const IPerTypeHandler& per_seqof_handler       = s_seqof;
const IPerTypeHandler& per_sequence_handler    = s_sequence;
const IPerTypeHandler& per_choice_handler      = s_choice;

// ---------------------------------------------------------------------------
// PerCodec public entry points

void PerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const Asn1Object* src) const
{
    validate_on_encode("PER", def, src);
    auto& stream = static_cast<PerEncodeStream&>(dst);
    (def.per_handler ? *def.per_handler : s_error).encode(*this, stream, def, src);
}

DecodeResult PerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              Asn1Object* dest) const
{
    auto& stream = static_cast<PerDecodeStream&>(src);
    DecodeDepthGuard depth_guard{stream.depth(), def};
    if (depth_guard.exceeded()) return decode_err(DecodeError(DecodeDepthGuard::message(def)));
    DecodeResult res = (def.per_handler ? *def.per_handler : s_error).decode(*this, stream, def, dest);
    if (res.has_value()) validate_on_decode("PER", def, dest);
    return res;
}

} // namespace asn1
