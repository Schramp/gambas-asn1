#include <cassert>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/Alphabets.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/Integer.hpp>

namespace asn1 {

// X.691 §10.2 — skip unknown open-type field by length-prefixed byte count.
DecodeResult PerDecodeStream::skip_open_type() {
    auto len_r = per_detail::get_length(*this);
    if (!len_r) return decode_err(len_r.error());
    for (std::size_t i = 0; i < *len_r; ++i) {
        auto b = get_bits(8);
        if (!b) return decode_err(b.error());
    }
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

// X.691 §10.9.3.4 "Where the length determinant is a normally small length and
// "n" is less than or equal to 64, a single-bit bit-field [...]"
// Flag=0: n in [1..64], encode n-1 in 6 bits. Flag=1: delegate to put_length().
static void put_nslength(PerEncodeStream& stream, std::size_t n) {
    if (n >= 1 && n <= 64) { stream.put_bits(0, 1); stream.put_bits(n - 1, 6); }
    else { stream.put_bits(1, 1); per_detail::put_length(stream, n); }
}

// X.691 §10.9.3.4 — see put_nslength above.
static Expected<std::size_t, DecodeError> get_nslength(PerDecodeStream& stream) {
    auto b = stream.get_bits(1);
    if (!b) return make_unexpected<std::size_t, DecodeError>(b.error());
    if (*b == 0) {
        auto v = stream.get_bits(6);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return *v + 1;
    }
    return per_detail::get_length(stream);
}


// X.691 §10.6 "Encoding of a normally small non-negative whole number"
// Flag=0: value in [0..63], encode in 6 bits. Flag=1: delegate to put_length().
// TODO: replace magic 6 / 63 / 64 with named constants (X.691 §10.6 "short form" bit width).
static void put_nsnn(PerEncodeStream& stream, int n) {
    if (n <= 63) { stream.put_bits(0, 1); stream.put_bits(static_cast<uint64_t>(n), 6); }
    else { stream.put_bits(1, 1); per_detail::put_length(stream, static_cast<std::size_t>(n)); }
}

// X.691 §10.6 — see put_nsnn above.
static Expected<int, DecodeError> get_nsnn(PerDecodeStream& stream) {
    auto b = stream.get_bits(1);
    if (!b) return make_unexpected<int, DecodeError>(b.error());
    if (*b == 0) {
        auto v = stream.get_bits(6);
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

// X.691 §10.5 "Encoding of a constrained whole number" (SIZE-constrained case),
//        §10.9 "General rules for encoding a length determinant" (unconstrained case).
// Fixed SIZE (size_range_bits==0): no bits written. Constrained: encode offset from lower bound.
static void encode_size_field(PerEncodeStream& stream, const TypeDescriptor& def, std::size_t len) {
    const Constraints& pc = def.constraints;
    bool size_constrained = pc.flags & Constraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        // Fixed SIZE(n): no length field
    } else if (size_constrained) {
	//TODO: Consider making a #define for put_bits that gives it a third ignored parameter that
	//can be used to specifify the name of the field as a string. default implementation
	//would drop the parameter at macro expansion, but be suitable to have a debug implementation as well protected y a #define.
        stream.put_bits(len - static_cast<std::size_t>(pc.size_lower), pc.size_range_bits, "SIZE");
    } else {
        per_detail::put_length(stream, len);
    }
}

// X.691 §10.5 / §10.9 — see encode_size_field above.
static Expected<std::size_t, DecodeError> decode_size_field(PerDecodeStream& stream,
                                                             const TypeDescriptor& def) {
    const Constraints& pc = def.constraints;
    bool size_constrained = pc.flags & Constraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        return static_cast<std::size_t>(pc.size_lower);
    } else if (size_constrained) {
        auto v = stream.get_bits(pc.size_range_bits);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return static_cast<std::size_t>(*v) + static_cast<std::size_t>(pc.size_lower);
    } else {
        return per_detail::get_length(stream);
    }
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
// TODO lookup based? Via TypeDescriptor?
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
    tmp_s.flush();
    per_detail::put_length(stream, tmp.size());
    for (auto b : tmp) stream.put_bits(b, 8);
}

// X.691 §10.2 — see encode_open_type above.
static DecodeResult decode_open_type(const PerCodec& codec, PerDecodeStream& stream,
                                     const TypeDescriptor& mdef, Asn1Object* mptr) {
    auto len_r = per_detail::get_length(stream);
    if (!len_r) return decode_err(len_r.error());
    auto bytes_r = per_detail::read_bytes(stream, *len_r);
    if (!bytes_r) return decode_err(bytes_r.error());
    PerDecodeStream tmp_s{std::span<const uint8_t>{bytes_r->data(), bytes_r->size()}};
    IDecodeStream& ds = tmp_s;
    return codec.decode(ds, mdef, mptr);
}

// ---------------------------------------------------------------------------
// Handler classes

class ErrorPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream&,
                const TypeDescriptor& def, const Asn1Object*) const override {
        assert(false && "PerCodec: unreachable dispatch table entry");
        (void)def;
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream&,
                        const TypeDescriptor& def, Asn1Object*) const override {
        assert(false && "PerCodec: unreachable dispatch table entry");
        return decode_err(DecodeError(std::string("PerCodec: unsupported: ") + def.name));
    }
};

class AnyPerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        per_detail::put_length(stream, bytes.size());
        for (auto b : bytes) stream.put_bits(b, 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto len_r = per_detail::get_length(stream);
        if (!len_r) return decode_err(len_r.error());
        auto bytes_r = per_detail::read_bytes(stream, *len_r);
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
            // X.691 §10.5.7.1 UPER: value in [lb..ub] encoded in minimum bits, no length prefix.
            int64_t encoded = svalue - pc.lower_bound;
            stream.put_bits(static_cast<uint64_t>(encoded), pc.range_bits, "INT.value");
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
            idest->set(pc.lower_bound + static_cast<int64_t>(*bits));
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
        if (real_val.value() == 0.0) return;
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
    void encode(const PerCodec&, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const BitString& v = *static_cast<const BitString*>(src);
        std::size_t bit_count = v.bit_count();
        encode_size_field(stream, def, bit_count);
        std::size_t remaining = bit_count;
        for (uint8_t b : v.bytes()) {
            int n = static_cast<int>(std::min(remaining, std::size_t{8}));
            stream.put_bits(static_cast<uint64_t>(b) >> (8 - n), n);
            remaining -= n;
            if (remaining == 0) break;
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto len_r = decode_size_field(stream, def);
        if (!len_r) return decode_err(len_r.error());
        std::size_t bit_count = *len_r;
        if (bit_count == 0) { *static_cast<BitString*>(dest) = BitString{}; return decode_ok(); }
        std::vector<uint8_t> bytes;
        bytes.reserve((bit_count + 7) / 8);
        std::size_t remaining = bit_count;
        while (remaining > 0) {
            int n = static_cast<int>(std::min(remaining, std::size_t{8}));
            auto b = stream.get_bits(n);
            if (!b) return decode_err(b.error());
            bytes.push_back(static_cast<uint8_t>(*b << (8 - n)));
            remaining -= n;
        }
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
        encode_size_field(stream, def, v.size());
        for (uint8_t b : v.bytes()) stream.put_bits(b, 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto len_r = decode_size_field(stream, def);
        if (!len_r) return decode_err(len_r.error());
        auto bytes = per_detail::read_bytes(stream, *len_r);
        if (!bytes) return decode_err(bytes.error());
        *static_cast<OctetString*>(dest) = OctetString{std::move(*bytes)};
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
    void encode(const PerCodec&, PerEncodeStream& stream,
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
            bool in_root;
            if (pc.flags & Constraints::SIZE_CONSTRAINED) {
                // TODO: also check alphabet membership here when has_alpha is true.
                // A SIZE-and-FROM extensible type with valid size but out-of-alphabet chars
                // is incorrectly classified as in_root; the per-char alphabet validation
                // below is skipped (EXTENSIBLE is set). No data-119 vector exercises this.
                in_root = (char_count >= static_cast<std::size_t>(pc.size_lower) &&
                           char_count <= static_cast<std::size_t>(pc.size_upper));
            } else if (has_alpha) {
                // For wide-char types (bpc>1), iterate code points: all high bytes must be
                // 0x00 (Basic Latin) AND low byte must be in the FROM alphabet.
                in_root = true;
                if (bpc > 1) {
                    for (std::size_t i = 0; i + static_cast<std::size_t>(bpc) <= str.size(); i += bpc) {
                        for (int b = 0; b < bpc - 1; ++b)
                            if (static_cast<unsigned char>(str[i + b]) != 0) { in_root = false; break; }
                        if (!in_root) break;
                        unsigned char lo = static_cast<unsigned char>(str[i + bpc - 1]);
                        if (pc.encode_table[lo] == 0xFFFFu)
                            { in_root = false; break; }
                    }
                } else {
                    for (unsigned char c : str)
                        if (pc.encode_table[c] == 0xFFFFu)
                            { in_root = false; break; }
                }
            } else {
                in_root = true;
            }
            stream.put_bits(in_root ? 0 : 1, 1);
            if (!in_root) {
                // Out-of-root: encode as open type (X.691 §18.8) — byte-length prefixed raw bytes.
                per_detail::put_length(stream, str.size());
                for (unsigned char c : str) stream.put_bits(c, 8);
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
        encode_size_field(stream, def, char_count);
        // FROM alphabet encoding: validate + map in one O(1) encode_table lookup per character.
        // For wide-char types (BMPString bpc=2, UniversalString bpc=4): high bytes must be
        // 0x00 (Basic Latin plane); the low byte is the alphabet index key.
        if (has_alpha) {
            if (bpc > 1) {
                for (std::size_t i = 0; i + static_cast<std::size_t>(bpc) <= str.size(); i += bpc) {
                    for (int b = 0; b < bpc - 1; ++b) {
                        if (static_cast<unsigned char>(str[i + b]) != 0) {
                            stream.set_encode_failed("codepoint outside Basic Latin in FROM alphabet");
                            return;
                        }
                    }
                    unsigned char lo = static_cast<unsigned char>(str[i + bpc - 1]);
                    uint16_t idx = pc.encode_table[lo];
                    if (idx == 0xFFFFu) {
                        stream.set_encode_failed("codepoint not in FROM alphabet");
                        return;
                    }
                    stream.put_bits(idx, pc.alphabet_bits);
                }
            } else {
                for (unsigned char c : str) {
                    uint16_t idx = pc.encode_table[c];
                    if (idx == 0xFFFFu) {
                        stream.set_encode_failed("character not in FROM alphabet");
                        return;
                    }
                    stream.put_bits(idx, pc.alphabet_bits);
                }
            }
        } else if (bpc > 1) {
            for (unsigned char c : str) stream.put_bits(c, 8);
        } else if (bits == 4) {
            for (char c : str) stream.put_bits(encode_numeric_char(c), 4);
        } else if (bits == 7) {
            for (char c : str) stream.put_bits(static_cast<uint8_t>(c), 7);
        } else {
            for (char c : str) stream.put_bits(static_cast<uint8_t>(c), 8);
        }
    }
    /// @brief Decode a known-multiplier character string from UPER bit stream.
    /// @param stream  Input bit stream.
    /// @param def     TypeDescriptor carrying SIZE/alphabet constraints.
    /// @param dest    `AsnStringBase*` to receive the decoded string.
    /// @see X.691 §26.5.
    DecodeResult decode(const PerCodec&, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const Constraints& pc = def.constraints;
        if (pc.flags & Constraints::EXTENSIBLE) {
            auto ext = stream.get_bits(1);
            if (!ext) return decode_err(ext.error());
            if (*ext) {
                auto len_r = per_detail::get_length(stream);
                if (!len_r) return decode_err(len_r.error());
                std::string result;
                result.reserve(*len_r);
                for (std::size_t i = 0; i < *len_r; ++i) {
                    auto b = stream.get_bits(8);
                    if (!b) return decode_err(b.error());
                    result.push_back(static_cast<char>(*b));
                }
                static_cast<AsnStringBase*>(dest)->str() = std::move(result);
                return decode_ok();
            }
        }
        auto len_r = decode_size_field(stream, def);
        if (!len_r) return decode_err(len_r.error());
        std::size_t char_count = *len_r;
        auto [bits, bpc] = string_params(def.tag.number);
        std::string result;
        if (pc.alphabet_bits > 0 && pc.alphabet != nullptr) {
            // Alphabet-indexed decode. For wide-char types (bpc>1), each code point is
            // written as (bpc-1) zero high bytes + one low byte from the alphabet table.
            result.reserve(char_count * static_cast<std::size_t>(bpc));
            for (std::size_t i = 0; i < char_count; ++i) {
                auto v = stream.get_bits(pc.alphabet_bits);
                if (!v) return decode_err(v.error());
                uint8_t lo = (*v < pc.alphabet_size) ? pc.alphabet[*v] : '?';
                for (int b = 0; b < bpc - 1; ++b) result.push_back('\0');
                result.push_back(static_cast<char>(lo));
            }
        } else {
            std::size_t byte_count = char_count * bpc;
            result.reserve(byte_count);
            if (bpc > 1) {
                for (std::size_t i = 0; i < byte_count; ++i) {
                    auto b = stream.get_bits(8);
                    if (!b) return decode_err(b.error());
                    result.push_back(static_cast<char>(*b));
                }
            } else if (bits == 4) {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = stream.get_bits(4);
                    if (!v) return decode_err(v.error());
                    result.push_back(decode_numeric_char(static_cast<uint8_t>(*v)));
                }
            } else if (bits == 7) {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = stream.get_bits(7);
                    if (!v) return decode_err(v.error());
                    result.push_back(static_cast<char>(*v));
                }
            } else {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = stream.get_bits(8);
                    if (!v) return decode_err(v.error());
                    result.push_back(static_cast<char>(*v));
                }
            }
        }
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
        if (sc.flags & Constraints::SIZE_CONSTRAINED) {
            if (sc.size_lower == sc.size_upper) {
                // Fixed size: count implicit
            } else {
                // TODO: wire into ValidationReport when available (currently no encode-time report scope here)
                std::size_t enc_count = count;
                if (enc_count < static_cast<std::size_t>(sc.size_lower)) {
                    std::fprintf(stderr, "[PER-ENC] SOF %s: count=%zu below SIZE lower bound %lld\n",
                                 def.name, count, (long long)sc.size_lower);
                    enc_count = static_cast<std::size_t>(sc.size_lower);
                }
                stream.put_bits(enc_count - static_cast<std::size_t>(sc.size_lower), sc.size_range_bits, "SOF.size");
                // Encode only actual elements; missing elements produce a desync (caller's fault).
                count = std::min(count, enc_count);
            }
        } else {
            per_detail::put_length(stream, count);
        }
        const auto& edef = *spec.element;
        IEncodeStream& es = stream;
        for (std::size_t i = 0; i < count; ++i)
            codec.encode(es, edef, seq.get_const(i));
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-DEC] SOF %s @%d/%d\n",
                         def.name, PerCodec::stream_bit_pos(stream), PerCodec::stream_total_bits(stream));
        const auto& spec = *def.seq_of_spec;
        const auto& sc = spec.size_constraints;
        std::size_t count = 0;
        if (sc.flags & Constraints::SIZE_CONSTRAINED) {
            if (sc.size_lower == sc.size_upper) {
                count = static_cast<std::size_t>(sc.size_lower);
            } else {
                auto v = stream.get_bits(sc.size_range_bits);
                if (!v) return decode_err(v.error());
                count = *v + static_cast<std::size_t>(sc.size_lower);
            }
        } else {
            auto v = per_detail::get_length(stream);
            if (!v) return decode_err(v.error());
            count = *v;
        }
        SeqOfBase& seq = *static_cast<SeqOfBase*>(dest);
        seq.resize(count);
        const auto& edef = *spec.element;
        IDecodeStream& ds = stream;
        for (std::size_t i = 0; i < count; ++i) {
            auto r = codec.decode(ds, edef, seq.get_mut(i));
            if (!r) return r;
        }
        return decode_ok();
    }
};

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
            int n_ext = spec.count - root_end;
            put_nslength(stream, static_cast<std::size_t>(n_ext));
            for (int i = root_end; i < spec.count; ++i)
                stream.put_bits(spec.members[i].optional_ops.is_present(src) ? 1 : 0, 1, "SEQ.ext_bitmap");
            for (int i = root_end; i < spec.count; ++i) {
                const auto& mbr = spec.members[i];
                if (!mbr.type_descriptor || !mbr.optional_ops.is_present(src)) continue;
                const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
                encode_open_type(codec, stream, *mbr.type_descriptor, mptr);
            }
        }
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
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
        int roms = 0;
        for (int i = 0; i < root_end; ++i)
            if (spec.members[i].optional) ++roms;
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
                for (int i = 0; i < n_ext; ++i) {
                    if (!ext_bitmap[i]) {
                        if (i < known_ext) {
                            const auto& absent = spec.members[root_end + i];
                            absent.optional_ops.set_present(dest, false);
                            if (absent.set_default) absent.set_default(dest);
                        }
                        continue;
                    }
                    if (i < known_ext) {
                        const auto& mbr = spec.members[root_end + i];
                        mbr.optional_ops.set_present(dest, true);
                        Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
                        auto r = decode_open_type(codec, stream, *mbr.type_descriptor, mptr);
                        if (!r) return r;
                    } else {
                        if (auto r = PerCodec::skip_ext(stream); !r) return r;
                    }
                }
            }
        }
        return decode_ok();
    }
};

class ChoicePerHandler final : public IPerTypeHandler {
public:
    void encode(const PerCodec& codec, PerEncodeStream& stream,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = static_cast<const ChoiceInterface*>(src);
        int pr = ch->_present;
        if (pr <= 0 || pr > spec.count) return;
        int def_idx = pr - 1;
        int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool in_ext = (spec.ext_at >= 0) && (def_idx >= root_count);
        if (debug_flags() & DBG_PER)
            std::fprintf(stderr, "[PER-ENC] CHO %s pr=%d root=%d ext=%d @%d\n",
                         def.name, pr, root_count, (int)in_ext, PerCodec::stream_bit_pos(stream));
        if (spec.ext_at >= 0) stream.put_bits(in_ext ? 1 : 0, 1, "CHO.ext");
        if (!in_ext) {
            // Generator emits root alternatives in canonical tag order — def_idx IS canonical.
            int bits = range_bits(root_count);
            if (bits > 0) stream.put_bits(static_cast<uint64_t>(def_idx), bits, "CHO.index");
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) return;
            IEncodeStream& es = stream;
            const Asn1Object* mptr = alt.get_const_fn(ch);
            codec.encode(es, *alt.type_descriptor, mptr);
        } else {
            int ext_idx = def_idx - root_count;
            // Generator emits extension alternatives in canonical tag order — ext_idx IS canonical.
            put_nsnn(stream, ext_idx);
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) return;
            const Asn1Object* mptr = alt.get_const_fn(ch);
            encode_open_type(codec, stream, *alt.type_descriptor, mptr);
        }
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& stream,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
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
            int bits = range_bits(root_count);
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
    auto& stream = static_cast<PerEncodeStream&>(dst);
    def.per_handler->encode(*this, stream, def, src);
}

DecodeResult PerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              Asn1Object* dest) const
{
    auto& stream = static_cast<PerDecodeStream&>(src);
    return def.per_handler->decode(*this, stream, def, dest);
}

} // namespace asn1
