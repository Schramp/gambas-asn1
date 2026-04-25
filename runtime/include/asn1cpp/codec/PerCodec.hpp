#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include "ICodec.hpp"
#include "PerConstraints.hpp"
#include "../Tag.hpp"
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
//
// Bits are packed MSB-first within each byte, matching X.691 conventions.
// UPER: no byte alignment between values.
// APER: byte-align before values with range >= 256 (not yet enforced here;
//       for small enumerations UPER == APER).

class PerEncodeStream : public IEncodeStream {
    std::vector<uint8_t>& buf_;
    uint8_t current_{0};
    int     bits_{0};   // bits written into current_ (0-7)
public:
    explicit PerEncodeStream(std::vector<uint8_t>& buf) : buf_(buf) {}

    // Write n bits of value, MSB first.
    void put_bits(uint64_t value, int n) {
        for (int i = n - 1; i >= 0; --i) {
            int bit = (value >> i) & 1;
            current_ |= static_cast<uint8_t>(bit << (7 - bits_));
            if (++bits_ == 8) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
        }
    }

    // Zero-pad the current byte and push it.
    // X.691 §11.1: a complete encoding of 0 bits is represented as one zero byte.
    void flush() {
        if (bits_ > 0 || buf_.empty()) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
    }

    std::vector<uint8_t>& buf() { return buf_; }
};

class PerDecodeStream : public IDecodeStream {
    std::span<const uint8_t> buf_;
    int byte_pos_{0};
    int bit_pos_{0};   // next bit within current byte (0 = MSB)
public:
    explicit PerDecodeStream(std::span<const uint8_t> buf) : buf_(buf) {}

    bool at_end() const override {
        return byte_pos_ >= static_cast<int>(buf_.size());
    }

    // Read n bits, MSB first.
    Expected<uint64_t, DecodeError> get_bits(int n) {
        uint64_t result = 0;
        for (int i = 0; i < n; ++i) {
            if (byte_pos_ >= static_cast<int>(buf_.size()))
                return make_unexpected<uint64_t, DecodeError>(
                    DecodeError("PER: unexpected end of data"));
            int bit = (buf_[byte_pos_] >> (7 - bit_pos_)) & 1;
            result = (result << 1) | static_cast<uint64_t>(bit);
            if (++bit_pos_ == 8) { ++byte_pos_; bit_pos_ = 0; }
        }
        return result;
    }
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

    // ------------------------------------------------------------------
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override
    {
        auto& s = static_cast<PerEncodeStream&>(dst);
        if (def.enum_spec)     { encode_enumerated(s, def, src); return; }
        if (def.sequence_spec) { encode_sequence   (s, def, src); return; }
        if (def.choice_spec)   { encode_choice     (s, def, src); return; }
        if (is_integer_tag(def.tag))  { encode_integer(s, def, src); return; }
        if (is_boolean_tag(def.tag))  { encode_boolean(s, src); return; }
        if (is_real_tag(def.tag))      { encode_real     (s, src); return; }
        if (is_bitstring_tag(def.tag))   { encode_bitstring  (s, src); return; }
        if (is_octetstring_tag(def.tag)) { encode_octetstring(s, src); return; }
        if (is_oid_tag(def.tag))         { encode_oid       (s, src); return; }
        if (is_reloid_tag(def.tag))      { encode_reloid    (s, src); return; }
        if (is_null_tag(def.tag))        { return; }  // NULL: zero bits (X.691 §18.1)
        if (is_string_tag(def.tag))      { encode_string    (s, def, src); return; }
    }

    // ------------------------------------------------------------------
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override
    {
        auto& s = static_cast<PerDecodeStream&>(src);
        if (def.enum_spec)     return decode_enumerated(s, def, dest);
        if (def.sequence_spec) return decode_sequence   (s, def, dest);
        if (def.choice_spec)   return decode_choice     (s, def, dest);
        if (is_integer_tag(def.tag))  return decode_integer(s, def, dest);
        if (is_boolean_tag(def.tag))  return decode_boolean(s, dest);
        if (is_real_tag(def.tag))      return decode_real     (s, dest);
        if (is_bitstring_tag(def.tag))   return decode_bitstring  (s, dest);
        if (is_octetstring_tag(def.tag)) return decode_octetstring(s, dest);
        if (is_oid_tag(def.tag))         return decode_oid   (s, dest);
        if (is_reloid_tag(def.tag))      return decode_reloid(s, dest);
        if (is_null_tag(def.tag))        return decode_ok();  // NULL: zero bits
        if (is_string_tag(def.tag))      return decode_string(s, def, dest);
        return decode_err(DecodeError(std::string("PerCodec: no spec for type ") + def.name));
    }

private:
    // ---- PER length determinant (X.691 §10.7) --------------------------
    // 0xxxxxxx         : length 0-127    (1 byte,  7 bits)
    // 10xxxxxx xxxxxxxx: length 128-16383 (2 bytes, 14 bits)

    static void put_length(PerEncodeStream& s, std::size_t n) {
        if (n <= 127) {
            s.put_bits(n, 8);  // top bit 0 + 7-bit value
        } else if (n <= 16383) {
            s.put_bits(0x80 | (n >> 8), 8);
            s.put_bits(n & 0xFF, 8);
        } else {
            // Fragmented encoding (§10.7.3) not yet implemented.
            // Callers should not pass lengths > 16383.
        }
    }

    static Expected<std::size_t, DecodeError> get_length(PerDecodeStream& s) {
        auto first = s.get_bits(8);
        if (!first) return make_unexpected<std::size_t, DecodeError>(first.error());
        if (!(*first & 0x80)) return static_cast<std::size_t>(*first);  // 0-127
        if ((*first & 0xC0) == 0x80) {
            auto second = s.get_bits(8);
            if (!second) return make_unexpected<std::size_t, DecodeError>(second.error());
            return static_cast<std::size_t>((*first & 0x3F) << 8 | *second);  // 128-16383
        }
        return make_unexpected<std::size_t, DecodeError>(
            DecodeError("PER: fragmented length not implemented"));
    }

    // ---- bit helpers ---------------------------------------------------

    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }
    static bool is_boolean_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Boolean;
    }
    static bool is_real_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Real;
    }
    static bool is_bitstring_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::BitString;
    }
    static bool is_octetstring_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::OctetString;
    }
    static bool is_null_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == 5;
    }
    static bool is_oid_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Oid;
    }
    static bool is_reloid_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::RelativeOid;
    }
    static bool is_string_tag(const Tag& t) {
        if (t.cls != TagClass::Universal) return false;
        switch (t.number) {
            case UniversalTag::ObjectDescriptor:
            case UniversalTag::NumericString:
            case UniversalTag::PrintableString:
            case UniversalTag::T61String:
            case UniversalTag::VideotexString:
            case UniversalTag::UtcTime:
            case UniversalTag::GeneralizedTime:
            case UniversalTag::GraphicString:
            case UniversalTag::VisibleString:
            case UniversalTag::GeneralString:
            case UniversalTag::UniversalString:
            case UniversalTag::BmpString:
                return true;
            default: return false;
        }
    }

    // Minimum bits to represent values in [0, range-1].
    static int range_bits(int64_t range) {
        if (range <= 1) return 0;
        int bits = 0;
        for (int64_t r = range - 1; r > 0; r >>= 1) ++bits;
        return bits;
    }

    // ---- BOOLEAN -------------------------------------------------------
    // X.691 §12.2: FALSE = 0, TRUE = 1 (single bit)

    static void encode_boolean(PerEncodeStream& s, const void* src) {
        bool v = *static_cast<const bool*>(src);
        s.put_bits(v ? 1 : 0, 1);
    }

    static DecodeResult decode_boolean(PerDecodeStream& s, void* dest) {
        auto bit = s.get_bits(1);
        if (!bit) return decode_err(bit.error());
        *static_cast<bool*>(dest) = (*bit != 0);
        return decode_ok();
    }

    // ---- BIT STRING ----------------------------------------------------
    // X.691 §15.6 unconstrained: 8-bit bit-count + raw bytes MSB-first.

    static void encode_bitstring(PerEncodeStream& s, const void* src) {
        const BitString& v = *static_cast<const BitString*>(src);
        put_length(s, v.bit_count());
        for (uint8_t b : v.bytes()) s.put_bits(b, 8);
    }

    static DecodeResult decode_bitstring(PerDecodeStream& s, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        int bit_count = static_cast<int>(*len_r);
        if (bit_count == 0) { *static_cast<BitString*>(dest) = BitString{}; return decode_ok(); }
        int byte_count = (bit_count + 7) / 8;
        uint8_t unused  = static_cast<uint8_t>(byte_count * 8 - bit_count);
        std::vector<uint8_t> bytes;
        bytes.reserve(byte_count);
        for (int i = 0; i < byte_count; ++i) {
            auto b = s.get_bits(8);
            if (!b) return decode_err(b.error());
            bytes.push_back(static_cast<uint8_t>(*b));
        }
        *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
        return decode_ok();
    }

    // ---- OCTET STRING --------------------------------------------------
    // X.691 §16: 8-bit byte-count + raw bytes.

    static void encode_octetstring(PerEncodeStream& s, const void* src) {
        const OctetString& v = *static_cast<const OctetString*>(src);
        put_length(s, v.size());
        for (uint8_t b : v.bytes()) s.put_bits(b, 8);
    }

    static DecodeResult decode_octetstring(PerDecodeStream& s, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        int len = static_cast<int>(*len_r);
        std::vector<uint8_t> bytes;
        bytes.reserve(len);
        for (int i = 0; i < len; ++i) {
            auto b = s.get_bits(8);
            if (!b) return decode_err(b.error());
            bytes.push_back(static_cast<uint8_t>(*b));
        }
        *static_cast<OctetString*>(dest) = OctetString{std::move(bytes)};
        return decode_ok();
    }

    // ---- OID / RELATIVE-OID --------------------------------------------
    // X.691 §14: length + BER content bytes (no TLV header).
    // Reuse BerTraits<Oid> to produce BER; strip the 2-byte TLV header.

    static void encode_oid(PerEncodeStream& s, const void* src) {
        const Oid& v = *static_cast<const Oid*>(src);
        std::vector<uint8_t> ber;
        { BerWriter w{ber}; BerTraits<Oid>::encode(w, v); }
        uint8_t content_len = ber[1];
        put_length(s, content_len);
        for (int i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
    }

    static DecodeResult decode_oid(PerDecodeStream& s, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        int len = static_cast<int>(*len_r);
        // Reconstruct BER TLV: [0x06, len, content...]
        std::vector<uint8_t> ber;
        ber.push_back(0x06);
        ber.push_back(static_cast<uint8_t>(len));
        for (int i = 0; i < len; ++i) {
            auto b = s.get_bits(8);
            if (!b) return decode_err(b.error());
            ber.push_back(static_cast<uint8_t>(*b));
        }
        BerReader r{ber};
        auto v = BerTraits<Oid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Oid*>(dest) = *v;
        return decode_ok();
    }

    static void encode_reloid(PerEncodeStream& s, const void* src) {
        const RelativeOid& v = *static_cast<const RelativeOid*>(src);
        std::vector<uint8_t> ber;
        { BerWriter w{ber}; BerTraits<RelativeOid>::encode(w, v); }
        uint8_t content_len = ber[1];
        put_length(s, content_len);
        for (int i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
    }

    static DecodeResult decode_reloid(PerDecodeStream& s, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        int len = static_cast<int>(*len_r);
        // Reconstruct BER TLV: [0x0d, len, content...]
        std::vector<uint8_t> ber;
        ber.push_back(0x0d);
        ber.push_back(static_cast<uint8_t>(len));
        for (int i = 0; i < len; ++i) {
            auto b = s.get_bits(8);
            if (!b) return decode_err(b.error());
            ber.push_back(static_cast<uint8_t>(*b));
        }
        BerReader r{ber};
        auto v = BerTraits<RelativeOid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<RelativeOid*>(dest) = *v;
        return decode_ok();
    }

    // ---- STRING TYPES --------------------------------------------------
    // Encoding per type (X.691 §27, unconstrained):
    //   NumericString (tag 18):   4-bit canonical index (11-char alphabet)
    //   PrintableString (tag 19): 7-bit canonical index (74-char alphabet)
    //     NOTE: asn1c has a bug here (truncates to 4 bits); XV not possible.
    //   UTCTime/GenTime/VisibleString/ObjectDescriptor: 7-bit raw ASCII value
    //   T61/Videotex/Graphic/General: 8-bit raw bytes
    //   BmpString: char-count + raw UTF-16BE bytes (2 bytes/char)
    //   UniversalString: char-count + raw UTF-32BE bytes (4 bytes/char)

    static constexpr const char PS_CHARSET[] =
        " '()+,-./" "0123456789" ":=?"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    static uint8_t encode_numeric_char(char c) {
        if (c == ' ') return 0;
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 1);
        return 0;
    }
    static char decode_numeric_char(uint8_t v) {
        if (v == 0) return ' ';
        if (v >= 1 && v <= 10) return static_cast<char>('0' + (v - 1));
        return '?';
    }

    static uint8_t encode_ps_char(char c) {
        for (int i = 0; PS_CHARSET[i]; ++i)
            if (PS_CHARSET[i] == c) return static_cast<uint8_t>(i);
        return 0;
    }
    static char decode_ps_char(uint8_t v) {
        return (v < 74) ? PS_CHARSET[v] : '?';
    }

    // Returns {bits_per_unit, bytes_per_char} where bytes_per_char>1 for BMP/Universal.
    static std::tuple<int,int> string_params(uint32_t tag_num) {
        switch (tag_num) {
            case UniversalTag::NumericString:   return {4, 1};
            case UniversalTag::PrintableString: return {7, 1};  // 7-bit raw ASCII (matches fixed asn1c)
            case UniversalTag::BmpString:       return {8, 2};  // length in chars, 2 bytes each
            case UniversalTag::UniversalString: return {8, 4};  // length in chars, 4 bytes each
            // 7-bit raw ASCII
            case UniversalTag::UtcTime:
            case UniversalTag::GeneralizedTime:
            case UniversalTag::VisibleString:   return {7, 1};
            // 8-bit raw bytes
            default:                            return {8, 1};
        }
    }

    static void encode_string(PerEncodeStream& s, const TypeDescriptor& def, const void* src) {
        const std::string& str = *reinterpret_cast<const std::string*>(src);
        auto [bits, bpc] = string_params(def.tag.number);
        std::size_t char_count = str.size() / bpc;
        put_length(s, char_count);
        if (bpc > 1) {
            // BmpString / UniversalString: write raw bytes directly
            for (unsigned char c : str) s.put_bits(c, 8);
        } else if (bits == 4) {
            for (char c : str) s.put_bits(encode_numeric_char(c), 4);
        } else if (bits == 7) {
            for (char c : str) s.put_bits(static_cast<uint8_t>(c), 7);
        } else {
            for (char c : str) s.put_bits(static_cast<uint8_t>(c), 8);
        }
    }

    static DecodeResult decode_string(PerDecodeStream& s, const TypeDescriptor& def, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        std::size_t char_count = *len_r;
        auto [bits, bpc] = string_params(def.tag.number);
        std::size_t byte_count = char_count * bpc;
        std::string result;
        result.reserve(byte_count);
        if (bpc > 1) {
            for (std::size_t i = 0; i < byte_count; ++i) {
                auto b = s.get_bits(8);
                if (!b) return decode_err(b.error());
                result.push_back(static_cast<char>(*b));
            }
        } else if (bits == 4) {
            for (std::size_t i = 0; i < char_count; ++i) {
                auto v = s.get_bits(4);
                if (!v) return decode_err(v.error());
                result.push_back(decode_numeric_char(static_cast<uint8_t>(*v)));
            }
        } else if (bits == 7) {
            for (std::size_t i = 0; i < char_count; ++i) {
                auto v = s.get_bits(7);
                if (!v) return decode_err(v.error());
                result.push_back(static_cast<char>(*v));
            }
        } else {
            for (std::size_t i = 0; i < char_count; ++i) {
                auto v = s.get_bits(8);
                if (!v) return decode_err(v.error());
                result.push_back(static_cast<char>(*v));
            }
        }
        *reinterpret_cast<std::string*>(dest) = std::move(result);
        return decode_ok();
    }

    // ---- REAL ----------------------------------------------------------
    // X.691 §15: zero → 0 bits; non-zero → length byte + BER content bytes.
    // Reuse BerTraits<Real> to produce the content; strip the 2-byte TLV header.

    void encode_real(PerEncodeStream& s, const void* src) const {
        const Real& v = *static_cast<const Real*>(src);
        if (v.value() == 0.0) return;  // 0 bits; flush() handles §11.1 zero byte
        std::vector<uint8_t> ber;
        { BerWriter w{ber}; BerTraits<Real>::encode(w, v); }
        // ber = [tag(1 byte), len(1 byte), content...]; REAL content always < 128 bytes
        std::size_t content_len = ber[1];
        put_length(s, content_len);
        for (std::size_t i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
    }

    DecodeResult decode_real(PerDecodeStream& s, void* dest) const {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        int len = static_cast<int>(*len_r);
        if (len == 0) { *static_cast<Real*>(dest) = Real{0.0}; return decode_ok(); }
        std::vector<uint8_t> ber;
        ber.push_back(0x09);  // REAL universal tag
        ber.push_back(static_cast<uint8_t>(len));
        for (int i = 0; i < len; ++i) {
            auto b = s.get_bits(8);
            if (!b) return decode_err(b.error());
            ber.push_back(static_cast<uint8_t>(*b));
        }
        BerReader r{std::span<const uint8_t>(ber)};
        auto v = BerTraits<Real>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Real*>(dest) = *v;
        return decode_ok();
    }

    // ---- INTEGER -------------------------------------------------------
    //
    // Constrained (per_constraints != nullptr):
    //   encoded = value - lower; write range_bits bits MSB-first (UPER).
    // Unconstrained (per_constraints == nullptr):
    //   length (1 byte, value in bytes) + big-endian minimal two's-complement.

    void encode_integer(PerEncodeStream& s,
                        const TypeDescriptor& def,
                        const void* src) const
    {
        int64_t value = *static_cast<const int64_t*>(src);
        const auto* pc = static_cast<const PerConstraints*>(def.per_constraints);
        if (pc && (pc->flags & PerConstraints::CONSTRAINED)) {
            int64_t encoded = value - pc->lower_bound;
            int64_t rcount  = pc->upper_bound - pc->lower_bound + 1;
            s.put_bits(static_cast<uint64_t>(encoded), range_bits(rcount));
        } else {
            // Unconstrained: minimal big-endian bytes, preceded by byte count.
            uint8_t buf[8]; int len = 0;
            if (value == 0) { buf[0] = 0; len = 1; }
            else {
                uint64_t u = static_cast<uint64_t>(value);
                for (int i = 7; i >= 0; --i) { buf[i] = u & 0xFF; u >>= 8; }
                int start = (value > 0) ? 0 : 0;
                if (value > 0) {
                    while (start < 7 && buf[start] == 0x00 && !(buf[start+1] & 0x80)) ++start;
                } else {
                    while (start < 7 && buf[start] == 0xFF && (buf[start+1] & 0x80)) ++start;
                }
                len = 8 - start;
                std::memmove(buf, buf + start, len);
            }
            s.put_bits(static_cast<uint64_t>(len), 8);  // length byte
            for (int i = 0; i < len; ++i) s.put_bits(buf[i], 8);
        }
    }

    DecodeResult decode_integer(PerDecodeStream& s,
                                const TypeDescriptor& def,
                                void* dest) const
    {
        const auto* pc = static_cast<const PerConstraints*>(def.per_constraints);
        if (pc && (pc->flags & PerConstraints::CONSTRAINED)) {
            int64_t rcount = pc->upper_bound - pc->lower_bound + 1;
            auto bits = s.get_bits(range_bits(rcount));
            if (!bits) return decode_err(bits.error());
            *static_cast<int64_t*>(dest) = pc->lower_bound + static_cast<int64_t>(*bits);
            return decode_ok();
        } else {
            // Unconstrained: read length byte, then that many bytes.
            auto len_bits = s.get_bits(8);
            if (!len_bits) return decode_err(len_bits.error());
            int len = static_cast<int>(*len_bits);
            if (len == 0 || len > 8)
                return decode_err(DecodeError("PER: INTEGER length out of range"));
            int64_t value = 0;
            for (int i = 0; i < len; ++i) {
                auto b = s.get_bits(8);
                if (!b) return decode_err(b.error());
                if (i == 0 && (*b & 0x80)) value = -1;  // sign-extend
                value = (value << 8) | static_cast<int64_t>(*b);
            }
            *static_cast<int64_t*>(dest) = value;
            return decode_ok();
        }
    }

    // ---- ENUMERATED ----------------------------------------------------
    //
    // X.691 §13:
    //   extensible  → 1-bit extension flag; 0 = root, 1 = extension
    //   root value  → constrained-whole-number in [0, root_count-1]
    //   ext value   → normally-small-number (open type; not yet implemented)
    //   non-extensible → constrained-whole-number in [0, count-1]

    void encode_enumerated(PerEncodeStream& s,
                           const TypeDescriptor& def,
                           const void* src) const
    {
        long value = *static_cast<const long*>(src);
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;

        // Find ordinal in definition order (per_value_order for root values).
        const long* order = spec.per_value_order;
        int ordinal = -1;
        bool is_ext = false;

        if (order) {
            for (int i = 0; i < rcount; ++i) {
                if (order[i] == value) { ordinal = i; break; }
            }
        } else {
            // No separate order array: entries are already in definition order.
            for (int i = 0; i < rcount; ++i) {
                if (spec.entries[i].value == value) { ordinal = i; break; }
            }
        }

        if (ordinal < 0) {
            // Extension value — find its extension ordinal.
            for (int i = rcount; i < spec.count; ++i) {
                if (spec.entries[i].value == value) {
                    ordinal = i - rcount;
                    is_ext = true;
                    break;
                }
            }
        }

        if (spec.extensible) {
            s.put_bits(is_ext ? 1 : 0, 1);
        }

        if (!is_ext) {
            int rb = range_bits(rcount);
            s.put_bits(static_cast<uint64_t>(ordinal), rb);
        } else {
            // Open-type extension encoding (X.691 §13.3) — not yet implemented.
            // Emit a placeholder 0 byte (normally-small-number = 0).
            s.put_bits(0, 8);
        }
    }

    DecodeResult decode_enumerated(PerDecodeStream& s,
                                   const TypeDescriptor& def,
                                   void* dest) const
    {
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;

        bool is_ext = false;
        if (spec.extensible) {
            auto bit = s.get_bits(1);
            if (!bit) return decode_err(bit.error());
            is_ext = (*bit != 0);
        }

        if (!is_ext) {
            int rb = range_bits(rcount);
            auto idx = s.get_bits(rb);
            if (!idx) return decode_err(idx.error());
            if (*idx >= static_cast<uint64_t>(rcount))
                return decode_err(DecodeError("PER: ENUM index out of range"));

            long value;
            const long* order = spec.per_value_order;
            if (order) {
                value = order[*idx];
            } else {
                value = spec.entries[*idx].value;
            }
            *static_cast<long*>(dest) = value;
            return decode_ok();
        } else {
            // Extension value: normally-small-number (not yet implemented).
            return decode_err(DecodeError("PER: ENUM extension values not yet implemented"));
        }
    }

    // ---- SEQUENCE / SET -------------------------------------------------
    //
    // Non-extensible, no-optional case: concatenate member encodings.
    // OPTIONAL members and extension bitmap (X.691 §18) deferred to later step.

    void encode_sequence(PerEncodeStream& s,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member PER encode
            const void* mptr = static_cast<const char*>(src) + mbr.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            encode(s, mdef, mptr);
        }
    }

    DecodeResult decode_sequence(PerDecodeStream& s,
                                 const TypeDescriptor& def,
                                 void* dest) const
    {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member PER decode
            void* mptr = static_cast<char*>(dest) + mbr.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            auto r = decode(s, mdef, mptr);
            if (!r) return r;
        }
        return decode_ok();
    }

    // ---- CHOICE (stub) -------------------------------------------------

    void encode_choice(PerEncodeStream& s,
                       const TypeDescriptor& def,
                       const void* src) const
    {
        (void)s; (void)def; (void)src;
    }

    DecodeResult decode_choice(PerDecodeStream& s,
                               const TypeDescriptor& def,
                               void* dest) const
    {
        (void)s; (void)def; (void)dest;
        return decode_err(DecodeError("PerCodec: CHOICE not yet implemented"));
    }
};

} // namespace asn1
