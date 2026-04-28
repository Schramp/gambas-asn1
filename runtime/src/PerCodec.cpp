#include <asn1cpp/codec/PerCodec.hpp>

namespace asn1 {

// ---------------------------------------------------------------------------
// PerCodec — generic PER encode/decode driven by TypeDescriptor tables

void PerCodec::encode(IEncodeStream& dst,
            const TypeDescriptor& def,
            const void* src) const
{
    auto& s = static_cast<PerEncodeStream&>(dst);
    if (def.enum_spec)     { encode_enumerated(s, def, src); return; }
    if (def.sequence_spec) { encode_sequence   (s, def, src); return; }
    if (def.choice_spec)   { encode_choice     (s, def, src); return; }
    if (def.seq_of_spec)   { encode_seq_of     (s, def, src); return; }
    if (is_integer_tag(def.tag))  { encode_integer(s, def, src); return; }
    if (is_boolean_tag(def.tag))  { encode_boolean(s, src); return; }
    if (is_real_tag(def.tag))      { encode_real     (s, src); return; }
    if (is_bitstring_tag(def.tag))   { encode_bitstring  (s, def, src); return; }
    if (is_octetstring_tag(def.tag)) { encode_octetstring(s, def, src); return; }
    if (is_oid_tag(def.tag))         { encode_oid       (s, src); return; }
    if (is_reloid_tag(def.tag))      { encode_reloid    (s, src); return; }
    if (is_null_tag(def.tag))        { return; }  // NULL: zero bits (X.691 §18.1)
    if (is_string_tag(def.tag))      { encode_string    (s, def, src); return; }
}

// ------------------------------------------------------------------
DecodeResult PerCodec::decode(IDecodeStream& src,
                    const TypeDescriptor& def,
                    void* dest) const
{
    auto& s = static_cast<PerDecodeStream&>(src);
    if (def.enum_spec)     return decode_enumerated(s, def, dest);
    if (def.sequence_spec) return decode_sequence   (s, def, dest);
    if (def.choice_spec)   return decode_choice     (s, def, dest);
    if (def.seq_of_spec)   return decode_seq_of     (s, def, dest);
    if (is_integer_tag(def.tag))  return decode_integer(s, def, dest);
    if (is_boolean_tag(def.tag))  return decode_boolean(s, dest);
    if (is_real_tag(def.tag))      return decode_real     (s, dest);
    if (is_bitstring_tag(def.tag))   return decode_bitstring  (s, def, dest);
    if (is_octetstring_tag(def.tag)) return decode_octetstring(s, def, dest);
    if (is_oid_tag(def.tag))         return decode_oid   (s, dest);
    if (is_reloid_tag(def.tag))      return decode_reloid(s, dest);
    if (is_null_tag(def.tag))        return decode_ok();  // NULL: zero bits
    if (is_string_tag(def.tag))      return decode_string(s, def, dest);
    return decode_err(DecodeError(std::string("PerCodec: no spec for type ") + def.name));
}

// 0 + 6 bits: count 1..64 (7 bits total)
// 1 + standard length: count > 64

void PerCodec::put_nslength(PerEncodeStream& s, std::size_t n) {
    if (n >= 1 && n <= 64) { s.put_bits(0, 1); s.put_bits(n - 1, 6); }
    else { s.put_bits(1, 1); put_length(s, n); }
}

Expected<std::size_t, DecodeError> PerCodec::get_nslength(PerDecodeStream& s) {
    auto b = s.get_bits(1);
    if (!b) return make_unexpected<std::size_t, DecodeError>(b.error());
    if (*b == 0) {
        auto v = s.get_bits(6);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return *v + 1;
    }
    return PerCodec::get_length(s);
}

// X.691 §10.6 — normally small non-negative whole number
void PerCodec::put_nsnnwn(PerEncodeStream& s, int n) {
    if (n <= 63) { s.put_bits(0, 1); s.put_bits(static_cast<uint64_t>(n), 6); }
    else { s.put_bits(1, 1); put_length(s, static_cast<std::size_t>(n)); }
}
Expected<int, DecodeError> PerCodec::get_nsnnwn(PerDecodeStream& s) {
    auto b = s.get_bits(1);
    if (!b) return make_unexpected<int, DecodeError>(b.error());
    if (*b == 0) {
        auto v = s.get_bits(6);
        if (!v) return make_unexpected<int, DecodeError>(v.error());
        return static_cast<int>(*v);
    }
    auto len = PerCodec::get_length(s);
    if (!len) return make_unexpected<int, DecodeError>(len.error());
    return static_cast<int>(*len);
}

// ---- Open-type helpers (X.691 §11.2) — extension member wrapping --------

void PerCodec::encode_open_type(PerEncodeStream& s,
                      const TypeDescriptor& mdef,
                      const void* mptr) const {
    std::vector<uint8_t> tmp;
    PerEncodeStream tmp_s{tmp};
    PerCodec::encode(tmp_s, mdef, mptr);
    tmp_s.flush();
    PerCodec::put_length(s, tmp.size());
    for (auto b : tmp) s.put_bits(b, 8);
}

DecodeResult PerCodec::decode_open_type(PerDecodeStream& s,
                              const TypeDescriptor& mdef,
                              void* mptr) const {
    auto len_r = PerCodec::get_length(s);
    if (!len_r) return decode_err(len_r.error());
    auto bytes_r = PerCodec::read_bytes(s, *len_r);
    if (!bytes_r) return decode_err(bytes_r.error());
    PerDecodeStream tmp_s{std::span<const uint8_t>{bytes_r->data(), bytes_r->size()}};
    return PerCodec::decode(tmp_s, mdef, mptr);
}

DecodeResult PerCodec::skip_open_type(PerDecodeStream& s) {
    auto len_r = PerCodec::get_length(s);
    if (!len_r) return decode_err(len_r.error());
    for (std::size_t i = 0; i < *len_r; ++i) {
        auto b = s.get_bits(8);
        if (!b) return decode_err(b.error());
    }
    return decode_ok();
}


// ---- bit helpers ---------------------------------------------------

bool PerCodec::is_integer_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
}
bool PerCodec::is_boolean_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Boolean;
}
bool PerCodec::is_real_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Real;
}
bool PerCodec::is_bitstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::BitString;
}
bool PerCodec::is_octetstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::OctetString;
}
bool PerCodec::is_null_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 5;
}
bool PerCodec::is_oid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Oid;
}
bool PerCodec::is_reloid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::RelativeOid;
}
bool PerCodec::is_string_tag(const Tag& t) {
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
int PerCodec::range_bits(int64_t range) {
    if (range <= 1) return 0;
    int bits = 0;
    for (int64_t r = range - 1; r > 0; r >>= 1) ++bits;
    return bits;
}

// ---- BOOLEAN -------------------------------------------------------
// X.691 §12.2: FALSE = 0, TRUE = 1 (single bit)

void PerCodec::encode_boolean(PerEncodeStream& s, const void* src) {
    bool v = *static_cast<const bool*>(src);
    s.put_bits(v ? 1 : 0, 1);
}

DecodeResult PerCodec::decode_boolean(PerDecodeStream& s, void* dest) {
    auto bit = s.get_bits(1);
    if (!bit) return decode_err(bit.error());
    *static_cast<bool*>(dest) = (*bit != 0);
    return decode_ok();
}

// ---- BIT STRING ----------------------------------------------------
// X.691 §15.6 unconstrained: 8-bit bit-count + raw bytes MSB-first.

// ---- Byte-read helper -------------------------------------------------


// ---- SIZE field helpers (shared by BIT STRING and OCTET STRING) ------

void PerCodec::encode_size_field(PerEncodeStream& s, const TypeDescriptor& def, std::size_t len) {
    const PerConstraints& pc = def.per_constraints;
    bool size_constrained = pc.flags & PerConstraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        // Fixed SIZE(n): no length field
    } else if (size_constrained) {
        s.put_bits(len - static_cast<std::size_t>(pc.size_lower), pc.size_range_bits);
    } else {
        PerCodec::put_length(s, len);
    }
}

Expected<std::size_t, DecodeError> PerCodec::decode_size_field(
        PerDecodeStream& s, const TypeDescriptor& def) {
    const PerConstraints& pc = def.per_constraints;
    bool size_constrained = pc.flags & PerConstraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        return static_cast<std::size_t>(pc.size_lower);
    } else if (size_constrained) {
        auto v = s.get_bits(pc.size_range_bits);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return static_cast<std::size_t>(*v) + static_cast<std::size_t>(pc.size_lower);
    } else {
        return PerCodec::get_length(s);
    }
}

// ---- BIT STRING ----------------------------------------------------
// X.691 §15: length = bit count; payload = top bit_count bits, packed MSB-first.

void PerCodec::encode_bitstring(PerEncodeStream& s, const TypeDescriptor& def, const void* src) {
    const BitString& v = *static_cast<const BitString*>(src);
    std::size_t bit_count = v.bit_count();
    PerCodec::encode_size_field(s, def, bit_count);
    std::size_t remaining = bit_count;
    for (uint8_t b : v.bytes()) {
        int n = static_cast<int>(std::min(remaining, std::size_t{8}));
        s.put_bits(static_cast<uint64_t>(b) >> (8 - n), n);
        remaining -= n;
        if (remaining == 0) break;
    }
}

DecodeResult PerCodec::decode_bitstring(PerDecodeStream& s, const TypeDescriptor& def, void* dest) {
    auto len_r = PerCodec::decode_size_field(s, def);
    if (!len_r) return decode_err(len_r.error());
    std::size_t bit_count = *len_r;
    if (bit_count == 0) { *static_cast<BitString*>(dest) = BitString{}; return decode_ok(); }
    std::vector<uint8_t> bytes;
    bytes.reserve((bit_count + 7) / 8);
    std::size_t remaining = bit_count;
    while (remaining > 0) {
        int n = static_cast<int>(std::min(remaining, std::size_t{8}));
        auto b = s.get_bits(n);
        if (!b) return decode_err(b.error());
        bytes.push_back(static_cast<uint8_t>(*b << (8 - n)));
        remaining -= n;
    }
    uint8_t unused = static_cast<uint8_t>((8 - bit_count % 8) % 8);
    *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
    return decode_ok();
}

// ---- OCTET STRING --------------------------------------------------
// X.691 §16: length = byte count; payload = raw bytes.

void PerCodec::encode_octetstring(PerEncodeStream& s, const TypeDescriptor& def, const void* src) {
    const OctetString& v = *static_cast<const OctetString*>(src);
    PerCodec::encode_size_field(s, def, v.size());
    for (uint8_t b : v.bytes()) s.put_bits(b, 8);
}

DecodeResult PerCodec::decode_octetstring(PerDecodeStream& s, const TypeDescriptor& def, void* dest) {
    auto len_r = PerCodec::decode_size_field(s, def);
    if (!len_r) return decode_err(len_r.error());
    auto bytes = PerCodec::read_bytes(s, *len_r);
    if (!bytes) return decode_err(bytes.error());
    *static_cast<OctetString*>(dest) = OctetString{std::move(*bytes)};
    return decode_ok();
}

// ---- OID / RELATIVE-OID --------------------------------------------
// X.691 §14: length + BER content bytes (no TLV header).
// Reuse BerTraits<Oid> to produce BER; strip the 2-byte TLV header.
//   PrintableString (tag 19): 7-bit canonical index (74-char alphabet)
//     NOTE: asn1c has a bug here (truncates to 4 bits); XV not possible.
//   UTCTime/GenTime/VisibleString/ObjectDescriptor: 7-bit raw ASCII value
//   T61/Videotex/Graphic/General: 8-bit raw bytes
//   BmpString: char-count + raw UTF-16BE bytes (2 bytes/char)
//   UniversalString: char-count + raw UTF-32BE bytes (4 bytes/char)

constexpr const char PS_CHARSET[] =
    " '()+,-./" "0123456789" ":=?"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

uint8_t PerCodec::encode_numeric_char(char c) {
    if (c == ' ') return 0;
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 1);
    return 0;
}
char PerCodec::decode_numeric_char(uint8_t v) {
    if (v == 0) return ' ';
    if (v >= 1 && v <= 10) return static_cast<char>('0' + (v - 1));
    return '?';
}

uint8_t PerCodec::encode_ps_char(char c) {
    for (int i = 0; PS_CHARSET[i]; ++i)
        if (PS_CHARSET[i] == c) return static_cast<uint8_t>(i);
    return 0;
}
char PerCodec::decode_ps_char(uint8_t v) {
    return (v < 74) ? PS_CHARSET[v] : '?';
}

// Returns {bits_per_unit, bytes_per_char} where bytes_per_char>1 for BMP/Universal.
std::tuple<int,int> PerCodec::string_params(uint32_t tag_num) {
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

void PerCodec::encode_string(PerEncodeStream& s, const TypeDescriptor& def, const void* src) {
    const std::string& str = *reinterpret_cast<const std::string*>(src);
    const PerConstraints& pc = def.per_constraints;

    auto [bits, bpc] = PerCodec::string_params(def.tag.number);
    bool has_alpha = pc.alphabet_bits > 0 && !pc.alphabet.empty();
    std::size_t char_count = has_alpha ? str.size() : str.size() / bpc;

    if (pc.flags & PerConstraints::EXTENSIBLE) {
        bool in_root;
        if (pc.flags & PerConstraints::SIZE_CONSTRAINED) {
            in_root = (char_count >= static_cast<std::size_t>(pc.size_lower) &&
                       char_count <= static_cast<std::size_t>(pc.size_upper));
        } else if (has_alpha) {
            in_root = true;
            for (unsigned char c : str)
                if (std::find(pc.alphabet.begin(), pc.alphabet.end(), c) == pc.alphabet.end())
                    { in_root = false; break; }
        } else {
            in_root = true;
        }
        s.put_bits(in_root ? 0 : 1, 1);
        if (!in_root) {
            PerCodec::put_length(s, char_count);
            for (unsigned char c : str) s.put_bits(c, 8);
            return;
        }
    }

    PerCodec::encode_size_field(s, def, char_count);

    // Character values
    if (has_alpha) {
        for (unsigned char c : str) {
            int code = 0;
            for (int i = 0; i < static_cast<int>(pc.alphabet.size()); ++i)
                if (pc.alphabet[i] == c) { code = i; break; }
            s.put_bits(static_cast<uint64_t>(code), pc.alphabet_bits);
        }
    } else if (bpc > 1) {
        for (unsigned char c : str) s.put_bits(c, 8);
    } else if (bits == 4) {
        for (char c : str) s.put_bits(encode_numeric_char(c), 4);
    } else if (bits == 7) {
        for (char c : str) s.put_bits(static_cast<uint8_t>(c), 7);
    } else {
        for (char c : str) s.put_bits(static_cast<uint8_t>(c), 8);
    }
}

DecodeResult PerCodec::decode_string(PerDecodeStream& s, const TypeDescriptor& def, void* dest) {
    const PerConstraints& pc = def.per_constraints;

    if (pc.flags & PerConstraints::EXTENSIBLE) {
        auto ext = s.get_bits(1);
        if (!ext) return decode_err(ext.error());
        if (*ext) {
            auto len_r = PerCodec::get_length(s);
            if (!len_r) return decode_err(len_r.error());
            std::string result;
            result.reserve(*len_r);
            for (std::size_t i = 0; i < *len_r; ++i) {
                auto b = s.get_bits(8);
                if (!b) return decode_err(b.error());
                result.push_back(static_cast<char>(*b));
            }
            *reinterpret_cast<std::string*>(dest) = std::move(result);
            return decode_ok();
        }
    }

    auto len_r = PerCodec::decode_size_field(s, def);
    if (!len_r) return decode_err(len_r.error());
    std::size_t char_count = *len_r;

    auto [bits, bpc] = PerCodec::string_params(def.tag.number);
    std::string result;

    if (pc.alphabet_bits > 0 && !pc.alphabet.empty()) {
        result.reserve(char_count);
        for (std::size_t i = 0; i < char_count; ++i) {
            auto v = s.get_bits(pc.alphabet_bits);
            if (!v) return decode_err(v.error());
            if (*v < pc.alphabet.size())
                result.push_back(static_cast<char>(pc.alphabet[*v]));
            else
                result.push_back('?');
        }
    } else {
        std::size_t byte_count = char_count * bpc;
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
    }

    *reinterpret_cast<std::string*>(dest) = std::move(result);
    return decode_ok();
}

// ---- REAL ----------------------------------------------------------
// X.691 §15: zero → 0 bits; non-zero → length byte + BER content bytes.
// Reuse BerTraits<Real> to produce the content; strip the 2-byte TLV header.

void PerCodec::encode_real(PerEncodeStream& s, const void* src) {
    const Real& v = *static_cast<const Real*>(src);
    if (v.value() == 0.0) return;  // 0 bits; flush() handles §11.1 zero byte
    std::vector<uint8_t> ber;
    { BerWriter w{ber}; BerTraits<Real>::encode(w, v); }
    // ber = [tag(1 byte), len(1 byte), content...]; REAL content always < 128 bytes
    std::size_t content_len = ber[1];
    PerCodec::put_length(s, content_len);
    for (std::size_t i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
}

DecodeResult PerCodec::decode_real(PerDecodeStream& s, void* dest) {
    return decode_ber_content<Real>(s, dest);
}

// ---- INTEGER -------------------------------------------------------
//
// Constrained (flags & CONSTRAINED):
//   encoded = value - lower; write range_bits bits MSB-first (UPER).
// Unconstrained (flags == 0):
//   length (1 byte, value in bytes) + big-endian minimal two's-complement.

// Unconstrained integer: 1-byte length + minimal 2's-complement bytes.
void PerCodec::encode_unconstrained_int(PerEncodeStream& s, int64_t value) {
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
    s.put_bits(static_cast<uint64_t>(len), 8);
    for (int i = 0; i < len; ++i) s.put_bits(buf[i], 8);
}

DecodeResult PerCodec::decode_unconstrained_int(PerDecodeStream& s, void* dest) {
    auto len_bits = s.get_bits(8);
    if (!len_bits) return decode_err(len_bits.error());
    int len = static_cast<int>(*len_bits);
    if (len == 0 || len > 8)
        return decode_err(DecodeError("PER: INTEGER length out of range"));
    int64_t value = 0;
    for (int i = 0; i < len; ++i) {
        auto b = s.get_bits(8);
        if (!b) return decode_err(b.error());
        if (i == 0 && (*b & 0x80)) value = -1;
        value = (value << 8) | static_cast<int64_t>(*b);
    }
    *static_cast<int64_t*>(dest) = value;
    return decode_ok();
}

void PerCodec::encode_integer(PerEncodeStream& s,
                    const TypeDescriptor& def,
                    const void* src)
{
    int64_t value = *static_cast<const int64_t*>(src);
    const PerConstraints& pc = def.per_constraints;
    if (pc.flags & PerConstraints::CONSTRAINED) {
        if (pc.flags & PerConstraints::EXTENSIBLE) {
            bool in_root = (value >= pc.lower_bound && value <= pc.upper_bound);
            s.put_bits(in_root ? 0 : 1, 1);
            if (!in_root) { encode_unconstrained_int(s, value); return; }
        }
        int64_t encoded = value - pc.lower_bound;
        int64_t rcount  = pc.upper_bound - pc.lower_bound + 1;
        s.put_bits(static_cast<uint64_t>(encoded), range_bits(rcount));
    } else if (pc.flags & PerConstraints::SEMI_CONSTRAINED) {
        if (pc.flags & PerConstraints::EXTENSIBLE) {
            bool in_root = (value >= pc.lower_bound);
            s.put_bits(in_root ? 0 : 1, 1);
            if (!in_root) { encode_unconstrained_int(s, value); return; }
        }
        PerCodec::encode_unconstrained_int(s, value - pc.lower_bound);
    } else {
        PerCodec::encode_unconstrained_int(s, value);
    }
}

DecodeResult PerCodec::decode_integer(PerDecodeStream& s,
                            const TypeDescriptor& def,
                            void* dest)
{
    const PerConstraints& pc = def.per_constraints;
    if (pc.flags & PerConstraints::CONSTRAINED) {
        if (pc.flags & PerConstraints::EXTENSIBLE) {
            auto ext = s.get_bits(1);
            if (!ext) return decode_err(ext.error());
            if (*ext) return decode_unconstrained_int(s, dest);
        }
        int64_t rcount = pc.upper_bound - pc.lower_bound + 1;
        auto bits = s.get_bits(range_bits(rcount));
        if (!bits) return decode_err(bits.error());
        *static_cast<int64_t*>(dest) = pc.lower_bound + static_cast<int64_t>(*bits);
        return decode_ok();
    } else if (pc.flags & PerConstraints::SEMI_CONSTRAINED) {
        if (pc.flags & PerConstraints::EXTENSIBLE) {
            auto ext = s.get_bits(1);
            if (!ext) return decode_err(ext.error());
            if (*ext) return decode_unconstrained_int(s, dest);
        }
        int64_t adjusted = 0;
        auto r = PerCodec::decode_unconstrained_int(s, &adjusted);
        if (!r) return r;
        *static_cast<int64_t*>(dest) = adjusted + pc.lower_bound;
        return decode_ok();
    } else {
        return PerCodec::decode_unconstrained_int(s, dest);
    }
}

// ---- ENUMERATED ----------------------------------------------------
//
// X.691 §13:
//   extensible  → 1-bit extension flag; 0 = root, 1 = extension
//   root value  → constrained-whole-number in [0, root_count-1]
//   ext value   → normally-small-number (open type; not yet implemented)
//   non-extensible → constrained-whole-number in [0, count-1]

void PerCodec::encode_enumerated(PerEncodeStream& s,
                       const TypeDescriptor& def,
                       const void* src)
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
        int rb = PerCodec::range_bits(rcount);
        s.put_bits(static_cast<uint64_t>(ordinal), rb);
    } else {
        // X.691 §13.3 + §10.6: normally small non-negative whole number
        PerCodec::put_nsnnwn(s, ordinal);
    }
}

DecodeResult PerCodec::decode_enumerated(PerDecodeStream& s,
                               const TypeDescriptor& def,
                               void* dest)
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
        int rb = PerCodec::range_bits(rcount);
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
        // X.691 §13.3 + §10.6: normally small non-negative whole number
        auto ord = PerCodec::get_nsnnwn(s);
        if (!ord) return decode_err(ord.error());
        int ext_idx = *ord;
        int ext_entry = rcount + ext_idx;
        if (ext_entry >= spec.count)
            return decode_err(DecodeError("PER: ENUM extension index out of range"));
        *static_cast<long*>(dest) = spec.entries[ext_entry].value;
        return decode_ok();
    }
}

// ---- SEQUENCE OF / SET OF -------------------------------------------
//
// X.691 §19: unconstrained length via put_length, or SIZE-constrained range bits.

void PerCodec::encode_seq_of(PerEncodeStream& s,
                   const TypeDescriptor& def,
                   const void* src) const
{
    const auto& spec = *def.seq_of_spec;
    std::size_t count = spec.count_fn(src);
    const auto& sc = spec.size_constraints;
    // Encode count
    if (sc.flags & PerConstraints::SIZE_CONSTRAINED) {
        if (sc.size_lower == sc.size_upper) {
            // Fixed size: count implicit, no bits emitted
        } else {
            s.put_bits(count - static_cast<std::size_t>(sc.size_lower), sc.size_range_bits);
        }
    } else {
        PerCodec::put_length(s, count);
    }
    // Encode elements
    const auto& edef = *spec.element;
    for (std::size_t i = 0; i < count; ++i)
        PerCodec::encode(s, edef, spec.get_const_fn(src, i));
}

DecodeResult PerCodec::decode_seq_of(PerDecodeStream& s,
                           const TypeDescriptor& def,
                           void* dest) const
{
    const auto& spec = *def.seq_of_spec;
    const auto& sc = spec.size_constraints;
    // Decode count
    std::size_t count = 0;
    if (sc.flags & PerConstraints::SIZE_CONSTRAINED) {
        if (sc.size_lower == sc.size_upper) {
            count = static_cast<std::size_t>(sc.size_lower);
        } else {
            auto v = s.get_bits(sc.size_range_bits);
            if (!v) return decode_err(v.error());
            count = *v + static_cast<std::size_t>(sc.size_lower);
        }
    } else {
        auto v = PerCodec::get_length(s);
        if (!v) return decode_err(v.error());
        count = *v;
    }
    // Decode elements
    spec.resize_fn(dest, count);
    const auto& edef = *spec.element;
    for (std::size_t i = 0; i < count; ++i) {
        auto r = PerCodec::decode(s, edef, spec.get_fn(dest, i));
        if (!r) return r;
    }
    return decode_ok();
}

// ---- SEQUENCE / SET -------------------------------------------------
//
// X.691 §18: preamble bitmap (roms_count bits, one per root OPTIONAL/DEFAULT
// member in definition order), then member values in order.

void PerCodec::encode_sequence(PerEncodeStream& s,
                     const TypeDescriptor& def,
                     const void* src) const
{
    const auto& spec = *def.sequence_spec;
    int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;

    // X.691 §18.1: extension bit — 1 if any extension member present
    bool has_ext = false;
    if (spec.ext_at >= 0) {
        for (int i = root_end; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (mbr.optional_ops.is_present(src)) { has_ext = true; break; }
        }
        s.put_bits(has_ext ? 1 : 0, 1);
    }

    // Root preamble: 1 bit per root optional member
    for (int i = 0; i < root_end; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.optional) continue;
        bool present = mbr.optional_ops.is_present(src);
        s.put_bits(present ? 1 : 0, 1);
    }

    // Root member values
    for (int i = 0; i < root_end; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.type_descriptor) continue;
        if (mbr.optional && (!mbr.optional_ops.is_present(src))) continue;
        const void* mptr = static_cast<const char*>(src) + mbr.offset;
        PerCodec::encode(s, *static_cast<const TypeDescriptor*>(mbr.type_descriptor), mptr);
    }

    // Extension encoding (X.691 §18.7-18.9)
    if (has_ext) {
        int n_ext = spec.count - root_end;
        PerCodec::put_nslength(s, static_cast<std::size_t>(n_ext));   // §18.8 bitmap length
        for (int i = root_end; i < spec.count; ++i) {       // §18.7 presence bitmap
            const auto& mbr = spec.members[i];
            bool present = mbr.optional_ops.is_present(src);
            s.put_bits(present ? 1 : 0, 1);
        }
        for (int i = root_end; i < spec.count; ++i) {       // §18.9 open-type values
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor || !mbr.optional_ops.is_present(src)) continue;
            const void* mptr = static_cast<const char*>(src) + mbr.offset;
            PerCodec::encode_open_type(s, *static_cast<const TypeDescriptor*>(mbr.type_descriptor), mptr);
        }
    }
}

DecodeResult PerCodec::decode_sequence(PerDecodeStream& s,
                             const TypeDescriptor& def,
                             void* dest) const
{
    const auto& spec = *def.sequence_spec;
    int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;

    // Extension bit (X.691 §18.1)
    bool ext_flag = false;
    if (spec.ext_at >= 0) {
        auto b = s.get_bits(1);
        if (!b) return decode_err(b.error());
        ext_flag = (*b != 0);
    }

    // Root preamble bitmap
    int roms = 0;
    for (int i = 0; i < root_end; ++i)
        if (spec.members[i].optional) ++roms;
    bool bitmap[64] = {};
    for (int i = 0; i < roms && i < 64; ++i) {
        auto bit = s.get_bits(1);
        if (!bit) return decode_err(bit.error());
        bitmap[i] = (*bit != 0);
    }

    // Root member values
    int opt_idx = 0;
    for (int i = 0; i < root_end; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.type_descriptor) continue;
        if (mbr.optional) {
            bool present = bitmap[opt_idx++];
            mbr.optional_ops.set_present(dest, present);
            if (!present) continue;
        }
        void* mptr = static_cast<char*>(dest) + mbr.offset;
        auto r = PerCodec::decode(s, *static_cast<const TypeDescriptor*>(mbr.type_descriptor), mptr);
        if (!r) return r;
    }

    // Extension decoding
    if (spec.ext_at >= 0) {
        int known_ext = spec.count - root_end;
        if (!ext_flag) {
            for (int i = root_end; i < spec.count; ++i) {
                const auto& mbr = spec.members[i];
                mbr.optional_ops.set_present(dest, false);
            }
        } else {
            auto n_ext_r = PerCodec::get_nslength(s);
            if (!n_ext_r) return decode_err(n_ext_r.error());
            int n_ext = static_cast<int>(*n_ext_r);
            bool ext_bitmap[64] = {};
            for (int i = 0; i < n_ext && i < 64; ++i) {
                auto b = s.get_bits(1);
                if (!b) return decode_err(b.error());
                ext_bitmap[i] = (*b != 0);
            }
            for (int i = 0; i < n_ext; ++i) {
                if (!ext_bitmap[i]) {
                    if (i < known_ext) {
                        const auto& mbr = spec.members[root_end + i];
                        mbr.optional_ops.set_present(dest, false);
                    }
                    continue;
                }
                if (i < known_ext) {
                    const auto& mbr = spec.members[root_end + i];
                    mbr.optional_ops.set_present(dest, true);
                    void* mptr = static_cast<char*>(dest) + mbr.offset;
                    auto r = PerCodec::decode_open_type(s, *static_cast<const TypeDescriptor*>(mbr.type_descriptor), mptr);
                    if (!r) return r;
                } else {
                    if (auto r = skip_open_type(s); !r) return r;
                }
            }
        }
    }
    return decode_ok();
}

// ---- CHOICE ---------------------------------------------------------

int PerCodec::choice_index_bits(int n) {
    if (n <= 1) return 0;
    int bits = 0, m = 1;
    while (m < n) { ++bits; m <<= 1; }
    return bits;
}

// X.691 §22.2: build to_canonical[i] = def_idx at canonical position i
// (sorted by ascending tag_class then tag_number).
// The UPER encoded value for def_idx d is to_canonical[d].
// from_canonical[encoded] = def_idx (inverse map, used for decode).
void PerCodec::build_canonical_maps(const ChoiceSpec& spec, int root_count,
                                 std::vector<int>& to_canonical,
                                 std::vector<int>& from_canonical)
{
    to_canonical.resize(root_count);
    std::iota(to_canonical.begin(), to_canonical.end(), 0);
    std::stable_sort(to_canonical.begin(), to_canonical.end(),
        [&](int a, int b) {
            const auto& ta = spec.alternatives[a].tag;
            const auto& tb = spec.alternatives[b].tag;
            if (ta.cls != tb.cls) return (int)ta.cls < (int)tb.cls;
            return ta.number < tb.number;
        });
    from_canonical.resize(root_count);
    for (int i = 0; i < root_count; ++i)
        from_canonical[to_canonical[i]] = i;
}

void PerCodec::encode_choice(PerEncodeStream& s,
                   const TypeDescriptor& def,
                   const void* src) const
{
    const auto& spec = *def.choice_spec;
    int pr = *static_cast<const int*>(src);
    if (pr <= 0 || pr > spec.count) return;
    int def_idx = pr - 1;

    int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
    bool in_ext = (spec.ext_at >= 0) && (def_idx >= root_count);

    if (spec.ext_at >= 0)
        s.put_bits(in_ext ? 1 : 0, 1);

    if (!in_ext) {
        std::vector<int> to_can, from_can;
        PerCodec::build_canonical_maps(spec, root_count, to_can, from_can);
        int canonical_idx = to_can[def_idx];
        int bits = PerCodec::choice_index_bits(root_count);
        if (bits > 0) s.put_bits(static_cast<uint64_t>(canonical_idx), bits);
        const auto& alt = spec.alternatives[def_idx];
        if (!alt.type_descriptor) return;
        const void* mptr = static_cast<const char*>(src) + alt.offset;
        PerCodec::encode(s, *static_cast<const TypeDescriptor*>(alt.type_descriptor), mptr);
    } else {
        // X.691 §22.8: normally-small non-negative whole number for ext index
        int ext_idx = def_idx - root_count;
        if (ext_idx < 64) {
            s.put_bits(0, 1);
            s.put_bits(static_cast<uint64_t>(ext_idx), 6);
        } else {
            s.put_bits(1, 1);
            PerCodec::put_length(s, static_cast<std::size_t>(ext_idx));
        }
        const auto& alt = spec.alternatives[def_idx];
        if (!alt.type_descriptor) return;
        const void* mptr = static_cast<const char*>(src) + alt.offset;
        PerCodec::encode_open_type(s, *static_cast<const TypeDescriptor*>(alt.type_descriptor), mptr);
    }
}

DecodeResult PerCodec::decode_choice(PerDecodeStream& s,
                           const TypeDescriptor& def,
                           void* dest) const
{
    const auto& spec = *def.choice_spec;
    int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;

    bool in_ext = false;
    if (spec.ext_at >= 0) {
        auto b = s.get_bits(1);
        if (!b) return decode_err(b.error());
        in_ext = (*b != 0);
    }

    if (!in_ext) {
        std::vector<int> to_can, from_can;
        PerCodec::build_canonical_maps(spec, root_count, to_can, from_can);
        int bits = PerCodec::choice_index_bits(root_count);
        int canonical_idx = 0;
        if (bits > 0) {
            auto v = s.get_bits(bits);
            if (!v) return decode_err(v.error());
            canonical_idx = static_cast<int>(*v);
        }
        if (canonical_idx < 0 || canonical_idx >= root_count)
            return decode_err(DecodeError("CHOICE index out of range"));
        int def_idx = from_can[canonical_idx];
        const auto& alt = spec.alternatives[def_idx];
        if (!alt.type_descriptor)
            return decode_err(DecodeError("CHOICE alternative has no type descriptor"));
        void* mptr = static_cast<char*>(dest) + alt.offset;
        auto r = PerCodec::decode(s, *static_cast<const TypeDescriptor*>(alt.type_descriptor), mptr);
        if (!r) return r;
        *static_cast<int*>(dest) = def_idx + 1;
        return decode_ok();
    } else {
        // X.691 §22.8: read normally-small non-negative whole number
        auto b = s.get_bits(1);
        if (!b) return decode_err(b.error());
        int ext_idx;
        if (*b == 0) {
            auto v = s.get_bits(6);
            if (!v) return decode_err(v.error());
            ext_idx = static_cast<int>(*v);
        } else {
            auto v = PerCodec::get_length(s);
            if (!v) return decode_err(v.error());
            ext_idx = static_cast<int>(*v);
        }
        int def_idx = root_count + ext_idx;
        if (def_idx < spec.count) {
            const auto& alt = spec.alternatives[def_idx];
            if (alt.type_descriptor) {
                void* mptr = static_cast<char*>(dest) + alt.offset;
                auto r = PerCodec::decode_open_type(s, *static_cast<const TypeDescriptor*>(alt.type_descriptor), mptr);
                if (!r) return r;
                *static_cast<int*>(dest) = def_idx + 1;
            } else {
                if (auto r = skip_open_type(s); !r) return r;
            }
        } else {
            if (auto r = skip_open_type(s); !r) return r;
        }
        return decode_ok();
    }
}

} // namespace asn1
