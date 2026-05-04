#include <asn1cpp/codec/XerCodec.hpp>

namespace asn1 {

// ---------------------------------------------------------------------------
// Public encode/decode dispatch

void XerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const void* src) const
{
    auto& s = static_cast<XerEncodeStream&>(dst);
    if (def.is_any)        { encode_any_xer        (s, def, src); return; }
    if (def.enum_spec)     { encode_enumerated(s, def, src); return; }
    if (def.sequence_spec) { encode_sequence   (s, def, src); return; }
    if (def.choice_spec)   { encode_choice     (s, def, src); return; }
    if (def.seq_of_spec)   { encode_seq_of     (s, def, src); return; }
    if (is_boolean_tag(def.tag))          { encode_boolean         (s, def, src); return; }
    if (is_integer_tag(def.tag))          { encode_integer         (s, def, src); return; }
    if (is_null_tag(def.tag))             { encode_null            (s, def);      return; }
    if (is_real_tag(def.tag))             { encode_real            (s, def, src); return; }
    if (is_bitstring_tag(def.tag))        { encode_bitstring       (s, def, src); return; }
    if (is_oid_tag(def.tag))              { encode_oid             (s, def, src); return; }
    if (is_relative_oid_tag(def.tag))     { encode_relative_oid   (s, def, src); return; }
    if (is_utctime_tag(def.tag))          { encode_time_string     (s, def, src); return; }
    if (is_gentime_tag(def.tag))          { encode_time_string     (s, def, src); return; }
    if (is_octetstring_tag(def.tag))      { encode_octetstring_xer (s, def, src); return; }
    if (is_hex_string_tag(def.tag))       { encode_hex_string      (s, def, src); return; }
    if (is_bmp_string_tag(def.tag))       { encode_bmp_string      (s, def, src); return; }
    if (is_universal_string_tag(def.tag)) { encode_universal_string(s, def, src); return; }
    if (is_primitive_string_tag(def.tag)) { encode_xer_string      (s, def, src); return; }
}

DecodeResult XerCodec::decode(IDecodeStream& src,
                               const TypeDescriptor& def,
                               void* dest) const
{
    auto& s = static_cast<XerDecodeStream&>(src);
    if (def.is_any)        return decode_any_xer        (s, def, dest);
    if (def.enum_spec)     return decode_enumerated(s, def, dest);
    if (def.sequence_spec) return decode_sequence   (s, def, dest);
    if (def.choice_spec)   return decode_choice     (s, def, dest);
    if (def.seq_of_spec)   return decode_seq_of     (s, def, dest);
    if (is_boolean_tag(def.tag))          return decode_boolean         (s, def, dest);
    if (is_integer_tag(def.tag))          return decode_integer         (s, def, dest);
    if (is_null_tag(def.tag))             return decode_null            (s, def, dest);
    if (is_real_tag(def.tag))             return decode_real            (s, def, dest);
    if (is_bitstring_tag(def.tag))        return decode_bitstring       (s, def, dest);
    if (is_oid_tag(def.tag))              return decode_oid             (s, def, dest);
    if (is_relative_oid_tag(def.tag))     return decode_relative_oid   (s, def, dest);
    if (is_utctime_tag(def.tag))          return decode_time_string<UtcTime>        (s, def, dest);
    if (is_gentime_tag(def.tag))          return decode_time_string<GeneralizedTime>(s, def, dest);
    if (is_octetstring_tag(def.tag))      return decode_octetstring_xer (s, def, dest);
    if (is_hex_string_tag(def.tag))       return decode_hex_string      (s, def, dest);
    if (is_bmp_string_tag(def.tag))       return decode_bmp_string      (s, def, dest);
    if (is_universal_string_tag(def.tag)) return decode_universal_string(s, def, dest);
    if (is_primitive_string_tag(def.tag)) return decode_xer_string      (s, def, dest);
    return decode_err(DecodeError(std::string("XerCodec: no spec for type ") + def.name));
}

// ---------------------------------------------------------------------------
// Tag predicates

bool XerCodec::is_boolean_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Boolean;
}
bool XerCodec::is_integer_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
}
bool XerCodec::is_null_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 5;
}
bool XerCodec::is_real_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 9;
}
bool XerCodec::is_bitstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 3;
}
bool XerCodec::is_oid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 6;
}
bool XerCodec::is_relative_oid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 13;
}
bool XerCodec::is_utctime_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 23;
}
bool XerCodec::is_gentime_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 24;
}
bool XerCodec::is_octetstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 4;
}
bool XerCodec::is_primitive_string_tag(const Tag& t) {
    if (t.cls != TagClass::Universal) return false;
    switch (t.number) {
    case 7: case 12: case 18: case 19: case 20:
    case 21: case 22: case 25: case 26: case 27: case 28: case 30:
        return true;
    default: return false;
    }
}
bool XerCodec::is_hex_string_tag(const Tag& t) {
    if (t.cls != TagClass::Universal) return false;
    switch (t.number) { case 20: case 21: case 25: case 27: return true; default: return false; }
}
bool XerCodec::is_bmp_string_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 30;
}
bool XerCodec::is_universal_string_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == 28;
}

// ---------------------------------------------------------------------------
// NULL

void XerCodec::encode_null(XerEncodeStream& s, const TypeDescriptor& def) const {
    s.os() << '<' << def.name << "></" << def.name << ">\n";
}

DecodeResult XerCodec::decode_null(XerDecodeStream& s,
                                    const TypeDescriptor& def,
                                    void* dest) const
{
    auto ti = xer_detail::consume_tag(s);
    if (ti.name != def.name || ti.closing)
        return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));
    if (!ti.self_closing) {
        auto close = xer_detail::consume_tag(s);
        if (!close.closing || close.name != def.name)
            return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));
    }
    (void)dest;
    return decode_ok();
}

// ---------------------------------------------------------------------------
// BOOLEAN

void XerCodec::encode_boolean(XerEncodeStream& s,
                               const TypeDescriptor& def,
                               const void* src) const
{
    bool v = static_cast<const Boolean*>(src)->value();
    s.os() << '<' << def.name << '>' << (v ? "<true/>" : "<false/>") << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_boolean(XerDecodeStream& s,
                                       const TypeDescriptor& def,
                                       void* dest) const
{
    if (auto r = xer_detail::consume_open_tag(s, def.name); !r) return r;
    auto inner = xer_detail::consume_tag(s);
    bool value;
    if (inner.name == "true"  && inner.self_closing) { value = true; }
    else if (inner.name == "false" && inner.self_closing) { value = false; }
    else return decode_err(DecodeError("XER BOOLEAN: expected <true/> or <false/>"));
    if (auto r = xer_detail::consume_close_tag(s, def.name); !r) return r;
    *static_cast<Boolean*>(dest) = Boolean{value};
    return decode_ok();
}

// ---------------------------------------------------------------------------
// UTCTime / GeneralizedTime

void XerCodec::encode_time_string(XerEncodeStream& s,
                                   const TypeDescriptor& def,
                                   const void* src) const
{
    encode_text_element(s, def, src);
}

// ---------------------------------------------------------------------------
// Generic primitive string

void XerCodec::encode_xer_string(XerEncodeStream& s,
                                  const TypeDescriptor& def,
                                  const void* src) const
{
    encode_text_element(s, def, src);
}

DecodeResult XerCodec::decode_xer_string(XerDecodeStream& s,
                                          const TypeDescriptor& def,
                                          void* dest) const
{
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        detail::asnstring_assign(dest, text);
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// Hex-byte string helpers + types

std::string XerCodec::format_hex_bytes(std::string_view sv) {
    std::string out;
    char hex[3];
    for (std::size_t i = 0; i < sv.size(); ++i) {
        if (i) out += ' ';
        std::snprintf(hex, sizeof(hex), "%02X", (uint8_t)sv[i]);
        out += hex;
    }
    return out;
}

std::string XerCodec::parse_hex_bytes(std::string_view sv) {
    std::string out;
    while (!sv.empty()) {
        while (!sv.empty() && std::isspace((unsigned char)sv[0])) sv.remove_prefix(1);
        if (sv.size() < 2) break;
        uint8_t b = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + 2, b, 16);
        if (ec != std::errc{}) break;
        out += (char)b;
        sv.remove_prefix(ptr - sv.data());
    }
    return out;
}

void XerCodec::encode_hex_string(XerEncodeStream& s,
                                  const TypeDescriptor& def,
                                  const void* src) const
{
    std::string_view sv = detail::asnstring_view(src);
    s.os() << '<' << def.name << '>' << format_hex_bytes(sv) << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_hex_string(XerDecodeStream& s,
                                          const TypeDescriptor& def,
                                          void* dest) const
{
    return decode_simple_text_element(s, def.name, [this, dest](std::string_view text) -> DecodeResult {
        detail::asnstring_assign(dest, parse_hex_bytes(text));
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// ANY — hex-encoded raw BER bytes (same format as asn1c's ANY_encode_xer)

void XerCodec::encode_any_xer(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
    const OctetString& v = *static_cast<const OctetString*>(src);
    auto bytes = v.bytes();
    std::string_view sv(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    s.os() << '<' << def.name << '>' << format_hex_bytes(sv) << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_any_xer(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const {
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        std::string bytes = parse_hex_bytes(text);
        *static_cast<OctetString*>(dest) = OctetString(
            std::vector<uint8_t>(bytes.begin(), bytes.end()));
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// OCTET STRING (Base64)

std::string XerCodec::base64_encode(std::span<const uint8_t> in) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < in.size(); i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in.size()) v |= (uint32_t)in[i+1] << 8;
        if (i + 2 < in.size()) v |= in[i+2];
        out += t[(v >> 18) & 0x3F];
        out += t[(v >> 12) & 0x3F];
        out += (i + 1 < in.size()) ? t[(v >> 6) & 0x3F] : '=';
        out += (i + 2 < in.size()) ? t[v & 0x3F]        : '=';
    }
    return out;
}

std::vector<uint8_t> XerCodec::base64_decode(std::string_view in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (char c : in) {
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((buf >> bits) & 0xFF); }
    }
    return out;
}

void XerCodec::encode_octetstring_xer(XerEncodeStream& s,
                                       const TypeDescriptor& def,
                                       const void* src) const
{
    const OctetString& v = *static_cast<const OctetString*>(src);
    auto& os = s.os();
    std::string b64 = base64_encode(v.bytes());
    os << '<' << def.name << '>';
    for (std::size_t i = 0; i < b64.size(); ) {
        if (i > 0) os << s.indent(1);
        std::size_t end = std::min(i + 76, b64.size());
        os << b64.substr(i, end - i);
        i = end;
        if (i < b64.size()) os << "\n";
    }
    os << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_octetstring_xer(XerDecodeStream& s,
                                               const TypeDescriptor& def,
                                               void* dest) const
{
    return decode_simple_text_element(s, def.name, [this, dest](std::string_view text) -> DecodeResult {
        *static_cast<OctetString*>(dest) = OctetString{base64_decode(text)};
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// BmpString (UTF-16BE) and UniversalString (UTF-32BE)

void XerCodec::encode_bmp_string(XerEncodeStream& s,
                                  const TypeDescriptor& def,
                                  const void* src) const
{
    encode_wide_string<2>(s, def, src);
}

DecodeResult XerCodec::decode_bmp_string(XerDecodeStream& s,
                                          const TypeDescriptor& def,
                                          void* dest) const
{
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        std::string out;
        std::size_t i = 0;
        while (i < text.size()) {
            uint32_t cp = utf8_decode_cp(text.data(), text.size(), i);
            out += (char)(uint8_t)(cp >> 8);
            out += (char)(uint8_t)(cp & 0xFF);
        }
        detail::asnstring_assign(dest, out);
        return decode_ok();
    });
}

void XerCodec::encode_universal_string(XerEncodeStream& s,
                                        const TypeDescriptor& def,
                                        const void* src) const
{
    encode_wide_string<4>(s, def, src);
}

DecodeResult XerCodec::decode_universal_string(XerDecodeStream& s,
                                                const TypeDescriptor& def,
                                                void* dest) const
{
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        std::string out;
        std::size_t i = 0;
        while (i < text.size()) {
            uint32_t cp = utf8_decode_cp(text.data(), text.size(), i);
            out += (char)(uint8_t)(cp >> 24);
            out += (char)(uint8_t)((cp >> 16) & 0xFF);
            out += (char)(uint8_t)((cp >> 8) & 0xFF);
            out += (char)(uint8_t)(cp & 0xFF);
        }
        detail::asnstring_assign(dest, out);
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// OID / RELATIVE-OID

void XerCodec::encode_oid(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
    encode_oid_impl<Oid>(s, def, src);
}
DecodeResult XerCodec::decode_oid(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const {
    return decode_oid_impl<Oid>(s, def, dest);
}
void XerCodec::encode_relative_oid(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
    encode_oid_impl<RelativeOid>(s, def, src);
}
DecodeResult XerCodec::decode_relative_oid(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const {
    return decode_oid_impl<RelativeOid>(s, def, dest);
}

// ---------------------------------------------------------------------------
// BIT STRING

void XerCodec::encode_bitstring(XerEncodeStream& s,
                                 const TypeDescriptor& def,
                                 const void* src) const
{
    const BitString& bs = *static_cast<const BitString*>(src);
    auto& os = s.os();
    os << '<' << def.name << ">\n";
    std::size_t total = bs.bit_count();
    auto bytes = bs.bytes();
    if (total == 0) {
        os << s.indent(1) << "\n";
    } else {
        for (std::size_t i = 0; i < total; ) {
            os << s.indent(1);
            std::size_t line_end = std::min(i + 64, total);
            for (; i < line_end; ++i) {
                int bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
                os << (char)('0' + bit);
            }
            os << "\n";
        }
    }
    os << s.indent() << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_bitstring(XerDecodeStream& s,
                                         const TypeDescriptor& def,
                                         void* dest) const
{
    if (auto r = xer_detail::consume_open_tag(s, def.name); !r) return r;
    s.skip_whitespace();

    std::string_view rem = s.remaining();
    std::size_t pos = 0;
    std::string bits;
    while (pos < rem.size() && rem[pos] != '<') {
        char c = rem[pos++];
        if (c == '0' || c == '1') bits += c;
        else if (!std::isspace((unsigned char)c))
            return decode_err(DecodeError("XER: invalid BIT STRING character"));
    }
    s.advance(pos);
    if (auto r = xer_detail::consume_close_tag(s, def.name); !r) return r;

    std::vector<uint8_t> bytes;
    uint8_t unused = 0;
    if (!bits.empty()) {
        std::size_t n = bits.size();
        bytes.resize((n + 7) / 8, 0);
        for (std::size_t i = 0; i < n; ++i)
            if (bits[i] == '1') bytes[i / 8] |= (uint8_t)(0x80 >> (i % 8));
        unused = (uint8_t)(bytes.size() * 8 - n);
    }
    *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
    return decode_ok();
}

// ---------------------------------------------------------------------------
// REAL

void XerCodec::encode_real(XerEncodeStream& s,
                            const TypeDescriptor& def,
                            const void* src) const
{
    double d = static_cast<const Real*>(src)->value();
    auto& os = s.os();
    os << '<' << def.name << '>';
    if (std::isnan(d)) {
        os << "<NOT-A-NUMBER/>";
    } else if (std::isinf(d)) {
        os << (d > 0 ? "<PLUS-INFINITY/>" : "<MINUS-INFINITY/>");
    } else if (d == 0.0) {
        os << '0';
    } else {
        int n = std::snprintf(nullptr, 0, "%.15f", d);
        std::string buf(n + 1, '\0');
        std::snprintf(buf.data(), n + 1, "%.15f", d);
        buf.resize(n);
        auto dot = buf.find('.');
        if (dot != std::string::npos) {
            std::size_t last = buf.size() - 1;
            while (last > dot + 1 && buf[last] == '0') --last;
            buf.resize(last + 1);
        }
        os << buf;
    }
    os << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_real(XerDecodeStream& s,
                                    const TypeDescriptor& def,
                                    void* dest) const
{
    if (auto r = xer_detail::consume_open_tag(s, def.name); !r) return r;
    s.skip_whitespace();

    double d;
    if (!s.remaining().empty() && s.remaining()[0] == '<') {
        auto inner = xer_detail::consume_tag(s);
        if      (inner.name == "PLUS-INFINITY")  d = std::numeric_limits<double>::infinity();
        else if (inner.name == "MINUS-INFINITY") d = -std::numeric_limits<double>::infinity();
        else if (inner.name == "NOT-A-NUMBER")   d = std::numeric_limits<double>::quiet_NaN();
        else return decode_err(DecodeError("XER: unknown REAL special value: " + inner.name));
        if (!inner.self_closing) {
            auto close_inner = xer_detail::consume_tag(s);
            if (!close_inner.closing || close_inner.name != inner.name)
                return decode_err(DecodeError("XER: malformed REAL special value"));
        }
    } else {
        auto text = xer_detail::read_text_content(s);
        text = xer_detail::trim(text);
        std::string buf(text);
        char* endp;
        d = std::strtod(buf.c_str(), &endp);
        if (endp != buf.c_str() + buf.size())
            return decode_err(DecodeError("XER: invalid REAL value: " + buf));
    }
    if (auto r = xer_detail::consume_close_tag(s, def.name); !r) return r;
    *static_cast<Real*>(dest) = Real{d};
    return decode_ok();
}

// ---------------------------------------------------------------------------
// INTEGER

void XerCodec::encode_integer(XerEncodeStream& s,
                               const TypeDescriptor& def,
                               const void* src) const
{
    int64_t v = *static_cast<const int64_t*>(src);
    s.os() << '<' << def.name << '>' << v << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_integer(XerDecodeStream& s,
                                       const TypeDescriptor& def,
                                       void* dest) const
{
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        text = xer_detail::trim(text);
        int64_t value = 0;
        auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (ec != std::errc{})
            return decode_err(DecodeError("XER: invalid INTEGER value: " + std::string(text)));
        *static_cast<int64_t*>(dest) = value;
        return decode_ok();
    });
}

// ---------------------------------------------------------------------------
// ENUMERATED

void XerCodec::encode_enumerated(XerEncodeStream& s,
                                  const TypeDescriptor& def,
                                  const void* src) const
{
    auto& os = s.os();
    long v = *static_cast<const long*>(src);
    const EnumSpec& spec = *def.enum_spec;
    const char* name = nullptr;
    int lo = 0, hi = spec.count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (spec.entries[mid].value == v) { name = spec.entries[mid].name; break; }
        if (spec.entries[mid].value < v) lo = mid + 1; else hi = mid - 1;
    }
    os << '<' << def.name << '>';
    if (name) os << '<' << name << "/>";
    else      os << v;
    os << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_enumerated(XerDecodeStream& s,
                                          const TypeDescriptor& def,
                                          void* dest) const
{
    auto outer = xer_detail::consume_tag(s);
    if (outer.name != def.name || outer.closing)
        return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));

    auto inner = xer_detail::consume_tag(s);
    if (inner.name.empty() || inner.closing)
        return decode_err(DecodeError("XER: expected enum value tag"));

    if (!inner.self_closing) {
        auto close = xer_detail::consume_tag(s);
        if (!close.closing || close.name != inner.name)
            return decode_err(DecodeError("XER: malformed enum value tag"));
    }
    auto close_outer = xer_detail::consume_tag(s);
    if (!close_outer.closing || close_outer.name != def.name)
        return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));

    const EnumSpec& spec = *def.enum_spec;
    for (int i = 0; i < spec.count; ++i) {
        if (inner.name == spec.entries[i].name) {
            *static_cast<long*>(dest) = spec.entries[i].value;
            return decode_ok();
        }
    }
    return decode_err(DecodeError("XER: unknown enum value: " + inner.name));
}

// ---------------------------------------------------------------------------
// SEQUENCE OF / SET OF

void XerCodec::encode_seq_of(XerEncodeStream& s,
                              const TypeDescriptor& def,
                              const void* src) const
{
    auto& os = s.os();
    const auto& spec = *def.seq_of_spec;
    std::size_t count = spec.count_fn(src);
    const TypeDescriptor& edef = *spec.element;
    if (count == 0) {
        os << '<' << def.name << "></" << def.name << ">\n";
    } else {
        os << '<' << def.name << ">\n";
        for (std::size_t i = 0; i < count; ++i) {
            const void* eptr = spec.get_const_fn(src, i);
            os << s.indent(1);
            XerEncodeStream es{os, s.depth() + 1};
            encode(es, edef, eptr);
        }
        os << s.indent() << "</" << def.name << ">\n";
    }
}

DecodeResult XerCodec::decode_seq_of(XerDecodeStream& s,
                                      const TypeDescriptor& def,
                                      void* dest) const
{
    {
        auto ti = xer_detail::consume_tag(s);
        if (ti.name != def.name || ti.closing || ti.self_closing)
            return decode_err(DecodeError(std::string("XER SEQUENCE OF: expected <") + def.name + ">"));
    }
    const auto& spec = *def.seq_of_spec;
    const TypeDescriptor& edef = *spec.element;
    std::size_t count = 0;
    for (;;) {
        auto ti = xer_detail::peek_tag(s);
        if (ti.closing && ti.name == def.name) { xer_detail::consume_tag(s); break; }
        if (ti.name.empty())
            return decode_err(DecodeError(std::string("XER SEQUENCE OF: unexpected end in <") + def.name + ">"));
        spec.resize_fn(dest, ++count);
        void* eptr = spec.get_fn(dest, count - 1);
        auto r = decode(s, edef, eptr);
        if (!r) return r;
    }
    return decode_ok();
}

// ---------------------------------------------------------------------------
// SEQUENCE

void XerCodec::encode_sequence(XerEncodeStream& s,
                                const TypeDescriptor& def,
                                const void* src) const
{
    auto& os = s.os();
    const auto& spec = *def.sequence_spec;
    os << '<' << def.name << ">\n";
    for (int i = 0; i < spec.count; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.type_descriptor) continue;
        if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
        const void* mptr = mbr.optional_ops.get_ptr
            ? mbr.optional_ops.get_ptr(const_cast<void*>(src))
            : static_cast<const char*>(src) + mbr.offset;
        TypeDescriptor mdef = *mbr.type_descriptor;
        mdef.name = mbr.name;
        os << s.indent(1);
        XerEncodeStream ms{os, s.depth() + 1};
        encode(ms, mdef, mptr);
    }
    os << s.indent() << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_sequence(XerDecodeStream& s,
                                        const TypeDescriptor& def,
                                        void* dest) const
{
    {
        auto ti = xer_detail::consume_tag(s);
        if (ti.name != def.name || ti.closing || ti.self_closing)
            return decode_err(DecodeError(std::string("XER SEQUENCE: expected <") + def.name + ">"));
    }

    const auto& spec = *def.sequence_spec;
    for (int i = 0; i < spec.count; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.type_descriptor) continue;
        if (mbr.optional) {
            bool present = (xer_detail::peek_tag(s).name == mbr.name);
            mbr.optional_ops.set_present(dest, present);
            if (!present) continue;
        }
        void* mptr = mbr.optional_ops.get_ptr
            ? mbr.optional_ops.get_ptr(dest)
            : static_cast<char*>(dest) + mbr.offset;
        TypeDescriptor mdef = *mbr.type_descriptor;
        mdef.name = mbr.name;
        auto r = decode(s, mdef, mptr);
        if (!r) return r;
    }

    {
        auto ti = xer_detail::consume_tag(s);
        if (ti.name != def.name || !ti.closing)
            return decode_err(DecodeError(std::string("XER SEQUENCE: expected </") + def.name + ">"));
    }
    return decode_ok();
}

// ---------------------------------------------------------------------------
// CHOICE

void XerCodec::encode_choice(XerEncodeStream& s,
                              const TypeDescriptor& def,
                              const void* src) const
{
    auto& os = s.os();
    const auto& spec = *def.choice_spec;
    int pr = *static_cast<const int*>(src);
    if (pr <= 0 || pr > spec.count) return;
    const auto& alt = spec.alternatives[pr - 1];
    if (!alt.type_descriptor) return;

    os << '<' << def.name << ">\n";
    os << s.indent(1);
    TypeDescriptor adef = *alt.type_descriptor;
    adef.name = alt.name;
    XerEncodeStream as{os, s.depth() + 1};
    encode(as, adef, static_cast<const char*>(src) + alt.offset);
    os << s.indent() << "</" << def.name << ">\n";
}

DecodeResult XerCodec::decode_choice(XerDecodeStream& s,
                                      const TypeDescriptor& def,
                                      void* dest) const
{
    if (auto r = xer_detail::consume_open_tag(s, def.name); !r) return r;

    {
        auto ti = xer_detail::peek_tag(s);
        const auto& spec = *def.choice_spec;
        bool found = false;
        for (int i = 0; i < spec.count; ++i) {
            const auto& alt = spec.alternatives[i];
            if (ti.name != alt.name) continue;
            if (!alt.type_descriptor)
                return decode_err(DecodeError(std::string("XER CHOICE: no descriptor for ") + alt.name));
            TypeDescriptor adef = *alt.type_descriptor;
            adef.name = alt.name;
            void* mptr = static_cast<char*>(dest) + alt.offset;
            auto r = decode(s, adef, mptr);
            if (!r) return r;
            *static_cast<int*>(dest) = i + 1;
            found = true;
            break;
        }
        if (!found)
            return decode_err(DecodeError(std::string("XER CHOICE: unknown alternative <") + std::string(ti.name) + ">"));
    }
    if (auto r = xer_detail::consume_close_tag(s, def.name); !r) return r;
    return decode_ok();
}

} // namespace asn1
