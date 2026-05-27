#include <cassert>
#include <asn1cpp/codec/XerCodec.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>

namespace asn1 {

namespace {

// ---------------------------------------------------------------------------
// Static helpers (not needed in header)

static std::string format_hex_bytes(std::string_view sv) {
    std::string out;
    char hex[3];
    for (std::size_t i = 0; i < sv.size(); ++i) {
        if (i) out += ' ';
        std::snprintf(hex, sizeof(hex), "%02X", (uint8_t)sv[i]);
        out += hex;
    }
    return out;
}

static std::string parse_hex_bytes(std::string_view sv) {
    std::string out;
    while (!sv.empty()) {
        while (!sv.empty() && xer_detail::xer_ws[(unsigned char)sv[0]]) sv.remove_prefix(1);
        if (sv.size() < 2) break;
        uint8_t b = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + 2, b, 16);
        if (ec != std::errc{}) break;
        out += (char)b;
        sv.remove_prefix(ptr - sv.data());
    }
    return out;
}

static std::string base64_encode(std::span<const uint8_t> in) {
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

static std::string base64_decode(std::string_view in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out;
    int buf = 0, bits = 0;
    for (char c : in) {
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<char>((buf >> bits) & 0xFF)); }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Handler classes

struct ErrorXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream&,
                const TypeDescriptor& def, const Asn1Object*) const override {
        assert(false && "XerCodec: unreachable dispatch table entry");
        (void)def;
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream&,
                        const TypeDescriptor& def, Asn1Object*) const override {
        assert(false && "XerCodec: unreachable dispatch table entry");
        return decode_err(DecodeError(std::string("XerCodec: unsupported: ") + def.name));
    }
};

struct NullXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object*) const override {
        s.os() << '<' << def.name << "></" << def.name << ">\n";
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object*) const override {
        auto ti = xer_detail::consume_tag(s);
        if (ti.name != def.name || ti.closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));
        if (!ti.self_closing) {
            auto close = xer_detail::consume_tag(s);
            if (!close.closing || close.name != def.name)
                return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));
        }
        return decode_ok();
    }
};

struct BooleanXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        bool v = static_cast<const Boolean*>(src)->value();
        s.os() << '<' << def.name << '>' << (v ? "<true/>" : "<false/>") << "</" << def.name << ">\n";
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
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
};

struct IntegerXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        if (def.constraints.int_kind == Constraints::INT_U64) {
            uint64_t v = static_cast<const UInteger*>(src)->value();
            s.os() << '<' << def.name << '>' << v << "</" << def.name << ">\n";
        } else {
            int64_t v = static_cast<const Integer*>(src)->value();
            s.os() << '<' << def.name << '>' << v << "</" << def.name << ">\n";
        }
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest, &def](std::string_view text) -> DecodeResult {
                text = xer_detail::trim(text);
                if (def.constraints.int_kind == Constraints::INT_U64) {
                    uint64_t value = 0;
                    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                    if (ec != std::errc{})
                        return decode_err(DecodeError("XER: invalid INTEGER value: " + std::string(text)));
                    static_cast<UInteger*>(dest)->set(value);
                } else {
                    int64_t value = 0;
                    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                    if (ec != std::errc{})
                        return decode_err(DecodeError("XER: invalid INTEGER value: " + std::string(text)));
                    static_cast<Integer*>(dest)->set(value);
                }
                return decode_ok();
            });
    }
};

struct RealXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
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
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
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
};

struct BitStringXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
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
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (auto r = xer_detail::consume_open_tag(s, def.name); !r) return r;
        s.skip_whitespace();
        std::string_view rem = s.remaining();
        std::size_t pos = 0;
        std::string bits;
        while (pos < rem.size() && rem[pos] != '<') {
            char c = rem[pos++];
            if (c == '0' || c == '1') bits += c;
            else if (!xer_detail::xer_ws[(unsigned char)c])
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
};

struct OctetStringXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
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
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                auto dec = base64_decode(text);
                *static_cast<OctetString*>(dest) = OctetString{
                    reinterpret_cast<const uint8_t*>(dec.data()), dec.size()};
                return decode_ok();
            });
    }
};

struct OidXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_oid_impl<Oid>(s, def, src);
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_oid_impl<Oid>(s, def, dest);
    }
};

struct RelOidXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_oid_impl<RelativeOid>(s, def, src);
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_oid_impl<RelativeOid>(s, def, dest);
    }
};

struct UtcTimeXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_text_element(s, def,
            static_cast<const AsnStringBase*>(src)->str());
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_time_string<UtcTime>(s, def, dest);
    }
};

struct GenTimeXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_text_element(s, def,
            static_cast<const AsnStringBase*>(src)->str());
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_time_string<GeneralizedTime>(s, def, dest);
    }
};

struct XerStringHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_text_element(s, def,
            static_cast<const AsnStringBase*>(src)->str());
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                static_cast<AsnStringBase*>(dest)->str().assign(text.data(), text.size());
                return decode_ok();
            });
    }
};

struct HexStringXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& sv = static_cast<const AsnStringBase*>(src)->str();
        s.os() << '<' << def.name << '>' << format_hex_bytes(sv) << "</" << def.name << ">\n";
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                static_cast<AsnStringBase*>(dest)->str() = parse_hex_bytes(text);
                return decode_ok();
            });
    }
};

struct BmpStringXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_wide_string<2>(s, def,
            static_cast<const AsnStringBase*>(src)->str());
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                std::string out;
                std::size_t i = 0;
                while (i < text.size()) {
                    uint32_t cp = xer_detail::utf8_decode_cp(text.data(), text.size(), i);
                    out += (char)(uint8_t)(cp >> 8);
                    out += (char)(uint8_t)(cp & 0xFF);
                }
                static_cast<AsnStringBase*>(dest)->str().assign(out);
                return decode_ok();
            });
    }
};

struct UniversalStringXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        xer_detail::encode_wide_string<4>(s, def,
            static_cast<const AsnStringBase*>(src)->str());
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                std::string out;
                std::size_t i = 0;
                while (i < text.size()) {
                    uint32_t cp = xer_detail::utf8_decode_cp(text.data(), text.size(), i);
                    out += (char)(uint8_t)(cp >> 24);
                    out += (char)(uint8_t)((cp >> 16) & 0xFF);
                    out += (char)(uint8_t)((cp >> 8) & 0xFF);
                    out += (char)(uint8_t)(cp & 0xFF);
                }
                static_cast<AsnStringBase*>(dest)->str().assign(out);
                return decode_ok();
            });
    }
};

struct AnyXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        std::string_view sv(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        s.os() << '<' << def.name << '>' << format_hex_bytes(sv) << "</" << def.name << ">\n";
    }
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        return xer_detail::decode_simple_text_element(s, def.name,
            [dest](std::string_view text) -> DecodeResult {
                std::string bytes = parse_hex_bytes(text);
                *static_cast<OctetString*>(dest) = OctetString(
                    std::vector<uint8_t>(bytes.begin(), bytes.end()));
                return decode_ok();
            });
    }
};

struct EnumeratedXerHandler final : IXerTypeHandler {
    void encode(const XerCodec&, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        long v = static_cast<const EnumValue*>(src)->value();
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
    DecodeResult decode(const XerCodec&, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
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
                static_cast<EnumValue*>(dest)->set(spec.entries[i].value);
                return decode_ok();
            }
        }
        return decode_err(DecodeError("XER: unknown enum value: " + inner.name));
    }
};

struct SeqOfXerHandler final : IXerTypeHandler {
    void encode(const XerCodec& codec, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec  = *def.seq_of_spec;
        const auto& seq   = *static_cast<const SeqOfBase*>(src);
        std::size_t count = seq.count();
        const TypeDescriptor& edef = *spec.element;
        if (count == 0) {
            os << '<' << def.name << "></" << def.name << ">\n";
        } else {
            os << '<' << def.name << '>';
            for (std::size_t i = 0; i < count; ++i) {
                const Asn1Object* eptr = seq.get_const(i);
                XerEncodeStream es{os, s.depth() + 1};
                if (!edef.choice_spec) {
                    if (i == 0) os << '\n';
                    os << s.indent(1);
                }
                codec.encode(es, edef, eptr);
            }
            os << s.indent() << "</" << def.name << ">\n";
        }
    }
    DecodeResult decode(const XerCodec& codec, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        {
            auto ti = xer_detail::consume_tag(s);
            if (ti.name != def.name || ti.closing || ti.self_closing)
                return decode_err(DecodeError(std::string("XER SEQUENCE OF: expected <") + def.name + ">"));
        }
        const auto& spec = *def.seq_of_spec;
        const TypeDescriptor& edef = *spec.element;
        SeqOfBase& seq = *static_cast<SeqOfBase*>(dest);
        std::size_t count = 0;
        for (;;) {
            auto ti = xer_detail::peek_tag(s);
            if (ti.closing && ti.name == def.name) { xer_detail::consume_tag(s); break; }
            if (ti.name.empty())
                return decode_err(DecodeError(
                    std::string("XER SEQUENCE OF: unexpected end in <") + def.name + ">"));
            seq.resize(++count);
            Asn1Object* eptr = seq.get_mut(count - 1);
            auto r = codec.decode(s, edef, eptr);
            if (!r) return r;
        }
        return decode_ok();
    }
};

struct SequenceXerHandler final : IXerTypeHandler {
    void encode(const XerCodec& codec, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.sequence_spec;
        bool any_present = false;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            any_present = true;
            break;
        }
        if (!any_present) {
            os << '<' << def.name << "></" << def.name << ">\n";
            return;
        }
        os << '<' << def.name << ">\n";
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            if (mdef.choice_spec) {
                os << s.indent(1) << '<' << mbr.name << '>';
                XerEncodeStream ms{os, s.depth() + 1};
                codec.encode(ms, mdef, mptr);
                os << s.indent(1) << "</" << mbr.name << ">\n";
            } else {
                os << s.indent(1);
                XerEncodeStream ms{os, s.depth() + 1};
                codec.encode(ms, mdef, mptr);
            }
        }
        os << s.indent() << "</" << def.name << ">\n";
    }
    DecodeResult decode(const XerCodec& codec, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        {
            auto ti = xer_detail::consume_tag(s);
            if (ti.name != def.name || ti.closing || ti.self_closing)
                return decode_err(DecodeError(
                    std::string("XER SEQUENCE: expected <") + def.name + ">"));
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
            Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            if (mdef.choice_spec) {
                if (auto r = xer_detail::consume_open_tag(s, mbr.name); !r) return r;
                auto r = codec.decode(s, mdef, mptr);
                if (!r) return r;
                if (auto r2 = xer_detail::consume_close_tag(s, mbr.name); !r2) return r2;
            } else {
                auto r = codec.decode(s, mdef, mptr);
                if (!r) return r;
            }
        }
        {
            auto ti = xer_detail::consume_tag(s);
            if (ti.name != def.name || !ti.closing)
                return decode_err(DecodeError(
                    std::string("XER SEQUENCE: expected </") + def.name + ">"));
        }
        return decode_ok();
    }
};

struct ChoiceXerHandler final : IXerTypeHandler {
    void encode(const XerCodec& codec, XerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = static_cast<const ChoiceInterface*>(src);
        int pr = ch->_present;
        if (pr <= 0 || pr > spec.count) return;
        const auto& alt = spec.alternatives[pr - 1];
        if (!alt.type_descriptor) return;
        TypeDescriptor adef = *alt.type_descriptor;
        adef.name = alt.name;
        const Asn1Object* mptr = alt.get_const_fn(ch);
        if (adef.choice_spec) {
            os << '\n' << s.indent(1) << '<' << alt.name << '>';
            XerEncodeStream as{os, s.depth() + 1};
            codec.encode(as, adef, mptr);
            os << s.indent(1) << "</" << alt.name << ">\n";
        } else {
            os << '\n' << s.indent(1);
            XerEncodeStream as{os, s.depth() + 1};
            codec.encode(as, adef, mptr);
        }
    }
    DecodeResult decode(const XerCodec& codec, XerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto ti = xer_detail::peek_tag(s);
        const auto& spec = *def.choice_spec;
        ChoiceInterface* ch = static_cast<ChoiceInterface*>(dest);
        for (int i = 0; i < spec.count; ++i) {
            const auto& alt = spec.alternatives[i];
            if (ti.name != alt.name) continue;
            if (!alt.type_descriptor)
                return decode_err(DecodeError(
                    std::string("XER CHOICE: no descriptor for ") + alt.name));
            TypeDescriptor adef = *alt.type_descriptor;
            adef.name = alt.name;
            if (ch->_present != i + 1) {
                ch->emplace_alt(alt);
            }
            Asn1Object* mptr = alt.get_mut_fn(ch);
            if (adef.choice_spec) {
                if (auto r = xer_detail::consume_open_tag(s, alt.name); !r) return r;
                auto r = codec.decode(s, adef, mptr);
                if (!r) return r;
                if (auto r2 = xer_detail::consume_close_tag(s, alt.name); !r2) return r2;
            } else {
                auto r = codec.decode(s, adef, mptr);
                if (!r) return r;
            }
            ch->_present = i + 1;
            return decode_ok();
        }
        return decode_err(DecodeError(
            std::string("XER CHOICE: unknown alternative <") + std::string(ti.name) + ">"));
    }
};

// ---------------------------------------------------------------------------
// Singletons

static const ErrorXerHandler           s_error;
static const NullXerHandler            s_null;
static const BooleanXerHandler         s_boolean;
static const IntegerXerHandler         s_integer;
static const RealXerHandler            s_real;
static const BitStringXerHandler       s_bitstring;
static const OctetStringXerHandler     s_octetstring;
static const OidXerHandler             s_oid;
static const RelOidXerHandler          s_reloid;
static const UtcTimeXerHandler         s_utctime;
static const GenTimeXerHandler         s_gentime;
static const XerStringHandler          s_xer_string;
static const HexStringXerHandler       s_hex_string;
static const BmpStringXerHandler       s_bmp_string;
static const UniversalStringXerHandler s_universal_string;
static const AnyXerHandler             s_any;
static const EnumeratedXerHandler      s_enumerated;
static const SeqOfXerHandler           s_seqof;
static const SequenceXerHandler        s_sequence;
static const ChoiceXerHandler          s_choice;

} // anonymous namespace

// ---------------------------------------------------------------------------
// Dispatch tables

const IXerTypeHandler* const XerCodec::comp_dispatch_[6] = {
    &s_error,      // [0] Primitive — routed to prim_dispatch_, never lands here
    &s_any,        // [1] Any
    &s_enumerated, // [2] Enumerated
    &s_sequence,   // [3] Sequence / SET
    &s_choice,     // [4] Choice
    &s_seqof,      // [5] SeqOf / SET OF
};

const IXerTypeHandler* const XerCodec::prim_dispatch_[32] = {
    &s_error,          // [ 0] EndOfContents
    &s_boolean,        // [ 1] Boolean
    &s_integer,        // [ 2] Integer
    &s_bitstring,      // [ 3] BitString
    &s_octetstring,    // [ 4] OctetString (base64)
    &s_null,           // [ 5] Null
    &s_oid,            // [ 6] OID
    &s_xer_string,     // [ 7] ObjectDescriptor
    &s_error,          // [ 8] External
    &s_real,           // [ 9] Real
    &s_error,          // [10] Enumerated   — TypeKind::Enumerated → comp_dispatch_
    &s_error,          // [11] EmbeddedPdv
    &s_xer_string,     // [12] Utf8String
    &s_reloid,         // [13] RelativeOid
    &s_error,          // [14] (unassigned)
    &s_error,          // [15] (unassigned)
    &s_error,          // [16] Sequence     — TypeKind::Sequence → comp_dispatch_
    &s_error,          // [17] Set          — TypeKind::Sequence → comp_dispatch_
    &s_xer_string,     // [18] NumericString
    &s_xer_string,     // [19] PrintableString
    &s_hex_string,     // [20] T61String
    &s_hex_string,     // [21] VideotexString
    &s_xer_string,     // [22] Ia5String
    &s_utctime,        // [23] UtcTime
    &s_gentime,        // [24] GeneralizedTime
    &s_hex_string,     // [25] GraphicString
    &s_xer_string,     // [26] VisibleString
    &s_hex_string,     // [27] GeneralString
    &s_universal_string,// [28] UniversalString
    &s_error,          // [29] CharacterString
    &s_bmp_string,     // [30] BmpString
    &s_error,          // [31] LongForm
};

// ---------------------------------------------------------------------------
// XerCodec public entry points

void XerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const Asn1Object* src) const
{
    auto& s = static_cast<XerEncodeStream&>(dst);
    if (def.kind == TypeKind::Primitive)
        prim_dispatch_[def.tag.number]->encode(*this, s, def, src);
    else
        comp_dispatch_[(int)def.kind]->encode(*this, s, def, src);
}

DecodeResult XerCodec::decode(IDecodeStream& src,
                               const TypeDescriptor& def,
                               Asn1Object* dest) const
{
    auto& s = static_cast<XerDecodeStream&>(src);
    if (def.kind == TypeKind::Primitive)
        return prim_dispatch_[def.tag.number]->decode(*this, s, def, dest);
    return comp_dispatch_[(int)def.kind]->decode(*this, s, def, dest);
}

} // namespace asn1
