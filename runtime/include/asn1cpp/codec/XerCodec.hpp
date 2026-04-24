#pragma once
#include <string>
#include <string_view>
#include <ostream>
#include <istream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <limits>
#include "ICodec.hpp"
#include "../Tag.hpp"
#include "../types/Real.hpp"
#include "../types/BitString.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// XER stream wrappers

class XerEncodeStream : public IEncodeStream {
    std::ostream& os_;
    int depth_{0};
public:
    explicit XerEncodeStream(std::ostream& os) : os_(os) {}
    explicit XerEncodeStream(std::ostream& os, int depth) : os_(os), depth_(depth) {}
    std::ostream& os() { return os_; }
    int depth() const { return depth_; }
};

class XerDecodeStream : public IDecodeStream {
    std::string buf_;
    std::size_t pos_{0};
public:
    explicit XerDecodeStream(std::string text) : buf_(std::move(text)) {}
    bool at_end() const override { return pos_ >= buf_.size(); }
    std::string_view remaining() const { return std::string_view(buf_).substr(pos_); }
    void advance(std::size_t n) { pos_ += n; }
};

// ---------------------------------------------------------------------------
// Simple XER helpers

namespace xer_detail {

// Skip whitespace in sv from pos.
inline std::size_t skip_ws(std::string_view sv, std::size_t pos) {
    while (pos < sv.size() && std::isspace((unsigned char)sv[pos])) ++pos;
    return pos;
}

// Consume expected literal; return new pos or npos on mismatch.
inline std::size_t expect(std::string_view sv, std::size_t pos, std::string_view tok) {
    pos = skip_ws(sv, pos);
    if (sv.substr(pos, tok.size()) != tok) return std::string_view::npos;
    return pos + tok.size();
}

// Parse <tag> or </tag> or <tag/>.  Returns tag name and whether it's closing/self-closing.
struct TagInfo { std::string name; bool closing; bool self_closing; };
inline TagInfo parse_tag(std::string_view sv, std::size_t& pos) {
    pos = skip_ws(sv, pos);
    if (pos >= sv.size() || sv[pos] != '<') return {"", false, false};
    ++pos;
    bool closing = pos < sv.size() && sv[pos] == '/';
    if (closing) ++pos;
    std::size_t name_start = pos;
    while (pos < sv.size() && sv[pos] != '>' && sv[pos] != '/' && !std::isspace((unsigned char)sv[pos]))
        ++pos;
    std::string name(sv.substr(name_start, pos - name_start));
    pos = skip_ws(sv, pos);
    bool self_closing = pos < sv.size() && sv[pos] == '/';
    if (self_closing) ++pos;
    if (pos < sv.size() && sv[pos] == '>') ++pos;
    return {name, closing, self_closing};
}

} // namespace xer_detail

// ---------------------------------------------------------------------------
// XerCodec

class XerCodec : public ICodec {
public:
    static XerCodec& instance() {
        static XerCodec inst;
        return inst;
    }

    const char* name() const override { return "XER"; }

    // ------------------------------------------------------------------
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override
    {
        auto& s = static_cast<XerEncodeStream&>(dst);
        if (def.enum_spec)     { encode_enumerated(s, def, src); return; }
        if (def.sequence_spec) { encode_sequence   (s, def, src); return; }
        if (def.choice_spec)   { encode_choice     (s, def, src); return; }
        if (is_integer_tag(def.tag)) { encode_integer(s, def, src); return; }
        if (is_null_tag(def.tag))    { encode_null   (s, def);     return; }
        if (is_real_tag(def.tag))      { encode_real     (s, def, src); return; }
        if (is_bitstring_tag(def.tag)) { encode_bitstring(s, def, src); return; }
    }

    // ------------------------------------------------------------------
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override
    {
        auto& s = static_cast<XerDecodeStream&>(src);
        if (def.enum_spec)     return decode_enumerated(s, def, dest);
        if (def.sequence_spec) return decode_sequence   (s, def, dest);
        if (def.choice_spec)   return decode_choice     (s, def, dest);
        if (is_integer_tag(def.tag)) return decode_integer(s, def, dest);
        if (is_null_tag(def.tag))    return decode_null   (s, def, dest);
        if (is_real_tag(def.tag))      return decode_real     (s, def, dest);
        if (is_bitstring_tag(def.tag)) return decode_bitstring(s, def, dest);
        return decode_err(DecodeError(std::string("XerCodec: no spec for type ") + def.name));
    }

private:
    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }
    static bool is_null_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == 5;
    }
    static bool is_real_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == 9;
    }
    static bool is_bitstring_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == 3;
    }

    // ---- NULL ----------------------------------------------------------

    void encode_null(XerEncodeStream& s, const TypeDescriptor& def) const {
        s.os() << '<' << def.name << "></" << def.name << ">\n";
    }

    DecodeResult decode_null(XerDecodeStream& s,
                             const TypeDescriptor& def,
                             void* dest) const
    {
        using namespace xer_detail;
        std::string_view rem = s.remaining();
        std::size_t pos = 0;
        auto ti = parse_tag(rem, pos);
        if (ti.name != def.name || ti.closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));
        if (!ti.self_closing) {
            auto close = parse_tag(rem, pos);
            if (!close.closing || close.name != def.name)
                return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));
        }
        s.advance(pos);
        (void)dest;
        return decode_ok();
    }

    // ---- REAL ----------------------------------------------------------

    // ---- BIT STRING ----------------------------------------------------
    // XER: <name>\n{indent*2}{bits}\n{indent}</name>\n
    // Empty BIT STRING: content line is blank (just the indent + newline).

    void encode_bitstring(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
        const BitString& bs = *static_cast<const BitString*>(src);
        auto& os = s.os();
        int depth = s.depth();
        std::string content_indent(4 * (depth + 1), ' ');
        std::string close_indent(4 * depth, ' ');
        os << '<' << def.name << ">\n";
        os << content_indent;
        std::size_t total = bs.bit_count();
        auto bytes = bs.bytes();
        for (std::size_t i = 0; i < total; ++i) {
            int bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
            os << (char)('0' + bit);
        }
        os << "\n";
        os << close_indent << "</" << def.name << ">\n";
    }

    DecodeResult decode_bitstring(XerDecodeStream& s,
                                  const TypeDescriptor& def,
                                  void* dest) const
    {
        using namespace xer_detail;
        std::string_view rem = s.remaining();
        std::size_t pos = 0;

        auto open = parse_tag(rem, pos);
        if (open.name != def.name || open.closing || open.self_closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));

        // Collect bit characters, skipping whitespace
        pos = skip_ws(rem, pos);
        std::string bits;
        while (pos < rem.size() && rem[pos] != '<') {
            char c = rem[pos++];
            if (c == '0' || c == '1') bits += c;
            else if (!std::isspace((unsigned char)c))
                return decode_err(DecodeError("XER: invalid BIT STRING character"));
        }

        auto close = parse_tag(rem, pos);
        if (!close.closing || close.name != def.name)
            return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));

        s.advance(pos);

        // Pack bits into bytes
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

    void encode_real(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
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
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.15f", d);
            // Strip trailing zeros; keep at least one decimal place (match asn1c behaviour).
            char* dot = std::strchr(buf, '.');
            if (dot) {
                char* p = buf + std::strlen(buf) - 1;
                while (p > dot + 1 && *p == '0') --p;
                *(p + 1) = '\0';
            }
            os << buf;
        }
        os << "</" << def.name << ">\n";
    }

    DecodeResult decode_real(XerDecodeStream& s,
                             const TypeDescriptor& def,
                             void* dest) const
    {
        using namespace xer_detail;
        std::string_view rem = s.remaining();
        std::size_t pos = 0;

        auto open = parse_tag(rem, pos);
        if (open.name != def.name || open.closing || open.self_closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));

        pos = skip_ws(rem, pos);
        double d;
        if (pos < rem.size() && rem[pos] == '<') {
            auto inner = parse_tag(rem, pos);
            if      (inner.name == "PLUS-INFINITY")  d = std::numeric_limits<double>::infinity();
            else if (inner.name == "MINUS-INFINITY") d = -std::numeric_limits<double>::infinity();
            else if (inner.name == "NOT-A-NUMBER")   d = std::numeric_limits<double>::quiet_NaN();
            else return decode_err(DecodeError("XER: unknown REAL special value: " + inner.name));
            if (!inner.self_closing) {
                auto close_inner = parse_tag(rem, pos);
                if (!close_inner.closing || close_inner.name != inner.name)
                    return decode_err(DecodeError("XER: malformed REAL special value"));
            }
        } else {
            std::size_t text_start = pos;
            while (pos < rem.size() && rem[pos] != '<') ++pos;
            std::string_view text = rem.substr(text_start, pos - text_start);
            while (!text.empty() && std::isspace((unsigned char)text.front())) text.remove_prefix(1);
            while (!text.empty() && std::isspace((unsigned char)text.back()))  text.remove_suffix(1);
            char buf[64];
            if (text.size() >= sizeof(buf))
                return decode_err(DecodeError("XER: REAL value too long"));
            std::copy(text.begin(), text.end(), buf);
            buf[text.size()] = '\0';
            char* endp;
            d = std::strtod(buf, &endp);
            if (endp != buf + text.size())
                return decode_err(DecodeError("XER: invalid REAL value: " + std::string(text)));
        }

        auto close = parse_tag(rem, pos);
        if (!close.closing || close.name != def.name)
            return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));

        s.advance(pos);
        *static_cast<Real*>(dest) = Real{d};
        return decode_ok();
    }

    // ---- INTEGER -------------------------------------------------------

    void encode_integer(XerEncodeStream& s,
                        const TypeDescriptor& def,
                        const void* src) const
    {
        int64_t v = *static_cast<const int64_t*>(src);
        s.os() << '<' << def.name << '>' << v << "</" << def.name << ">\n";
    }

    DecodeResult decode_integer(XerDecodeStream& s,
                                const TypeDescriptor& def,
                                void* dest) const
    {
        using namespace xer_detail;
        std::string_view rem = s.remaining();
        std::size_t pos = 0;

        // Expect <TypeName>
        auto outer = parse_tag(rem, pos);
        if (outer.name != def.name || outer.closing || outer.self_closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));

        // Read text content up to '<'
        pos = skip_ws(rem, pos);
        std::size_t text_start = pos;
        while (pos < rem.size() && rem[pos] != '<') ++pos;
        std::string_view text = rem.substr(text_start, pos - text_start);

        // Parse decimal integer
        // Trim whitespace
        while (!text.empty() && std::isspace((unsigned char)text.front())) text.remove_prefix(1);
        while (!text.empty() && std::isspace((unsigned char)text.back()))  text.remove_suffix(1);
        int64_t value = 0;
        auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (ec != std::errc{})
            return decode_err(DecodeError("XER: invalid INTEGER value: " + std::string(text)));

        // Expect </TypeName>
        auto close = parse_tag(rem, pos);
        if (!close.closing || close.name != def.name)
            return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));

        s.advance(pos);
        *static_cast<int64_t*>(dest) = value;
        return decode_ok();
    }

    // ---- ENUMERATED ----------------------------------------------------

    void encode_enumerated(XerEncodeStream& s,
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

    DecodeResult decode_enumerated(XerDecodeStream& s,
                                   const TypeDescriptor& def,
                                   void* dest) const
    {
        using namespace xer_detail;
        std::string_view rem = s.remaining();
        std::size_t pos = 0;

        // Expect <TypeName>
        auto outer = parse_tag(rem, pos);
        if (outer.name != def.name || outer.closing)
            return decode_err(DecodeError(std::string("XER: expected <") + def.name + ">"));

        pos = skip_ws(rem, pos);
        // Expect <valueName/>
        auto inner = parse_tag(rem, pos);
        if (inner.name.empty() || inner.closing)
            return decode_err(DecodeError("XER: expected enum value tag"));

        // Expect </TypeName>
        if (!inner.self_closing) {
            auto close = parse_tag(rem, pos);
            if (!close.closing || close.name != inner.name)
                return decode_err(DecodeError("XER: malformed enum value tag"));
        }
        auto close_outer = parse_tag(rem, pos);
        if (!close_outer.closing || close_outer.name != def.name)
            return decode_err(DecodeError(std::string("XER: expected </") + def.name + ">"));

        s.advance(pos);

        // Look up name in enum spec
        const EnumSpec& spec = *def.enum_spec;
        for (int i = 0; i < spec.count; ++i) {
            if (inner.name == spec.entries[i].name) {
                *static_cast<long*>(dest) = spec.entries[i].value;
                return decode_ok();
            }
        }
        return decode_err(DecodeError("XER: unknown enum value: " + inner.name));
    }

    // ---- SEQUENCE ---------------------------------------------------------
    //
    // XER: <TypeName>\n  <member1>value</member1>\n ... </TypeName>\n
    // Each member is encoded/decoded using its type_descriptor with name
    // overridden to the member name so the XML element matches.
    // Optional members: checked via the has_value bool at the start of
    // std::optional<T> (implementation-defined layout, but portable in practice
    // for trivially-copyable T on all supported compilers).

    void encode_sequence(XerEncodeStream& s,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        auto& os = s.os();
        int depth = s.depth();
        std::string member_indent(4 * (depth + 1), ' ');
        std::string close_indent(4 * depth, ' ');
        const auto& spec = *def.sequence_spec;
        os << '<' << def.name << ">\n";
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member encode
            const void* mptr = static_cast<const char*>(src) + mbr.offset;
            TypeDescriptor mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            mdef.name = mbr.name;
            os << member_indent;
            XerEncodeStream ms{os, depth + 1};
            encode(ms, mdef, mptr);
        }
        os << close_indent << "</" << def.name << ">\n";
    }

    DecodeResult decode_sequence(XerDecodeStream& s,
                                 const TypeDescriptor& def,
                                 void* dest) const
    {
        using namespace xer_detail;
        // Consume <TypeName>
        {
            auto rem = s.remaining();
            std::size_t pos = 0;
            auto ti = parse_tag(rem, pos);
            if (ti.name != def.name || ti.closing || ti.self_closing)
                return decode_err(DecodeError(std::string("XER SEQUENCE: expected <") + def.name + ">"));
            s.advance(pos);
        }

        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member decode
            void* mptr = static_cast<char*>(dest) + mbr.offset;
            TypeDescriptor mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            mdef.name = mbr.name;
            auto r = decode(s, mdef, mptr);
            if (!r) return r;
        }

        // Consume </TypeName>
        {
            auto rem = s.remaining();
            std::size_t pos = 0;
            auto ti = parse_tag(rem, pos);
            if (ti.name != def.name || !ti.closing)
                return decode_err(DecodeError(std::string("XER SEQUENCE: expected </") + def.name + ">"));
            s.advance(pos);
        }
        return decode_ok();
    }

    // ---- CHOICE (stub) -------------------------------------------------

    void encode_choice(XerEncodeStream& s,
                       const TypeDescriptor& def,
                       const void* src) const
    {
        (void)s; (void)def; (void)src;
    }

    DecodeResult decode_choice(XerDecodeStream& s,
                               const TypeDescriptor& def,
                               void* dest) const
    {
        (void)s; (void)def; (void)dest;
        return decode_err(DecodeError("XerCodec: CHOICE decode not yet implemented"));
    }
};

} // namespace asn1
