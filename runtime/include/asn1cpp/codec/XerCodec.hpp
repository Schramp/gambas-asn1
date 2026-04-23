#pragma once
#include <string>
#include <string_view>
#include <ostream>
#include <istream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <charconv>
#include "ICodec.hpp"
#include "../Tag.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// XER stream wrappers

class XerEncodeStream : public IEncodeStream {
    std::ostream& os_;
public:
    explicit XerEncodeStream(std::ostream& os) : os_(os) {}
    std::ostream& os() { return os_; }
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
        if (def.enum_spec)     { encode_enumerated(s.os(), def, src); return; }
        if (def.sequence_spec) { encode_sequence   (s.os(), def, src); return; }
        if (def.choice_spec)   { encode_choice     (s.os(), def, src); return; }
        if (is_integer_tag(def.tag)) { encode_integer(s.os(), def, src); return; }
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
        return decode_err(DecodeError(std::string("XerCodec: no spec for type ") + def.name));
    }

private:
    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }

    // ---- INTEGER -------------------------------------------------------

    void encode_integer(std::ostream& os,
                        const TypeDescriptor& def,
                        const void* src) const
    {
        int64_t v = *static_cast<const int64_t*>(src);
        os << '<' << def.name << '>' << v << "</" << def.name << ">\n";
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

    void encode_enumerated(std::ostream& os,
                           const TypeDescriptor& def,
                           const void* src) const
    {
        long v = *static_cast<const long*>(src);
        const EnumSpec& spec = *def.enum_spec;
        // Binary search by value (entries sorted by value)
        const char* name = nullptr;
        int lo = 0, hi = spec.count - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (spec.entries[mid].value == v) { name = spec.entries[mid].name; break; }
            if (spec.entries[mid].value < v) lo = mid + 1; else hi = mid - 1;
        }
        os << '<' << def.name << '>';
        if (name) os << '<' << name << "/>";
        else      os << v;  // unknown extension value — emit as integer
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

    void encode_sequence(std::ostream& os,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        const auto& spec = *def.sequence_spec;
        os << '<' << def.name << ">\n";
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            const void* mptr = static_cast<const char*>(src) + mbr.offset;
            if (mbr.optional) continue;  // TODO: optional member encode
            TypeDescriptor mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            mdef.name = mbr.name;
            XerEncodeStream ms{os};
            encode(ms, mdef, mptr);
        }
        os << "</" << def.name << ">\n";
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

    void encode_choice(std::ostream& os,
                       const TypeDescriptor& def,
                       const void* src) const
    {
        (void)os; (void)def; (void)src;
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
