#pragma once
#include <array>
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
#include <span>
#include "ICodec.hpp"
#include "../Tag.hpp"
#include "../types/Boolean.hpp"
#include "../types/OctetString.hpp"
#include "../types/Real.hpp"
#include "../types/BitString.hpp"
#include "../types/Oid.hpp"
#include "../types/Time.hpp"
#include "../types/Strings.hpp"

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
    std::string indent(int offset = 0) const { return std::string(4 * (depth_ + offset), ' '); }
};

// ---------------------------------------------------------------------------
// XER helpers (free functions used by handler classes and callers)

namespace xer_detail {

// Lookup table avoids locale-aware std::isspace overhead (was 8.9% of CPU in profiler).
inline constexpr auto make_xer_ws() {
    std::array<bool, 256> t{};
    t['\t'] = t['\n'] = t['\r'] = t[' '] = true;
    return t;
}
static constexpr auto xer_ws = make_xer_ws();

} // namespace xer_detail (reopened below after XerDecodeStream)

// Controls non-standard XER extensions accepted by the decoder.
// Standard BASIC-XER (X.693 §8) is strict: BOOLEAN must use empty-element
// form (<true/>/<false/>) and BIT STRING must use xmlbstring (0/1 chars).
// Lenient mode additionally accepts:
//   BOOLEAN: text content "true"/"false" (EXTENDED-XER §10)
//   BIT STRING: hex pairs "AABBCC…" (non-standard asn1c extension, no grammar production)
enum class XerDecodeMode { Strict, Lenient };

class XerDecodeStream : public IDecodeStream {
    std::string buf_;
    std::size_t pos_{0};
    bool lenient_;
public:
    explicit XerDecodeStream(std::string text, XerDecodeMode mode = XerDecodeMode::Strict)
        : buf_(std::move(text)), lenient_(mode == XerDecodeMode::Lenient) {}
    bool at_end() const override { return pos_ >= buf_.size(); }
    bool lenient() const { return lenient_; }
    std::string_view remaining() const { return std::string_view(buf_).substr(pos_); }
    void advance(std::size_t n) { pos_ += n; }
    void skip_whitespace() {
        while (pos_ < buf_.size() && xer_detail::xer_ws[(unsigned char)buf_[pos_]]) ++pos_;
    }
};

namespace xer_detail {

inline std::size_t skip_ws(std::string_view sv, std::size_t pos) {
    while (pos < sv.size() && xer_ws[(unsigned char)sv[pos]]) ++pos;
    return pos;
}

inline std::string_view trim(std::string_view sv) {
    while (!sv.empty() && xer_ws[(unsigned char)sv.front()]) sv.remove_prefix(1);
    while (!sv.empty() && xer_ws[(unsigned char)sv.back()])  sv.remove_suffix(1);
    return sv;
}

struct TagInfo { std::string name; bool closing; bool self_closing; };
inline TagInfo parse_tag(std::string_view sv, std::size_t& pos) {
    pos = skip_ws(sv, pos);
    if (pos >= sv.size() || sv[pos] != '<') return {"", false, false};
    ++pos;
    bool closing = pos < sv.size() && sv[pos] == '/';
    if (closing) ++pos;
    std::size_t name_start = pos;
    while (pos < sv.size() && sv[pos] != '>' && sv[pos] != '/' && !xer_ws[(unsigned char)sv[pos]])
        ++pos;
    std::string name(sv.substr(name_start, pos - name_start));
    pos = skip_ws(sv, pos);
    bool self_closing = pos < sv.size() && sv[pos] == '/';
    if (self_closing) ++pos;
    if (pos < sv.size() && sv[pos] == '>') ++pos;
    return {name, closing, self_closing};
}

inline TagInfo consume_tag(XerDecodeStream& s) {
    std::size_t pos = 0;
    auto ti = parse_tag(s.remaining(), pos);
    s.advance(pos);
    return ti;
}

inline TagInfo peek_tag(XerDecodeStream& s) {
    std::size_t pos = 0;
    return parse_tag(s.remaining(), pos);
}

inline std::string_view read_text_content(XerDecodeStream& s) {
    std::string_view rem = s.remaining();
    std::size_t pos = 0;
    while (pos < rem.size() && rem[pos] != '<') ++pos;
    std::string_view text = rem.substr(0, pos);
    s.advance(pos);
    return text;
}

inline std::string xer_escape(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char c : sv) {
        switch (c) {
        case '<': out += "&lt;";   break;
        case '>': out += "&gt;";   break;
        case '&': out += "&amp;";  break;
        default:  out += c;        break;
        }
    }
    return out;
}

inline std::string xer_unescape(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (std::size_t i = 0; i < sv.size(); ) {
        if (sv[i] != '&') { out += sv[i++]; continue; }
        std::size_t end = i + 1;
        while (end < sv.size() && end - i < 12 && sv[end] != ';') ++end;
        if (end >= sv.size() || sv[end] != ';') { out += sv[i++]; continue; }
        std::string_view ent = sv.substr(i + 1, end - i - 1);
        bool ok = true;
        if      (ent == "lt")    out += '<';
        else if (ent == "gt")    out += '>';
        else if (ent == "amp")   out += '&';
        else if (ent == "quot")  out += '"';
        else if (ent == "apos")  out += '\'';
        else if (!ent.empty() && ent.front() == '#') {
            uint32_t cp = 0;
            std::string_view num = ent.substr(1);
            int base = 10;
            if (!num.empty() && (num.front() == 'x' || num.front() == 'X')) {
                base = 16; num.remove_prefix(1);
            }
            for (char c : num) {
                int d;
                if      (c >= '0' && c <= '9') d = c - '0';
                else if (base == 16 && c >= 'a' && c <= 'f') d = 10 + c - 'a';
                else if (base == 16 && c >= 'A' && c <= 'F') d = 10 + c - 'A';
                else { ok = false; break; }
                cp = cp * base + d;
            }
            if (ok) {
                if (cp < 0x80)  out += (char)cp;
                else if (cp < 0x800) {
                    out += (char)(0xC0 | (cp >> 6));
                    out += (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    out += (char)(0xE0 | (cp >> 12));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                } else {
                    out += (char)(0xF0 | ((cp >> 18) & 0x07));
                    out += (char)(0x80 | ((cp >> 12) & 0x3F));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                }
            }
        } else {
            ok = false;
        }
        if (ok) i = end + 1;
        else    { out += sv[i++]; }
    }
    return out;
}

inline DecodeResult consume_open_tag(XerDecodeStream& s, std::string_view name) {
    auto ti = consume_tag(s);
    if (ti.name != name || ti.closing || ti.self_closing)
        return decode_err(DecodeError(std::string("XER: expected <") + std::string(name) + ">"));
    return decode_ok();
}

inline DecodeResult consume_close_tag(XerDecodeStream& s, std::string_view name) {
    auto ti = consume_tag(s);
    if (!ti.closing || ti.name != name)
        return decode_err(DecodeError(std::string("XER: expected </") + std::string(name) + ">"));
    return decode_ok();
}

// ---------------------------------------------------------------------------
// UTF-8 / wide-string helpers (used by BmpString and UniversalString handlers)

inline void utf8_encode_cp(std::ostream& os, uint32_t cp) {
    if (cp < 0x80) {
        os << (char)cp;
    } else if (cp < 0x800) {
        os << (char)(0xC0 | (cp >> 6));
        os << (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        os << (char)(0xE0 | (cp >> 12));
        os << (char)(0x80 | ((cp >> 6) & 0x3F));
        os << (char)(0x80 | (cp & 0x3F));
    } else {
        os << (char)(0xF0 | ((cp >> 18) & 0x07));
        os << (char)(0x80 | ((cp >> 12) & 0x3F));
        os << (char)(0x80 | ((cp >> 6) & 0x3F));
        os << (char)(0x80 | (cp & 0x3F));
    }
}

inline uint32_t utf8_decode_cp(const char* data, std::size_t len, std::size_t& pos) {
    uint8_t c = (uint8_t)data[pos++];
    if ((c & 0x80) == 0) return c;
    uint32_t cp; int extra;
    if      ((c & 0xE0) == 0xC0) { cp = c & 0x1Fu; extra = 1; }
    else if ((c & 0xF0) == 0xE0) { cp = c & 0x0Fu; extra = 2; }
    else if ((c & 0xF8) == 0xF0) { cp = c & 0x07u; extra = 3; }
    else return 0xFFFDu;
    while (extra-- > 0 && pos < len) cp = (cp << 6) | ((uint8_t)data[pos++] & 0x3Fu);
    return cp;
}

// ---------------------------------------------------------------------------
// OID arc helpers

inline std::string format_arcs(const std::vector<uint32_t>& arcs) {
    std::string s;
    for (std::size_t i = 0; i < arcs.size(); ++i) {
        if (i) s += '.';
        s += std::to_string(arcs[i]);
    }
    return s;
}

inline std::vector<uint32_t> parse_arcs(std::string_view sv) {
    std::vector<uint32_t> arcs;
    while (!sv.empty()) {
        uint32_t v = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
        if (ec != std::errc{}) break;
        arcs.push_back(v);
        sv.remove_prefix(ptr - sv.data());
        if (!sv.empty() && sv[0] == '.') sv.remove_prefix(1);
    }
    return arcs;
}

// ---------------------------------------------------------------------------
// String emit helper

inline void encode_text_element(XerEncodeStream& s, const TypeDescriptor& def,
                                std::string_view value) {
    s.os() << '<' << def.name << '>'
           << xer_escape(value)
           << "</" << def.name << ">\n";
}

// ---------------------------------------------------------------------------
// Template decode/encode helpers (inline, no codec reference needed)

template<typename F>
inline DecodeResult decode_simple_text_element(XerDecodeStream& s, const char* name, F&& fn) {
    if (auto r = consume_open_tag(s, name); !r) return r;
    auto raw = read_text_content(s);
    if (auto r = consume_close_tag(s, name); !r) return r;
    std::string unescaped = xer_unescape(raw);
    return fn(std::string_view{unescaped});
}

template<typename T>
inline DecodeResult decode_time_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) {
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        *static_cast<T*>(dest) = T{std::string(text)};
        return decode_ok();
    });
}

template<int stride>
inline void encode_wide_string(XerEncodeStream& s, const TypeDescriptor& def,
                               std::string_view sv) {
    static_assert(stride == 2 || stride == 4);
    std::ostringstream utf8;
    for (std::size_t i = 0; i + stride <= sv.size(); i += stride) {
        uint32_t cp;
        if constexpr (stride == 2)
            cp = ((uint8_t)sv[i] << 8) | (uint8_t)sv[i+1];
        else
            cp = ((uint8_t)sv[i] << 24) | ((uint8_t)sv[i+1] << 16) | ((uint8_t)sv[i+2] << 8) | (uint8_t)sv[i+3];
        utf8_encode_cp(utf8, cp);
    }
    s.os() << '<' << def.name << '>'
           << xer_escape(utf8.str())
           << "</" << def.name << ">\n";
}

template<typename T>
inline void encode_oid_impl(XerEncodeStream& s, const TypeDescriptor& def, const void* src) {
    s.os() << '<' << def.name << '>'
           << format_arcs(static_cast<const T*>(src)->arcs())
           << "</" << def.name << ">\n";
}

template<typename T>
inline DecodeResult decode_oid_impl(XerDecodeStream& s, const TypeDescriptor& def, void* dest) {
    return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
        *static_cast<T*>(dest) = T{parse_arcs(trim(text))};
        return decode_ok();
    });
}

} // namespace xer_detail

// ---------------------------------------------------------------------------
// Per-type handler interface — one singleton per type

class XerCodec;

struct IXerTypeHandler {
    virtual ~IXerTypeHandler() = default;
    virtual void encode(const XerCodec& codec, XerEncodeStream& s,
                        const TypeDescriptor& def, const Asn1Object* src) const = 0;
    virtual DecodeResult decode(const XerCodec& codec, XerDecodeStream& s,
                                const TypeDescriptor& def, Asn1Object* dest) const = 0;
};

// ---------------------------------------------------------------------------
// XerCodec — generic XER encode/decode driven by TypeDescriptor tables

class XerCodec : public ICodec {
public:
    static XerCodec& instance() {
        static XerCodec inst;
        return inst;
    }

    const char* name() const override { return "XER"; }

    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const Asn1Object* src) const override;

    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        Asn1Object* dest) const override;

private:
    static const IXerTypeHandler* const comp_dispatch_[6];   // indexed by (int)TypeKind
    static const IXerTypeHandler* const prim_dispatch_[32];  // indexed by tag.number
};

} // namespace asn1
