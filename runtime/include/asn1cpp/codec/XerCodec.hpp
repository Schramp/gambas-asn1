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

class XerDecodeStream : public IDecodeStream {
    std::string buf_;
    std::size_t pos_{0};
public:
    explicit XerDecodeStream(std::string text) : buf_(std::move(text)) {}
    bool at_end() const override { return pos_ >= buf_.size(); }
    std::string_view remaining() const { return std::string_view(buf_).substr(pos_); }
    void advance(std::size_t n) { pos_ += n; }
    void skip_whitespace() {
        while (pos_ < buf_.size() && std::isspace((unsigned char)buf_[pos_])) ++pos_;
    }
};

// ---------------------------------------------------------------------------
// Simple XER helpers

namespace xer_detail {

inline std::size_t skip_ws(std::string_view sv, std::size_t pos) {
    while (pos < sv.size() && std::isspace((unsigned char)sv[pos])) ++pos;
    return pos;
}

inline std::string_view trim(std::string_view sv) {
    while (!sv.empty() && std::isspace((unsigned char)sv.front())) sv.remove_prefix(1);
    while (!sv.empty() && std::isspace((unsigned char)sv.back()))  sv.remove_suffix(1);
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
    while (pos < sv.size() && sv[pos] != '>' && sv[pos] != '/' && !std::isspace((unsigned char)sv[pos]))
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

// XER text content escapes — only the three required by XML 1.0 §2.4 in
// element content (`<`, `>`, `&`) plus the two attribute-only entities
// (`"`, `'`) for symmetry on decode. Codec emits the three; decoder
// resolves all five named entities plus numeric `&#NN;` / `&#xNN;`.
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
        // find ';' within a small window
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
            // numeric character reference: emit as UTF-8
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
        else    { out += sv[i++]; }   // unknown entity: keep '&' literal, retry next char
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

    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override;

    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override;

private:
    // ---- Tag predicates ---------------------------------------------------
    static bool is_boolean_tag(const Tag& t);
    static bool is_integer_tag(const Tag& t);
    static bool is_null_tag(const Tag& t);
    static bool is_real_tag(const Tag& t);
    static bool is_bitstring_tag(const Tag& t);
    static bool is_oid_tag(const Tag& t);
    static bool is_relative_oid_tag(const Tag& t);
    static bool is_utctime_tag(const Tag& t);
    static bool is_gentime_tag(const Tag& t);
    static bool is_octetstring_tag(const Tag& t);
    static bool is_primitive_string_tag(const Tag& t);
    static bool is_hex_string_tag(const Tag& t);
    static bool is_bmp_string_tag(const Tag& t);
    static bool is_universal_string_tag(const Tag& t);

    // ---- Template methods (must stay in header) ---------------------------

    template<typename F>
    DecodeResult decode_simple_text_element(XerDecodeStream& s, const char* name, F&& fn) const {
        if (auto r = xer_detail::consume_open_tag(s, name); !r) return r;
        auto raw = xer_detail::read_text_content(s);
        if (auto r = xer_detail::consume_close_tag(s, name); !r) return r;
        // Resolve XML entities. Only allocates when an '&' is present;
        // otherwise xer_unescape returns the same content verbatim.
        std::string unescaped = xer_detail::xer_unescape(raw);
        return fn(std::string_view{unescaped});
    }

    template<typename T>
    DecodeResult decode_time_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const {
        return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
            *static_cast<T*>(dest) = T{std::string(text)};
            return decode_ok();
        });
    }

    // ---- Inline statics needed by templates -------------------------------

    static void utf8_encode_cp(std::ostream& os, uint32_t cp) {
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

    static uint32_t utf8_decode_cp(const char* data, std::size_t len, std::size_t& pos) {
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

    static std::string format_arcs(const std::vector<uint32_t>& arcs) {
        std::string s;
        for (std::size_t i = 0; i < arcs.size(); ++i) {
            if (i) s += '.';
            s += std::to_string(arcs[i]);
        }
        return s;
    }

    static std::vector<uint32_t> parse_arcs(std::string_view sv) {
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

    static void encode_text_element(XerEncodeStream& s, const TypeDescriptor& def, const void* src) {
        s.os() << '<' << def.name << '>'
               << xer_detail::xer_escape(detail::asnstring_view(src))
               << "</" << def.name << ">\n";
    }

    template<int stride>
    void encode_wide_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const {
        static_assert(stride == 2 || stride == 4);
        std::string_view sv = detail::asnstring_view(src);
        // Encode to UTF-8 in a buffer, then XML-escape — code points 0x3C /
        // 0x3E / 0x26 emit as bare ASCII bytes that need entities.
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
               << xer_detail::xer_escape(utf8.str())
               << "</" << def.name << ">\n";
    }

    template<typename T>
    static void encode_oid_impl(XerEncodeStream& s, const TypeDescriptor& def, const void* src) {
        s.os() << '<' << def.name << '>' << format_arcs(static_cast<const T*>(src)->arcs()) << "</" << def.name << ">\n";
    }

    template<typename T>
    DecodeResult decode_oid_impl(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const {
        return decode_simple_text_element(s, def.name, [dest](std::string_view text) -> DecodeResult {
            *static_cast<T*>(dest) = T{parse_arcs(xer_detail::trim(text))};
            return decode_ok();
        });
    }

    // ---- Static helpers (defined in XerCodec.cpp) -------------------------
    static std::string format_hex_bytes(std::string_view sv);
    static std::string parse_hex_bytes(std::string_view sv);
    static std::string base64_encode(std::span<const uint8_t> in);
    static std::vector<uint8_t> base64_decode(std::string_view in);

    // ---- Non-template method declarations ---------------------------------
    void encode_null(XerEncodeStream& s, const TypeDescriptor& def) const;
    DecodeResult decode_null(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_boolean(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_boolean(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_time_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;

    void encode_xer_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_xer_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_hex_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_hex_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_any_xer(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_any_xer(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_octetstring_xer(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_octetstring_xer(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_bmp_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_bmp_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_universal_string(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_universal_string(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_oid(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_oid(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_relative_oid(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_relative_oid(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_bitstring(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_bitstring(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_real(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_real(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_integer(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_integer(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_enumerated(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_enumerated(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_seq_of(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_seq_of(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_sequence(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_sequence(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_choice(XerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_choice(XerDecodeStream& s, const TypeDescriptor& def, void* dest) const;
};

} // namespace asn1
