/*
 * JerCodec.cpp — JER (JSON Encoding Rules, X.697) codec for asn1cpp.
 *
 * Parser ported from asn1c jer_support.c:
 *   Copyright (c) 2003, 2004 X/IO Labs, xiolabs.com.
 *   Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 *   BSD licence.
 */
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <charconv>
#include <limits>
#include <span>
#include <asn1cpp/codec/JerCodec.hpp>
#include <asn1cpp/codec/XerCodec.hpp>    // for xer_detail::format_arcs / parse_arcs
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/SeqOfBase.hpp>

namespace asn1 {

// ---------------------------------------------------------------------------
// Parser — ported from asn1c jer_support.c

namespace jer_detail {

namespace {

enum class State {
    Text, Key, KeyBody, Colon, Value, ValueBody,
    ArrayValue, ArrayValueBody, End
};

constexpr int charclass[256] = {
    0,0,0,0,0,0,0,0,0,1,1,0,1,1,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,2,2,2,2,2,2,2,2,2,2,0,0,0,0,0,0,
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,0
};

constexpr bool is_ws(unsigned char c) { return charclass[c] == 1; }

constexpr char CCOLON = ':';
constexpr char LCBRAC = '{';
constexpr char RCBRAC = '}';
constexpr char CQUOTE = '"';
constexpr char LSBRAC = '[';
constexpr char RSBRAC = ']';
constexpr char CCOMMA = ',';

} // anonymous namespace

std::ptrdiff_t parse(int& state_ctx, const char* jsonbuf, std::size_t size,
                     const JerCallback& cb)
{
    State state = static_cast<State>(state_ctx);
    const char* chunk_start = jsonbuf;
    const char* p = jsonbuf;
    const char* end = jsonbuf + size;

    bool in_string = false;
    bool escaped   = false;
    bool stopped   = false;

    auto token_cb = [&](ChunkType type, State next_state,
                        bool include_current, bool is_final) -> bool {
        const char* data = chunk_start;
        std::ptrdiff_t sz = (p - chunk_start) + (include_current ? 1 : 0);
        if (sz == 0) { state = next_state; return true; }
        ChunkType effective = type;
        if (is_final) {
            if (type == ChunkType::Key)   effective = ChunkType::KeyEnd;
            if (type == ChunkType::Value) effective = ChunkType::ValueEnd;
        }
        int ret = cb(effective, data, static_cast<std::size_t>(sz));
        if (ret < sz) {
            if (include_current && ret == -1) state = next_state;
            stopped = true;
            return false;
        }
        chunk_start = p + (include_current ? 1 : 0);
        state = next_state;
        return true;
    };

    for (; p < end && !stopped; p++) {
        unsigned char C = static_cast<unsigned char>(*p);
        switch (state) {
        case State::Text:
            if (C == static_cast<unsigned char>(CQUOTE) && !escaped) {
                in_string = !in_string; break;
            }
            if (C == '\\') { escaped = !escaped; break; }
            escaped = false;
            if (!in_string) {
                switch (*p) {
                case LCBRAC: token_cb(ChunkType::Delim, State::Key, true, false); break;
                case LSBRAC: token_cb(ChunkType::Delim, State::ArrayValue, true, false); break;
                case RSBRAC: { bool inc = (p == chunk_start); token_cb(ChunkType::Value, State::Text, inc, true); break; }
                case RCBRAC: { bool inc = (p == chunk_start); token_cb(ChunkType::Value, State::Text, inc, true); break; }
                case CCOMMA: token_cb(ChunkType::Value, State::Text, false, true); break;
                default: break;
                }
            }
            break;
        case State::Key:
            switch (*p) {
            case RCBRAC: token_cb(ChunkType::Value, State::Text, true, true); break;
            case CQUOTE: token_cb(ChunkType::Text, State::KeyBody, false, false); break;
            default: break;
            }
            break;
        case State::KeyBody:
            if (*p == CQUOTE) token_cb(ChunkType::Key, State::Colon, true, true);
            break;
        case State::Colon:
            if (*p == CCOLON) state = State::Value;
            break;
        case State::Value:
            if (is_ws(C)) break;
            switch (*p) {
            case CCOMMA: token_cb(ChunkType::Delim, State::Key, true, false); break;
            case RCBRAC: token_cb(ChunkType::Delim, State::End, true, false); break;
            case RSBRAC: token_cb(ChunkType::Value, State::Text, true, true); break;
            default:     token_cb(ChunkType::Text, State::ValueBody, false, false); break;
            }
            break;
        case State::ValueBody:
            switch (*p) {
            case RCBRAC: token_cb(ChunkType::Value, State::End, false, true); break;
            case CCOMMA: { bool inc = (p == chunk_start); token_cb(ChunkType::Value, State::Key, inc, true); break; }
            default: break;
            }
            break;
        case State::ArrayValue:
            if (is_ws(C)) break;
            switch (*p) {
            case LCBRAC: token_cb(ChunkType::Delim, State::ArrayValue, true, false); break;
            case CCOMMA: token_cb(ChunkType::Delim, State::ArrayValue, true, false); break;
            case LSBRAC: token_cb(ChunkType::Delim, State::ArrayValue, true, false); break;
            case RSBRAC: token_cb(ChunkType::Delim, State::End, true, false); break;
            default:     token_cb(ChunkType::Text, State::ArrayValueBody, false, false); break;
            }
            break;
        case State::ArrayValueBody:
            switch (*p) {
            case RSBRAC: { bool inc = (p == chunk_start); token_cb(ChunkType::Value, State::Text, inc, true); break; }
            case CCOMMA: {
                bool inc = (p == chunk_start);
                if (!inc) token_cb(ChunkType::Value, State::ArrayValue, false, true);
                else      token_cb(ChunkType::Delim, State::ArrayValue, false, false);
                break;
            }
            default: break;
            }
            break;
        case State::End:
            if (*p == RCBRAC) token_cb(ChunkType::Value, State::Text, true, true);
            break;
        }
    }

    if (!stopped && p > chunk_start && state == State::Text)
        token_cb(ChunkType::Value, state, false, true);

    state_ctx = static_cast<int>(state);
    return chunk_start - jsonbuf;
}

// ---------------------------------------------------------------------------
// Low-level JSON scanner helpers

static void skip_ws(JerDecodeStream& s) {
    while (!s.at_end() && is_ws(static_cast<unsigned char>(s.data()[0])))
        s.advance(1);
}

// Read a JSON string (cursor must be at opening "). Fills out with unescaped content.
static DecodeResult read_json_string(JerDecodeStream& s, std::string& out) {
    skip_ws(s);
    if (s.at_end() || s.data()[0] != '"')
        return decode_err(DecodeError("JER: expected '\"'"));
    s.advance(1);
    out.clear();
    bool esc = false;
    while (!s.at_end()) {
        char c = s.data()[0];
        s.advance(1);
        if (esc) {
            switch (c) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            default:  out += c; break;
            }
            esc = false;
        } else if (c == '\\') {
            esc = true;
        } else if (c == '"') {
            return decode_ok();
        } else {
            out += c;
        }
    }
    return decode_err(DecodeError("JER: unterminated string"));
}

// Read a JSON non-string value (number, boolean, null) as a raw token.
static DecodeResult read_json_token(JerDecodeStream& s, std::string& out) {
    skip_ws(s);
    out.clear();
    while (!s.at_end()) {
        char c = s.data()[0];
        if (c == ',' || c == '}' || c == ']' || is_ws(static_cast<unsigned char>(c)))
            break;
        out += c;
        s.advance(1);
    }
    if (out.empty())
        return decode_err(DecodeError("JER: expected value token"));
    return decode_ok();
}

// Consume a specific character, skipping leading whitespace. Error if not found.
static DecodeResult expect_char(JerDecodeStream& s, char expected) {
    skip_ws(s);
    if (s.at_end() || s.data()[0] != expected) {
        std::string msg = "JER: expected '";
        msg += expected; msg += "'";
        return decode_err(DecodeError(msg));
    }
    s.advance(1);
    return decode_ok();
}

// Escape a string for JSON output.
static std::string json_escape(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (unsigned char c : sv) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04X", (unsigned)c);
            out += buf;
        } else {
            out += (char)c;
        }
    }
    return out;
}

// Hex helpers (uppercase, no spaces — X.697 §8.9 / §8.8)
static std::string to_hex_upper(std::string_view sv) {
    std::string out;
    out.reserve(sv.size() * 2);
    char buf[3];
    for (unsigned char b : sv) {
        std::snprintf(buf, sizeof(buf), "%02X", b);
        out += buf;
    }
    return out;
}

static std::string from_hex(std::string_view sv) {
    std::string out;
    for (std::size_t i = 0; i + 1 < sv.size(); i += 2) {
        uint8_t hi, lo;
        std::from_chars(sv.data() + i, sv.data() + i + 1, hi, 16);
        std::from_chars(sv.data() + i + 1, sv.data() + i + 2, lo, 16);
        out += (char)((hi << 4) | lo);
    }
    return out;
}

// Proper hex parse: handles both upper and lower case
static uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return (uint8_t)(c - 'a' + 10);
}

static std::string parse_hex_str(std::string_view sv) {
    std::string out;
    out.reserve(sv.size() / 2);
    for (std::size_t i = 0; i + 1 < sv.size(); i += 2)
        out += (char)((hex_val(sv[i]) << 4) | hex_val(sv[i+1]));
    return out;
}

// Skip any JSON value (string, number, object, array, literal) without decoding it.
static DecodeResult skip_json_value(JerDecodeStream& s) {
    skip_ws(s);
    if (s.at_end()) return decode_err(DecodeError("JER: unexpected end in value"));
    char first = s.data()[0];
    if (first == '"') {
        std::string dummy;
        return read_json_string(s, dummy);
    }
    if (first == '{' || first == '[') {
        char close = (first == '{') ? '}' : ']';
        int depth = 0;
        bool in_str = false, esc = false;
        while (!s.at_end()) {
            char c = s.data()[0]; s.advance(1);
            if (esc) { esc = false; continue; }
            if (c == '\\' && in_str) { esc = true; continue; }
            if (c == '"') { in_str = !in_str; continue; }
            if (!in_str) {
                if (c == first) ++depth;
                else if (c == close) { --depth; if (depth == 0) return decode_ok(); }
            }
        }
        return decode_err(DecodeError("JER: unterminated object/array"));
    }
    // number, true, false, null
    while (!s.at_end()) {
        char c = s.data()[0];
        if (c == ',' || c == '}' || c == ']' || is_ws(static_cast<unsigned char>(c))) break;
        s.advance(1);
    }
    return decode_ok();
}

// Peek next non-whitespace character without consuming it. Returns 0 at end.
static char peek_char(JerDecodeStream& s) {
    skip_ws(s);
    return s.at_end() ? '\0' : s.data()[0];
}

} // namespace jer_detail

// ---------------------------------------------------------------------------
// Handler classes

namespace {

struct ErrorJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream&,
                const TypeDescriptor& def, const Asn1Object*) const override {
        assert(false && "JerCodec: unreachable dispatch table entry");
        (void)def;
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream&,
                        const TypeDescriptor& def, Asn1Object*) const override {
        return decode_err(DecodeError(std::string("JER: unsupported: ") + def.name));
    }
};

// NULL → json: null
struct NullJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object*) const override {
        s.os() << "null";
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object*) const override {
        std::string tok;
        if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
        if (tok != "null")
            return decode_err(DecodeError("JER: expected null, got: " + tok));
        return decode_ok();
    }
};

// BOOLEAN → json: true / false
struct BooleanJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        s.os() << (static_cast<const Boolean*>(src)->value() ? "true" : "false");
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string tok;
        if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
        if (tok == "true")       *static_cast<Boolean*>(dest) = Boolean{true};
        else if (tok == "false") *static_cast<Boolean*>(dest) = Boolean{false};
        else return decode_err(DecodeError("JER: BOOLEAN expected true/false, got: " + tok));
        return decode_ok();
    }
};

// INTEGER → json: bare number (X.697 §8.2)
struct IntegerJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        if (def.constraints.int_kind == Constraints::INT_U64)
            s.os() << static_cast<const UInteger*>(src)->value();
        else
            s.os() << static_cast<const Integer*>(src)->value();
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        std::string tok;
        if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
        if (def.constraints.int_kind == Constraints::INT_U64) {
            uint64_t v = 0;
            auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
            if (ec != std::errc{})
                return decode_err(DecodeError("JER: invalid INTEGER: " + tok));
            static_cast<UInteger*>(dest)->set(v);
        } else {
            int64_t v = 0;
            auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
            if (ec != std::errc{})
                return decode_err(DecodeError("JER: invalid INTEGER: " + tok));
            static_cast<Integer*>(dest)->set(v);
        }
        return decode_ok();
    }
};

// REAL → json: number or "NaN"/"PLUS-INFINITY"/"MINUS-INFINITY" (X.697 §8.6)
struct RealJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        double d = static_cast<const Real*>(src)->value();
        auto& os = s.os();
        if (std::isnan(d))      { os << "\"NaN\""; return; }
        if (std::isinf(d))      { os << (d > 0 ? "\"PLUS-INFINITY\"" : "\"MINUS-INFINITY\""); return; }
        if (d == 0.0)           { os << '0'; return; }
        // Use the same representation as asn1c: %.15g-style but with E notation
        char buf[64];
        // Try %g first; if it produces integer-like output, ensure we emit a decimal point
        int n = std::snprintf(buf, sizeof(buf), "%.15G", d);
        // asn1c emits e.g. -2.251799813685248E15 — match format
        // snprintf with %G already does that; just lowercase the E separator to match asn1c
        // Actually asn1c uses uppercase E, which %G gives us.
        (void)n;
        os << buf;
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        jer_detail::skip_ws(s);
        if (!s.at_end() && s.data()[0] == '"') {
            // Quoted special value
            std::string str;
            if (auto r = jer_detail::read_json_string(s, str); !r) return r;
            double d;
            if      (str == "NaN")            d = std::numeric_limits<double>::quiet_NaN();
            else if (str == "PLUS-INFINITY")  d = std::numeric_limits<double>::infinity();
            else if (str == "MINUS-INFINITY") d = -std::numeric_limits<double>::infinity();
            else {
                // Some implementations write the number as a quoted string
                char* endp;
                d = std::strtod(str.c_str(), &endp);
                if (endp != str.c_str() + str.size())
                    return decode_err(DecodeError("JER: invalid REAL string: " + str));
            }
            *static_cast<Real*>(dest) = Real{d};
            return decode_ok();
        }
        std::string tok;
        if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
        char* endp;
        double d = std::strtod(tok.c_str(), &endp);
        if (endp != tok.c_str() + tok.size())
            return decode_err(DecodeError("JER: invalid REAL: " + tok));
        *static_cast<Real*>(dest) = Real{d};
        return decode_ok();
    }
};

// BIT STRING → json: {"value":"HEX","length":N} for unnamed (X.697 §8.8.1)
struct BitStringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const BitString& bs = *static_cast<const BitString*>(src);
        auto& os = s.os();
        auto bytes = bs.bytes();
        std::size_t bits = bs.bit_count();
        std::string hex = jer_detail::to_hex_upper(
            std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        os << "{\"value\":\"" << hex << "\",\"length\":" << bits << '}';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        jer_detail::skip_ws(s);
        if (!s.at_end() && s.data()[0] == '[') {
            // Named-bit array form ["bit0","bit1"] — decode as present bits only
            // We don't have the named-bit table, so just return an empty BitString
            // and consume the array. Full named-bit support deferred to later.
            s.advance(1); // [
            std::size_t depth = 1;
            while (!s.at_end() && depth > 0) {
                char c = s.data()[0]; s.advance(1);
                if (c == '[') ++depth;
                else if (c == ']') --depth;
            }
            *static_cast<BitString*>(dest) = BitString{};
            return decode_ok();
        }
        // Object form {"value":"HEX","length":N}
        if (auto r = jer_detail::expect_char(s, '{'); !r) return r;
        std::string hex_str;
        uint64_t bit_count = 0;
        // Parse two keys in either order
        for (int k = 0; k < 2; ++k) {
            std::string key;
            if (auto r = jer_detail::read_json_string(s, key); !r) return r;
            if (auto r = jer_detail::expect_char(s, ':'); !r) return r;
            if (key == "value") {
                if (auto r = jer_detail::read_json_string(s, hex_str); !r) return r;
            } else if (key == "length") {
                std::string tok;
                if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
                std::from_chars(tok.data(), tok.data() + tok.size(), bit_count);
            } else {
                // Unknown key — consume value
                std::string tok;
                jer_detail::read_json_token(s, tok);
            }
            jer_detail::skip_ws(s);
            if (!s.at_end() && s.data()[0] == ',') s.advance(1);
        }
        if (auto r = jer_detail::expect_char(s, '}'); !r) return r;
        std::string raw = jer_detail::parse_hex_str(hex_str);
        std::size_t byte_count = (bit_count + 7) / 8;
        raw.resize(byte_count, '\0');
        uint8_t unused = (uint8_t)(byte_count * 8 - bit_count);
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        // Clear unused low bits in last byte
        if (!bytes.empty() && unused > 0)
            bytes.back() &= (uint8_t)(0xFFu << unused);
        *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
        return decode_ok();
    }
};

// OCTET STRING → json: "HEXUPPER" (X.697 §8.9 — hex, not base64, per asn1c behaviour)
struct OctetStringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        std::string hex = jer_detail::to_hex_upper(
            std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        s.os() << '"' << hex << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string hex;
        if (auto r = jer_detail::read_json_string(s, hex); !r) return r;
        std::string raw = jer_detail::parse_hex_str(hex);
        *static_cast<OctetString*>(dest) = OctetString{
            reinterpret_cast<const uint8_t*>(raw.data()), raw.size()};
        return decode_ok();
    }
};

// OID → json: "1.2.3.4" (dotted-decimal quoted string, X.697 §8.14)
struct OidJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        s.os() << '"' << xer_detail::format_arcs(static_cast<const Oid*>(src)->arcs()) << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string str;
        if (auto r = jer_detail::read_json_string(s, str); !r) return r;
        *static_cast<Oid*>(dest) = Oid{xer_detail::parse_arcs(str)};
        return decode_ok();
    }
};

// RELATIVE-OID → json: "1.2.3" (same as OID)
struct RelOidJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        s.os() << '"' << xer_detail::format_arcs(static_cast<const RelativeOid*>(src)->arcs()) << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string str;
        if (auto r = jer_detail::read_json_string(s, str); !r) return r;
        *static_cast<RelativeOid*>(dest) = RelativeOid{xer_detail::parse_arcs(str)};
        return decode_ok();
    }
};

// String types (UTF8String, VisibleString, IA5String, …) → json: quoted UTF-8 string
struct StringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const auto& sv = static_cast<const AsnStringBase*>(src)->str();
        s.os() << '"' << jer_detail::json_escape(sv) << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string str;
        if (auto r = jer_detail::read_json_string(s, str); !r) return r;
        static_cast<AsnStringBase*>(dest)->str().assign(str);
        return decode_ok();
    }
};

// BmpString — internal encoding is UTF-16BE; JER is UTF-8 quoted string
struct BmpStringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        // Re-use XER path: it already converts UTF-16BE → UTF-8 for output
        std::ostringstream tmp;
        XerEncodeStream xs{tmp};
        XerCodec::instance().encode(xs, def, src);
        // XER output: <Name>text</Name> — extract the text
        std::string xer = tmp.str();
        auto gt = xer.find('>');
        auto lt2 = xer.rfind('<');
        if (gt != std::string::npos && lt2 != std::string::npos && lt2 > gt) {
            std::string_view content(xer.data() + gt + 1, lt2 - gt - 1);
            s.os() << '"' << jer_detail::json_escape(content) << '"';
        } else {
            s.os() << "\"\"";
        }
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string utf8;
        if (auto r = jer_detail::read_json_string(s, utf8); !r) return r;
        // Convert UTF-8 → UTF-16BE (internal storage)
        std::string out;
        std::size_t i = 0;
        while (i < utf8.size()) {
            uint32_t cp = xer_detail::utf8_decode_cp(utf8.data(), utf8.size(), i);
            out += (char)(uint8_t)(cp >> 8);
            out += (char)(uint8_t)(cp & 0xFF);
        }
        static_cast<AsnStringBase*>(dest)->str().assign(out);
        return decode_ok();
    }
};

// UniversalString — internal encoding is UTF-32BE; JER is UTF-8 quoted string
struct UniversalStringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        std::ostringstream tmp;
        XerEncodeStream xs{tmp};
        XerCodec::instance().encode(xs, def, src);
        std::string xer = tmp.str();
        auto gt = xer.find('>');
        auto lt2 = xer.rfind('<');
        if (gt != std::string::npos && lt2 != std::string::npos && lt2 > gt) {
            std::string_view content(xer.data() + gt + 1, lt2 - gt - 1);
            s.os() << '"' << jer_detail::json_escape(content) << '"';
        } else {
            s.os() << "\"\"";
        }
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string utf8;
        if (auto r = jer_detail::read_json_string(s, utf8); !r) return r;
        std::string out;
        std::size_t i = 0;
        while (i < utf8.size()) {
            uint32_t cp = xer_detail::utf8_decode_cp(utf8.data(), utf8.size(), i);
            out += (char)(uint8_t)(cp >> 24);
            out += (char)(uint8_t)((cp >> 16) & 0xFF);
            out += (char)(uint8_t)((cp >>  8) & 0xFF);
            out += (char)(uint8_t)(cp & 0xFF);
        }
        static_cast<AsnStringBase*>(dest)->str().assign(out);
        return decode_ok();
    }
};

// Hex-encoded string types (T61String, VideotexString, GraphicString, GeneralString)
// → JER: quoted hex string
struct HexStringJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const auto& sv = static_cast<const AsnStringBase*>(src)->str();
        s.os() << '"' << jer_detail::to_hex_upper(sv) << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string hex;
        if (auto r = jer_detail::read_json_string(s, hex); !r) return r;
        static_cast<AsnStringBase*>(dest)->str() = jer_detail::parse_hex_str(hex);
        return decode_ok();
    }
};

// Time types (UTCTime, GeneralizedTime) → JER: quoted string (X.697 §8.23–8.24)
struct TimeJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const auto& sv = static_cast<const AsnStringBase*>(src)->str();
        s.os() << '"' << jer_detail::json_escape(sv) << '"';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string str;
        if (auto r = jer_detail::read_json_string(s, str); !r) return r;
        static_cast<AsnStringBase*>(dest)->str().assign(str);
        return decode_ok();
    }
};

// ANY — pass-through raw JSON value (best-effort: capture until value end)
struct AnyJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        // Stored as opaque OCTET STRING containing the raw JSON bytes.
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        if (bytes.empty()) { s.os() << "null"; return; }
        s.os().write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        // Capture raw JSON token(s) and store as OCTET STRING bytes.
        jer_detail::skip_ws(s);
        if (s.at_end()) return decode_err(DecodeError("JER: ANY: unexpected end"));
        char first = s.data()[0];
        std::string raw;
        if (first == '"') {
            std::string str;
            if (auto r = jer_detail::read_json_string(s, str); !r) return r;
            raw = '"' + str + '"';
        } else if (first == '{' || first == '[') {
            // Capture structured value by depth tracking
            int depth = 0;
            char open = first, close = (first == '{') ? '}' : ']';
            while (!s.at_end()) {
                char c = s.data()[0]; s.advance(1); raw += c;
                if (c == open) ++depth;
                else if (c == close) { --depth; if (depth == 0) break; }
            }
        } else {
            if (auto r = jer_detail::read_json_token(s, raw); !r) return r;
        }
        *static_cast<OctetString*>(dest) = OctetString{
            reinterpret_cast<const uint8_t*>(raw.data()), raw.size()};
        return decode_ok();
    }
};

// ENUMERATED → json: "identifier" (quoted, X.697 §8.4)
struct EnumeratedJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        long v = static_cast<const EnumValue*>(src)->value();
        const EnumSpec& spec = *def.enum_spec;
        // Binary search for the name
        int lo = 0, hi = spec.count - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (spec.entries[mid].value == v) {
                s.os() << '"' << spec.entries[mid].name << '"';
                return;
            }
            if (spec.entries[mid].value < v) lo = mid + 1; else hi = mid - 1;
        }
        // Unknown value — emit as number (X.697 extension point)
        s.os() << v;
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        jer_detail::skip_ws(s);
        if (!s.at_end() && s.data()[0] == '"') {
            std::string name;
            if (auto r = jer_detail::read_json_string(s, name); !r) return r;
            const EnumSpec& spec = *def.enum_spec;
            for (int i = 0; i < spec.count; ++i) {
                if (name == spec.entries[i].name) {
                    static_cast<EnumValue*>(dest)->set(spec.entries[i].value);
                    return decode_ok();
                }
            }
            return decode_err(DecodeError("JER: unknown enum value: " + name));
        }
        // Bare number fallback
        std::string tok;
        if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
        long v = 0;
        auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
        if (ec != std::errc{})
            return decode_err(DecodeError("JER: invalid ENUMERATED: " + tok));
        static_cast<EnumValue*>(dest)->set(v);
        return decode_ok();
    }
};

// SEQUENCE OF / SET OF → json: [...] (X.697 §10)
struct SeqOfJerHandler final : IJerTypeHandler {
    void encode(const JerCodec& codec, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.seq_of_spec;
        const TypeDescriptor& edef = *spec.element;
        const SeqOfBase& seq = *static_cast<const SeqOfBase*>(src);
        std::size_t n = seq.count();
        os << '[';
        for (std::size_t i = 0; i < n; ++i) {
            if (i > 0) os << ',';
            JerEncodeStream es{os, s.depth() + 1};
            codec.encode(es, edef, seq.get_const(i));
        }
        os << ']';
    }
    DecodeResult decode(const JerCodec& codec, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (auto r = jer_detail::expect_char(s, '['); !r) return r;
        const auto& spec = *def.seq_of_spec;
        const TypeDescriptor& edef = *spec.element;
        SeqOfBase& seq = *static_cast<SeqOfBase*>(dest);
        seq.resize(0);
        std::size_t count = 0;
        for (;;) {
            char pk = jer_detail::peek_char(s);
            if (pk == ']') { s.advance(1); break; }
            if (pk == '\0') return decode_err(DecodeError("JER: unexpected end in array"));
            if (pk == ',') { s.advance(1); continue; }
            seq.resize(++count);
            if (auto r = codec.decode(s, edef, seq.get_mut(count - 1)); !r) return r;
        }
        return decode_ok();
    }
};

// SEQUENCE / SET → json: {...} (X.697 §9)
struct SequenceJerHandler final : IJerTypeHandler {
    void encode(const JerCodec& codec, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.sequence_spec;
        os << '{';
        bool first = true;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            if (!first) os << ',';
            first = false;
            const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            os << '"' << mbr.name << "\":";
            JerEncodeStream ms{os, s.depth() + 1};
            codec.encode(ms, mdef, mptr);
        }
        os << '}';
    }
    DecodeResult decode(const JerCodec& codec, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (auto r = jer_detail::expect_char(s, '{'); !r) return r;
        const auto& spec = *def.sequence_spec;
        // Track which members were decoded
        std::vector<bool> seen(spec.count, false);
        // Default-absent all optional members before reading
        for (int i = 0; i < spec.count; ++i)
            if (spec.members[i].optional)
                spec.members[i].optional_ops.set_present(dest, false);
        for (;;) {
            char pk = jer_detail::peek_char(s);
            if (pk == '}') { s.advance(1); break; }
            if (pk == '\0') return decode_err(DecodeError("JER: unexpected end in object"));
            if (pk == ',') { s.advance(1); continue; }
            // Read key
            std::string key;
            if (auto r = jer_detail::read_json_string(s, key); !r) return r;
            if (auto r = jer_detail::expect_char(s, ':'); !r) return r;
            // Find matching member
            int found = -1;
            for (int i = 0; i < spec.count; ++i)
                if (key == spec.members[i].name) { found = i; break; }
            if (found < 0) {
                // Unknown key: skip value
                if (auto r = jer_detail::skip_json_value(s); !r) return r;
                continue;
            }
            const auto& mbr = spec.members[found];
            if (!mbr.type_descriptor) {
                if (auto r = jer_detail::skip_json_value(s); !r) return r;
                continue;
            }
            if (mbr.optional)
                mbr.optional_ops.set_present(dest, true);
            Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            if (auto r = codec.decode(s, mdef, mptr); !r) return r;
            seen[found] = true;
        }
        // Required members not seen → error
        for (int i = 0; i < spec.count; ++i) {
            if (!seen[i] && !spec.members[i].optional && spec.members[i].type_descriptor)
                return decode_err(DecodeError(
                    std::string("JER: missing required member: ") + spec.members[i].name));
        }
        return decode_ok();
    }
};

// CHOICE → json: {"alternativeName": value} (X.697 §11)
struct ChoiceJerHandler final : IJerTypeHandler {
    void encode(const JerCodec& codec, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = static_cast<const ChoiceInterface*>(src);
        int pr = ch->_present;
        if (pr <= 0 || pr > spec.count) { os << "{}"; return; }
        const auto& alt = spec.alternatives[pr - 1];
        if (!alt.type_descriptor) { os << "{}"; return; }
        TypeDescriptor adef = *alt.type_descriptor;
        adef.name = alt.name;
        const Asn1Object* mptr = alt.get_const_fn(ch);
        os << "{\"" << alt.name << "\":";
        JerEncodeStream as{os, s.depth() + 1};
        codec.encode(as, adef, mptr);
        os << '}';
    }
    DecodeResult decode(const JerCodec& codec, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        if (auto r = jer_detail::expect_char(s, '{'); !r) return r;
        const auto& spec = *def.choice_spec;
        ChoiceInterface* ch = static_cast<ChoiceInterface*>(dest);
        // Read the single key
        std::string key;
        if (auto r = jer_detail::read_json_string(s, key); !r) return r;
        if (auto r = jer_detail::expect_char(s, ':'); !r) return r;
        // Find matching alternative
        for (int i = 0; i < spec.count; ++i) {
            const auto& alt = spec.alternatives[i];
            if (key != alt.name) continue;
            if (!alt.type_descriptor)
                return decode_err(DecodeError(
                    std::string("JER: CHOICE: no descriptor for ") + alt.name));
            TypeDescriptor adef = *alt.type_descriptor;
            adef.name = alt.name;
            if (ch->_present != i + 1)
                ch->emplace_alt(alt);
            Asn1Object* mptr = alt.get_mut_fn(ch);
            if (auto r = codec.decode(s, adef, mptr); !r) return r;
            ch->_present = i + 1;
            if (auto r = jer_detail::expect_char(s, '}'); !r) return r;
            return decode_ok();
        }
        return decode_err(DecodeError("JER: CHOICE: unknown alternative: " + key));
    }
};

// ---------------------------------------------------------------------------
// Singletons

static const ErrorJerHandler              s_error;
static const NullJerHandler               s_null;
static const BooleanJerHandler            s_boolean;
static const IntegerJerHandler            s_integer;
static const RealJerHandler               s_real;
static const BitStringJerHandler          s_bitstring;
static const OctetStringJerHandler        s_octetstring;
static const OidJerHandler                s_oid;
static const RelOidJerHandler             s_reloid;
static const TimeJerHandler               s_time;
static const StringJerHandler             s_string;
static const HexStringJerHandler          s_hex_string;
static const BmpStringJerHandler          s_bmp_string;
static const UniversalStringJerHandler    s_universal_string;
static const AnyJerHandler                s_any;
static const EnumeratedJerHandler         s_enumerated;
static const SeqOfJerHandler              s_seqof;
static const SequenceJerHandler           s_sequence;
static const ChoiceJerHandler             s_choice;

} // anonymous namespace

// ---------------------------------------------------------------------------
// Dispatch tables (same indexing as XerCodec: tag.number for primitives)

const IJerTypeHandler* const JerCodec::comp_dispatch_[6] = {
    &s_error,      // [0] Primitive — routed to prim_dispatch_, never lands here
    &s_any,        // [1] Any
    &s_enumerated, // [2] Enumerated
    &s_sequence,   // [3] Sequence / SET
    &s_choice,     // [4] Choice
    &s_seqof,      // [5] SeqOf / SET OF
};

const IJerTypeHandler* const JerCodec::prim_dispatch_[32] = {
    &s_error,             // [ 0] EndOfContents
    &s_boolean,           // [ 1] Boolean
    &s_integer,           // [ 2] Integer
    &s_bitstring,         // [ 3] BitString
    &s_octetstring,       // [ 4] OctetString
    &s_null,              // [ 5] Null
    &s_oid,               // [ 6] OID
    &s_string,            // [ 7] ObjectDescriptor
    &s_error,             // [ 8] External
    &s_real,              // [ 9] Real
    &s_error,             // [10] Enumerated — TypeKind::Enumerated → comp_dispatch_
    &s_error,             // [11] EmbeddedPdv
    &s_string,            // [12] Utf8String
    &s_reloid,            // [13] RelativeOid
    &s_error,             // [14] (unassigned)
    &s_error,             // [15] (unassigned)
    &s_error,             // [16] Sequence    — TypeKind::Sequence → comp_dispatch_
    &s_error,             // [17] Set         — TypeKind::Sequence → comp_dispatch_
    &s_string,            // [18] NumericString
    &s_string,            // [19] PrintableString
    &s_hex_string,        // [20] T61String
    &s_hex_string,        // [21] VideotexString
    &s_string,            // [22] Ia5String
    &s_time,              // [23] UtcTime
    &s_time,              // [24] GeneralizedTime
    &s_hex_string,        // [25] GraphicString
    &s_string,            // [26] VisibleString
    &s_hex_string,        // [27] GeneralString
    &s_universal_string,  // [28] UniversalString
    &s_error,             // [29] CharacterString
    &s_bmp_string,        // [30] BmpString
    &s_error,             // [31] LongForm
};

// ---------------------------------------------------------------------------
// JerCodec public entry points

void JerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const Asn1Object* src) const
{
    auto& s = static_cast<JerEncodeStream&>(dst);
    if (def.kind == TypeKind::Primitive)
        prim_dispatch_[def.tag.number]->encode(*this, s, def, src);
    else
        comp_dispatch_[(int)def.kind]->encode(*this, s, def, src);
    // TODO #160: add validate() call here under ASN1CPP_VALIDATE guards (mirrors BerCodec::encode)
}

DecodeResult JerCodec::decode(IDecodeStream& src,
                               const TypeDescriptor& def,
                               Asn1Object* dest) const
{
    auto& s = static_cast<JerDecodeStream&>(src);
    DecodeResult res = def.kind == TypeKind::Primitive
        ? prim_dispatch_[def.tag.number]->decode(*this, s, def, dest)
        : comp_dispatch_[(int)def.kind]->decode(*this, s, def, dest);
    // TODO #160: add validate() call on res.has_value() under ASN1CPP_VALIDATE guards (mirrors BerCodec::decode)
    return res;
}

} // namespace asn1
