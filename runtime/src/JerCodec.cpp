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
#include <asn1cpp/codec/DecodeDepth.hpp>
#include <asn1cpp/codec/JerCodec.hpp>
#include "HexEncoder.hpp"
#include <asn1cpp/codec/ContainedDecoders.hpp>
#include <asn1cpp/codec/XerCodec.hpp>    // for xer_detail::format_arcs / parse_arcs
#include <asn1cpp/codec/Debug.hpp>
#include <asn1cpp/codec/Validation.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/SeqOfBase.hpp>
#ifdef ASN1CPP_VALIDATE
#include <asn1cpp/Validate.hpp>
#endif

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

/**
 * @brief Read four hex digits of a JSON \\u escape (RFC 8259 §7).
 * @param s  stream positioned just after the "\\u".
 * @param cu receives the UTF-16 code unit.
 * @return false if fewer than four hex digits follow.
 */
static bool read_hex4(JerDecodeStream& s, uint32_t& cu) {
    cu = 0;
    for (int i = 0; i < 4; ++i) {
        if (s.at_end()) return false;
        char c = s.data()[0];
        uint32_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        cu = cu << 4 | d;
        s.advance(1);
    }
    return true;
}

/// @brief Append Unicode code point @p cp to @p out as UTF-8.
static void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | cp >> 6);
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | cp >> 12);
        out += static_cast<char>(0x80 | (cp >> 6 & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | cp >> 18);
        out += static_cast<char>(0x80 | (cp >> 12 & 0x3F));
        out += static_cast<char>(0x80 | (cp >> 6 & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

/**
 * @brief Read one JSON string token and unescape it (RFC 8259 §7).
 *
 * Every JER string goes through here: string values, hex/base64 payloads
 * and member names (X.697 §23.4 NOTE allows escapes in all of them). A
 * \\u escape is a UTF-16 code unit; a surrogate pair combines into one
 * code point, and the result is written as UTF-8. A lone surrogate, a
 * short \\u sequence or an unknown escape character is a decode error.
 * @param s   stream positioned at (or before, with whitespace) the opening quote.
 * @param out receives the unescaped UTF-8 content.
 * @return decode_ok() on the closing quote, an error otherwise.
 */
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
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                uint32_t cu;
                if (!read_hex4(s, cu))
                    return decode_err(DecodeError("JER: malformed \\u escape"));
                if (cu >= 0xDC00 && cu <= 0xDFFF)
                    return decode_err(DecodeError("JER: lone low surrogate in \\u escape"));
                if (cu >= 0xD800 && cu <= 0xDBFF) {
                    uint32_t lo;
                    if (s.size() < 2 || s.data()[0] != '\\' || s.data()[1] != 'u')
                        return decode_err(DecodeError("JER: lone high surrogate in \\u escape"));
                    s.advance(2);
                    if (!read_hex4(s, lo))
                        return decode_err(DecodeError("JER: malformed \\u escape"));
                    if (lo < 0xDC00 || lo > 0xDFFF)
                        return decode_err(DecodeError("JER: lone high surrogate in \\u escape"));
                    cu = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
                }
                append_utf8(out, cu);
                break;
            }
            default:
                return decode_err(DecodeError("JER: invalid escape in string"));
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
    return hex_encode_upper(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
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
/// @brief Formats a finite, nonzero REAL as a JSON number that converts back
///        to exactly the same double: the shortest such digit string
///        (\c std::to_chars), in plain decimal notation when the decimal
///        exponent is in [-4, 15) and as \c d.dddE<exp> otherwise. The Rust
///        runtime's \c jer::real::encode applies the same rule, so both
///        produce identical text.
/// @param d  The value; NaN, infinities and zeros are the caller's
///           special-value strings.
/// @return The JSON number text.
/// @see X.697 §23 (REAL as a JSON number).
static std::string format_real(double d) {
    char buf[40];
    auto res = std::to_chars(buf, buf + sizeof(buf), d, std::chars_format::scientific);
    std::string_view sci(buf, static_cast<std::size_t>(res.ptr - buf));   // e.g. -1.9370032316011307e+05
    bool neg = sci.front() == '-';
    if (neg) sci.remove_prefix(1);
    auto epos = sci.find('e');
    std::string digits;
    for (char c : sci.substr(0, epos)) if (c != '.') digits += c;
    int exp = std::atoi(std::string(sci.substr(epos + 1)).c_str());
    std::string out = neg ? "-" : "";
    if (exp >= -4 && exp < 15) {
        if (exp < 0) {
            out += "0.";
            out.append(static_cast<std::size_t>(-exp - 1), '0');
            out += digits;
        } else {
            std::size_t int_len = static_cast<std::size_t>(exp) + 1;
            if (digits.size() <= int_len) {
                out += digits;
                out.append(int_len - digits.size(), '0');
            } else {
                out += digits.substr(0, int_len);
                out += '.';
                out += digits.substr(int_len);
            }
        }
    } else {
        out += digits[0];
        if (digits.size() > 1) { out += '.'; out += digits.substr(1); }
        out += 'E';
        out += std::to_string(exp);
    }
    return out;
}

static char peek_char(JerDecodeStream& s) {
    skip_ws(s);
    return s.at_end() ? '\0' : s.data()[0];
}

/// @brief Detects the JSON literal `null` (RFC 8259 §3) as the next value,
///        without consuming it.
/// @param s Decode stream, positioned before a value.
/// @return The octets from the cursor through the end of `null`, leading
///         whitespace included; 0 when the next value is not `null`.
static std::size_t peek_null(const JerDecodeStream& s) {
    std::string_view rest = s.remaining();
    std::size_t i = 0;
    while (i < rest.size() && is_ws(static_cast<unsigned char>(rest[i]))) ++i;
    if (i == rest.size() || rest[i] != 'n' || rest.substr(i, 4) != "null") return 0;
    if (rest.size() > i + 4) {
        char c = rest[i + 4];
        if (c != ',' && c != '}' && c != ']' && !is_ws(static_cast<unsigned char>(c))) return 0;
    }
    return i + 4;
}

} // namespace jer_detail

// ---------------------------------------------------------------------------
// Handler classes

namespace {

/// @brief Fallback for a dispatch-table slot with no JER codec. Encode
///        flags the stream as failed, decode returns an error, so a schema
///        construct the runtime cannot handle fails one record instead of
///        aborting the process.
struct ErrorJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object*) const override {
        std::string reason = std::string("JerCodec: unsupported: ") + def.name;
        s.set_encode_failed(reason.c_str());
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

// REAL → json: number, or one of the Table 2 special-value strings
// (X.697 §23: "-0"/"-INF"/"INF"/"NaN" — NOT "PLUS-INFINITY"/
// "MINUS-INFINITY", a nonconformant spelling this handler used to emit
// and decode; asn1c's own specialRealValue_jer table already uses the
// standard's exact spelling). §23.1.1/23.2 also require -0.0 (distinct
// from +0.0, which a bare IEEE `==` comparison can't tell apart — see
// std::signbit below) to encode as the special string "-0", not the
// bare number 0.
struct RealJerHandler final : IJerTypeHandler {
    /// @brief Encode a JER REAL: a \c Decimal as its exact digits, a bare JSON
    ///        number when the JER-visible base constraint admits only 10 and
    ///        `{"base10Value": n}` otherwise; any other value as a JSON number
    ///        or special string.
    /// @see X.697 §23.1.4, §23.4.
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const Real& r = *static_cast<const Real*>(src);
        double d = r.value();
        auto& os = s.os();
        if (r.storage() == Real::Storage::Decimal) {
            if (def.constraints.flags & Constraints::REAL_BASE_10) os << r.decimal_text();
            else os << "{\"base10Value\":" << r.decimal_text() << '}';
            return;
        }
        if (std::isnan(d))      { os << "\"NaN\""; return; }
        if (std::isinf(d))      { os << (d > 0 ? "\"INF\"" : "\"-INF\""); return; }
        if (d == 0.0) {
            os << (std::signbit(d) ? "\"-0\"" : "0");
            return;
        }
        os << jer_detail::format_real(d);
    }
    /// @brief Decode a JER REAL: a JSON number (X.697 §23.3), a special-value
    ///        string (§23.2), or the object `{"base10Value": number}` (§23.4),
    ///        which gives an exact \c Decimal value. A number gives a \c Double,
    ///        or a \c Decimal when the base constraint admits only 10 (§23.1.4).
    /// @return decode_ok, or an error for any other JSON value or member.
    /// @see X.697 §23.
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        jer_detail::skip_ws(s);
        if (!s.at_end() && s.data()[0] == '{') {
            s.advance(1);
            std::string key;
            if (auto r = jer_detail::read_json_string(s, key); !r) return r;
            if (key != "base10Value")
                return decode_err(DecodeError("JER: unexpected REAL object member: " + key));
            if (auto r = jer_detail::expect_char(s, ':'); !r) return r;
            std::string tok;
            if (auto r = jer_detail::read_json_token(s, tok); !r) return r;
            auto v = detail::parse_decimal_number(tok);
            if (!v) return decode_err(DecodeError("JER: invalid REAL base10Value: " + tok));
            if (auto r = jer_detail::expect_char(s, '}'); !r) return r;
            *static_cast<Real*>(dest) = std::move(*v);
            return decode_ok();
        }
        if (!s.at_end() && s.data()[0] == '"') {
            // Quoted special value
            std::string str;
            if (auto r = jer_detail::read_json_string(s, str); !r) return r;
            double d;
            if      (str == "NaN")  d = std::numeric_limits<double>::quiet_NaN();
            else if (str == "INF")  d = std::numeric_limits<double>::infinity();
            else if (str == "-INF") d = -std::numeric_limits<double>::infinity();
            else if (str == "-0")   d = -0.0;
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
        if (def.constraints.flags & Constraints::REAL_BASE_10) {
            auto v = detail::parse_decimal_number(tok);
            if (!v) return decode_err(DecodeError("JER: invalid REAL: " + tok));
            *static_cast<Real*>(dest) = std::move(*v);
            return decode_ok();
        }
        char* endp;
        double d = std::strtod(tok.c_str(), &endp);
        if (endp != tok.c_str() + tok.size())
            return decode_err(DecodeError("JER: invalid REAL: " + tok));
        *static_cast<Real*>(dest) = Real{d};
        return decode_ok();
    }
};

// BIT STRING → json: a bare "HEX" string when the SIZE is fixed, else
// {"value":"HEX","length":N} (X.697 §8.8.1)
struct BitStringJerHandler final : IJerTypeHandler {
    /// @brief The fixed bit count of a BIT STRING whose effective SIZE
    ///        constraint is a single value and not extensible, which X.697
    ///        writes as a bare hex string; -1 for every other BIT STRING.
    /// @param def  The BIT STRING's descriptor (its own constraints).
    static int64_t fixed_size(const TypeDescriptor& def) {
        const Constraints& c = def.constraints;
        if (!(c.flags & Constraints::SIZE_CONSTRAINED) || (c.flags & Constraints::EXTENSIBLE)) return -1;
        return c.size_lower == c.size_upper ? c.size_lower : -1;
    }
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const BitString& bs = *static_cast<const BitString*>(src);
        auto& os = s.os();
        auto bytes = bs.bytes();
        std::size_t bits = bs.bit_count();
        std::string hex = jer_detail::to_hex_upper(
            std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        // A value whose length breaks the fixed size keeps the object form,
        // so the length is not lost.
        if (fixed_size(def) >= 0 && static_cast<int64_t>(bits) == fixed_size(def))
            os << '"' << hex << '"';
        else
            os << "{\"value\":\"" << hex << "\",\"length\":" << bits << '}';
    }
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        jer_detail::skip_ws(s);
        if (!s.at_end() && s.data()[0] == '"') {
            // Fixed-size form: a bare hex string, length given by the type.
            int64_t n = fixed_size(def);
            if (n < 0) return decode_err(DecodeError(std::string("JER: BIT STRING ") + def.name + " is not fixed-size; expected {\"value\",\"length\"}"));
            std::string hex_str;
            if (auto r = jer_detail::read_json_string(s, hex_str); !r) return r;
            std::string raw = jer_detail::parse_hex_str(hex_str);
            std::size_t byte_count = static_cast<std::size_t>((n + 7) / 8);
            if (raw.size() != byte_count)
                return decode_err(DecodeError(std::string("JER: BIT STRING ") + def.name + ": expected " + std::to_string(byte_count) + " hex octets"));
            uint8_t unused = static_cast<uint8_t>(byte_count * 8 - static_cast<std::size_t>(n));
            std::vector<uint8_t> bytes(raw.begin(), raw.end());
            if (!bytes.empty() && unused > 0) bytes.back() &= static_cast<uint8_t>(0xFFu << unused);
            *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
            return decode_ok();
        }
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
        auto& os = s.os();
        os << '"';
        write_hex_bytes(os, v.bytes());
        os << '"';
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

/// @brief JER of BMPString (stride 2) and UniversalString (stride 4): a
///        JSON string of the characters, stored as big-endian UCS-2 / UCS-4
///        code units.
/// @see X.697 §38.1 (restricted character strings as JSON strings), X.680 (07/2002) §37.15.
template<int stride>
struct WideStringJerHandler final : IJerTypeHandler {
    /// @brief Writes the characters as one JSON-escaped UTF-8 string.
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const auto& sv = static_cast<const AsnStringBase*>(src)->str();
        s.os() << '"' << jer_detail::json_escape(xer_detail::wide_to_utf8<stride>(sv)) << '"';
    }
    /// @brief Reads a JSON string and stores each code point as one
    ///        big-endian code unit of \p stride octets.
    /// @return decode_ok, or the JSON string error.
    DecodeResult decode(const JerCodec&, JerDecodeStream& s,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        std::string utf8;
        if (auto r = jer_detail::read_json_string(s, utf8); !r) return r;
        std::string out;
        std::size_t i = 0;
        while (i < utf8.size()) {
            uint32_t cp = xer_detail::utf8_decode_cp(utf8.data(), utf8.size(), i);
            for (int k = stride - 1; k >= 0; --k)
                out += (char)(uint8_t)(cp >> (8 * k));
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

// ANY / OPEN TYPE — quoted uppercase hex of the raw stored content, same
// convention OCTET STRING's own JerCodec handler and ANY's own XerCodec
// handler (AnyXerHandler, format_hex_bytes/parse_hex_bytes) already use.
//
// A previous version of this handler instead passed the stored bytes
// straight through as literal JSON text, on the assumption they were
// already well-formed JSON (a real open-type resolution — re-serializing
// an ANY value according to its actual governing type, identified by a
// sibling field elsewhere in the structure, X.697's real contract for
// open types — which this runtime doesn't implement for any codec).
// Every actual producer of ANY content in this runtime (RandomFiller,
// decoded-and-recaptured BER bytes) stores raw BER-encoded bytes, not
// JSON text, so that assumption produced invalid JSON for every real
// caller (gambas-asn1#668) — confirmed by the fact that AnyXerHandler,
// sitting right next to it, already made the hex choice instead of the
// analogous "assume it's pre-formed XML" mistake.
struct AnyJerHandler final : IJerTypeHandler {
    void encode(const JerCodec&, JerEncodeStream& s,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        std::string_view sv(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        s.os() << '"' << jer_detail::to_hex_upper(sv) << '"';
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
            JerEncodeStream es = s.child();
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
/// @brief JER form of a contained field (\c Containing<T>, X.682 §11): a hex
///        string, or `{"containing": <JER of the inner value>}` (X.697
///        §25.4), or that object plus `"raw": "<hex>"` (`inline_raw`, an
///        extension). Decode accepts every form.
struct ContainedJer {
    static void encode(const JerCodec& codec, JerEncodeStream& s,
                       const TypeDescriptor& def, const Asn1Object* src) {
        const auto& cb = *static_cast<const ContainedBase*>(src);
        const ContainedSpec& cs = *def.contained;
        std::vector<uint8_t> scratch;
        std::string err;
        auto wire = contained_wire_bytes(def, cb, ContainedEncoding::Ber, s.contained(), scratch, err);
        if (!err.empty()) s.set_encode_failed(err.c_str());
        auto& os = s.os();
        ContainedText m = s.contained() && s.contained()->jer ? *s.contained()->jer : cs.jer;
        if (m == ContainedText::Hex || !cb.has_value()) {
            os << '"';
            write_hex_bytes(os, wire);
            os << '"';
            return;
        }
        os << "{\"containing\":";
        JerEncodeStream is = s.child();
        codec.encode(is, *cs.inner_def, cb.value_object());
        if (m == ContainedText::InlineRaw) {
            os << ",\"raw\":\"";
            write_hex_bytes(os, wire);
            os << '"';
        }
        os << '}';
    }

    static DecodeResult decode(const JerCodec& codec, JerDecodeStream& s,
                               const TypeDescriptor& def, Asn1Object* dest) {
        auto& cb = *static_cast<ContainedBase*>(dest);
        const ContainedSpec& cs = *def.contained;
        if (jer_detail::peek_char(s) != '{') {
            std::string hex;
            if (auto r = jer_detail::read_json_string(s, hex); !r) return r;
            std::string raw = jer_detail::parse_hex_str(hex);
            cb.set_raw_from_wire({reinterpret_cast<const uint8_t*>(raw.data()), raw.size()}, ContainedEncoding::Ber);
            return decode_ok();
        }
        if (auto r = jer_detail::expect_char(s, '{'); !r) return r;
        Asn1Object* inner = nullptr;
        std::string raw;
        bool have_raw = false;
        for (;;) {
            char pk = jer_detail::peek_char(s);
            if (pk == '}') { s.advance(1); break; }
            if (pk == ',') { s.advance(1); continue; }
            if (pk == '\0') return decode_err(DecodeError("JER: unexpected end in contained value"));
            std::string key;
            if (auto r = jer_detail::read_json_string(s, key); !r) return r;
            if (auto r = jer_detail::expect_char(s, ':'); !r) return r;
            if (key == "containing") {
                inner = cb.emplace_value_object(*cs.ops);
                if (auto r = codec.decode(s, *cs.inner_def, inner); !r) return r;
            } else if (key == "raw") {
                std::string hex;
                if (auto r = jer_detail::read_json_string(s, hex); !r) return r;
                raw = jer_detail::parse_hex_str(hex);
                have_raw = true;
            } else if (auto r = jer_detail::skip_json_value(s); !r) {
                return r;
            }
        }
        if (!inner) return decode_err(DecodeError(std::string("JER: ") + def.name + ": object without \"containing\""));
        // XER/JER carry an outer-encoding field's contents as BER (the
        // same rules their hex form uses, see ContainedXer/ContainedJer).
        ContainedEncoding enc = cs.encoding == ContainedEncoding::Outer ? ContainedEncoding::Ber : cs.encoding;
        if (!have_raw) {
            const ContainedDecoders& reg = s.contained() ? s.contained()->registry() : ContainedDecoders::defaults();
            std::vector<uint8_t> out;
            std::string err;
            ContainedEncodeArgs ea{*inner, cs, enc, reg, s.contained()};
            if (!ContainedDecoders::encode_value(ea, out, err))
                return decode_err(DecodeError(std::string(def.name) + ": " + err));
            raw.assign(reinterpret_cast<const char*>(out.data()), out.size());
        }
        cb.set_raw_for_value({reinterpret_cast<const uint8_t*>(raw.data()), raw.size()}, enc);
        return decode_ok();
    }
};

/// @brief True for a type whose own JER value can be `null`: NULL
///        (X.697 §26) and an open type, which carries any value.
/// @param def The member's type descriptor.
static bool jer_value_may_be_null(const TypeDescriptor& def) {
    return def.kind == TypeKind::Any
        || (def.kind == TypeKind::Primitive && builtin_tag(def).number == 5);
}

struct SequenceJerHandler final : IJerTypeHandler {
    void encode(const JerCodec& codec, JerEncodeStream& s,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        auto& os = s.os();
        const auto& spec = *def.sequence_spec;
        os << '{';
        bool first = true;
        // Contained members (sorted indices), walked by a cursor so a
        // member costs one compare; only for a type that has any.
        const int* cnext = def.has_contained ? spec.contained_members : nullptr;
        const int* cend  = def.has_contained ? spec.contained_members + spec.contained_count : nullptr;
        for (int i = 0; i < spec.count; ++i) {
            bool contained = cnext != cend && *cnext == i;
            if (contained) ++cnext;
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            if (!first) os << ',';
            first = false;
            const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            os << '"' << mbr.name << "\":";
            JerEncodeStream ms = s.child();
            if (contained) ContainedJer::encode(codec, ms, mdef, mptr);
            else           codec.encode(ms, mdef, mptr);
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
            // X.697 §27.3.4: an absent OPTIONAL or DEFAULT member may be
            // sent as `null`, unless its type can itself be `null`.
            std::size_t null_len = mbr.optional ? jer_detail::peek_null(s) : 0;
            if (null_len && !jer_value_may_be_null(*mbr.type_descriptor)) {
                s.advance(null_len);
                mbr.optional_ops.set_present(dest, false);
                seen[found] = false;
                continue;
            }
            if (mbr.optional)
                mbr.optional_ops.set_present(dest, true);
            Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
            TypeDescriptor mdef = *mbr.type_descriptor;
            mdef.name = mbr.name;
            auto r = def.has_contained && mdef.contained ? ContainedJer::decode(codec, s, mdef, mptr)
                                                         : codec.decode(s, mdef, mptr);
            if (!r) return r;
            seen[found] = true;
        }
        // Required members not seen → error
        for (int i = 0; i < spec.count; ++i) {
            if (!seen[i] && !spec.members[i].optional && spec.members[i].type_descriptor)
                return decode_err(DecodeError(
                    std::string("JER: missing required member: ") + spec.members[i].name));
        }
        // Contained fields that arrived as hex: decode their inner value
        // (those given in the `containing` form are already decoded).
        if (def.has_contained) {
            std::string err;
            if (!decode_contained_members(def, dest, ContainedEncoding::Ber, s.depth(), s.contained(), err))
                return decode_err(DecodeError(std::string(def.name) + "." + err));
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
        if (pr <= 0 || pr > spec.count) {
            std::string reason = std::string("CHOICE ") + def.name + ": no alternative selected";
            s.set_encode_failed(reason.c_str());
            return;
        }
        const auto& alt = spec.alternatives[pr - 1];
        if (!alt.type_descriptor) { s.set_encode_failed((std::string("CHOICE ") + def.name + ": alternative " + alt.name + " has no codec").c_str()); return; }
        TypeDescriptor adef = *alt.type_descriptor;
        adef.name = alt.name;
        const Asn1Object* mptr = alt.get_const_fn(ch);
        os << "{\"" << alt.name << "\":";
        JerEncodeStream as = s.child();
        if (def.has_contained && adef.contained) ContainedJer::encode(codec, as, adef, mptr);
        else                                     codec.encode(as, adef, mptr);
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
            auto r = def.has_contained && adef.contained ? ContainedJer::decode(codec, s, adef, mptr)
                                                         : codec.decode(s, adef, mptr);
            if (!r) return r;
            ch->_present = i + 1;
            if (auto r2 = jer_detail::expect_char(s, '}'); !r2) return r2;
            if (!def.has_contained) return decode_ok();
            std::string err;
            if (!decode_contained_alternative(def, dest, ContainedEncoding::Ber, s.depth(), s.contained(), err))
                return decode_err(DecodeError(std::string(def.name) + "." + err));
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
static const WideStringJerHandler<2>      s_bmp_string;
static const WideStringJerHandler<4>      s_universal_string;
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
    validate_on_encode("JER", def, src);
    auto& s = static_cast<JerEncodeStream&>(dst);
    if (def.kind == TypeKind::Primitive)
        // prim_dispatch_ is indexed by the builtin's universal tag number
        // (builtin_tag) — never def.tag itself, the wire tag, which after
        // the type assignment's own [n] can carry a different class and a
        // number matching a *different* builtin (see the matching comment
        // in XerCodec::encode).
        prim_dispatch_[builtin_tag(def).number]->encode(*this, s, def, src);
    else
        comp_dispatch_[(int)def.kind]->encode(*this, s, def, src);
}

DecodeResult JerCodec::decode(IDecodeStream& src,
                               const TypeDescriptor& def,
                               Asn1Object* dest) const
{
    auto& s = static_cast<JerDecodeStream&>(src);
    DecodeDepthGuard depth_guard{s.depth(), def};
    if (depth_guard.exceeded()) return decode_err(DecodeError(DecodeDepthGuard::message(def)));
    DecodeResult res = def.kind == TypeKind::Primitive
        // See the matching comment in encode() above.
        ? prim_dispatch_[builtin_tag(def).number]->decode(*this, s, def, dest)
        : comp_dispatch_[(int)def.kind]->decode(*this, s, def, dest);
    if (res.has_value()) validate_on_decode("JER", def, dest);
    return res;
}

} // namespace asn1
