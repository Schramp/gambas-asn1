/*
 * JerCodec.cpp — JER (JSON Encoding Rules, X.697) codec for asn1cpp.
 *
 * Parser ported from asn1c jer_support.c:
 *   Copyright (c) 2003, 2004 X/IO Labs, xiolabs.com.
 *   Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 *   BSD licence.
 *
 * All encode/decode handlers are stubs that return "not implemented" until
 * individual type support is added in later issues.
 */
#include <cassert>
#include <asn1cpp/codec/JerCodec.hpp>

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

constexpr bool is_ws(unsigned char c)    { return charclass[c] == 1; }

constexpr char CCOLON = ':';
constexpr char LCBRAC = '{';
constexpr char RCBRAC = '}';
constexpr char CQUOTE = '"';
constexpr char LSBRAC = '[';
constexpr char RSBRAC = ']';
constexpr char CCOMMA = ',';

} // anonymous namespace

std::ptrdiff_t parse(int& state_ctx, const char* jsonbuf, std::size_t size,
                     const JerCallback& cb) {
    State state = static_cast<State>(state_ctx);
    const char* chunk_start = jsonbuf;
    const char* p = jsonbuf;
    const char* end = jsonbuf + size;

    bool in_string = false;
    bool escaped   = false;

    // TOKEN_CB_CALL equivalent — invoke cb, advance chunk_start, switch state.
    // Returns true to continue, false to stop (caller sets goto finish).
    bool stopped = false;

    auto token_cb = [&](ChunkType type, State next_state,
                        bool include_current, bool is_final) -> bool {
        const char* data = chunk_start;
        std::ptrdiff_t sz = (p - chunk_start) + (include_current ? 1 : 0);
        if (sz == 0) {
            state = next_state;
            return true;
        }
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
                in_string = !in_string;
                break;
            }
            if (C == '\\') { escaped = !escaped; break; }
            escaped = false;
            if (!in_string) {
                switch (*p) {
                case LCBRAC: token_cb(ChunkType::Delim, State::Key, true, false); break;
                case LSBRAC: token_cb(ChunkType::Delim, State::ArrayValue, true, false); break;
                case RSBRAC: {
                    bool inc = (p == chunk_start);
                    token_cb(ChunkType::Value, State::Text, inc, true);
                    break;
                }
                case RCBRAC: {
                    bool inc = (p == chunk_start);
                    token_cb(ChunkType::Value, State::Text, inc, true);
                    break;
                }
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
            case CCOMMA: {
                bool inc = (p == chunk_start);
                token_cb(ChunkType::Value, State::Key, inc, true);
                break;
            }
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
            case RSBRAC: {
                bool inc = (p == chunk_start);
                token_cb(ChunkType::Value, State::Text, inc, true);
                break;
            }
            case CCOMMA: {
                bool inc = (p == chunk_start);
                if (!inc)
                    token_cb(ChunkType::Value, State::ArrayValue, false, true);
                else
                    token_cb(ChunkType::Delim, State::ArrayValue, false, false);
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

} // namespace jer_detail

// ---------------------------------------------------------------------------
// JerCodec — stubs (not implemented)

void JerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const Asn1Object*) const {
    (void)dst; (void)def;
    // TODO (#156+): dispatch via type handler table once basic types implemented.
    assert(false && "JerCodec::encode not implemented");
}

DecodeResult JerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              Asn1Object*) const {
    (void)src; (void)def;
    // TODO (#156+): dispatch via type handler table once basic types implemented.
    return decode_err(DecodeError("JER: not implemented"));
}

} // namespace asn1
