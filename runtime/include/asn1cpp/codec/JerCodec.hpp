#pragma once
#include <string>
#include <string_view>
#include <ostream>
#include <cstddef>
#include <functional>
#include "ICodec.hpp"
#include "../Tag.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// JER stream wrappers

/// @brief IEncodeStream adapter that writes JSON to a std::ostream.
/// @code
/// asn1::JerEncodeStream js{std::cout};
/// asn1::JerCodec::instance().encode(js, MyType::asn_DEF, &obj);
/// @endcode
class JerEncodeStream : public IEncodeStream {
    std::ostream& os_;
    int depth_{0};
public:
    explicit JerEncodeStream(std::ostream& os) : os_(os) {}
    explicit JerEncodeStream(std::ostream& os, int depth) : os_(os), depth_(depth) {}
    std::ostream& os() { return os_; }
    int depth() const { return depth_; }
    std::string indent(int offset = 0) const { return std::string(2 * (depth_ + offset), ' '); }
};

/// @brief IDecodeStream adapter that holds full JSON text for JerCodec::decode().
/// @code
/// std::string json = R"({"field":42})";
/// asn1::JerDecodeStream ds{json};
/// MyType obj{};
/// auto ok = asn1::JerCodec::instance().decode(ds, MyType::asn_DEF, &obj);
/// @endcode
class JerDecodeStream : public IDecodeStream {
    std::string buf_;
    std::size_t pos_{0};
    int parse_state_{0};
public:
    explicit JerDecodeStream(std::string text) : buf_(std::move(text)) {}
    bool at_end() const override { return pos_ >= buf_.size(); }
    std::string_view remaining() const { return std::string_view(buf_).substr(pos_); }
    const char* data() const { return buf_.data() + pos_; }
    std::size_t size() const { return buf_.size() - pos_; }
    void advance(std::size_t n) { pos_ += n; }
    int& parse_state() { return parse_state_; }
};

// ---------------------------------------------------------------------------
// JER streaming parser — ported from asn1c jer_support.c (BSD licence)
// X.697 JER uses the same token types asn1c defined.

namespace jer_detail {

/// Token types delivered to the JerCallback.
enum class ChunkType {
    Text,     ///< Raw text fragment (not yet classified)
    Key,      ///< JSON object key (final chunk, includes closing quote)
    Value,    ///< JSON value (final chunk)
    Delim,    ///< Structural delimiter: { [ } ] ,
    KeyEnd,   ///< Alias for Key (final chunk variant in TOKEN_CB_FINAL)
    ValueEnd, ///< Alias for Value (final chunk variant in TOKEN_CB_FINAL)
};

/// Callback invoked for each token. Return value: bytes consumed (<size = stop).
using JerCallback = std::function<int(ChunkType, const char* data, std::size_t sz)>;

/// Parse up to @p size bytes from @p buf, calling @p cb for each token.
/// @p state_ctx carries parser state across incremental calls (init to 0).
/// Returns number of bytes consumed (same contract as asn1c pjson_parse).
std::ptrdiff_t parse(int& state_ctx, const char* buf, std::size_t size, const JerCallback& cb);

} // namespace jer_detail

// ---------------------------------------------------------------------------
// Per-type handler interface (internal, mirrors IXerTypeHandler)

class JerCodec;

struct IJerTypeHandler {
    virtual ~IJerTypeHandler() = default;
    virtual void encode(const JerCodec& codec, JerEncodeStream& s,
                        const TypeDescriptor& def, const Asn1Object* src) const = 0;
    virtual DecodeResult decode(const JerCodec& codec, JerDecodeStream& s,
                                const TypeDescriptor& def, Asn1Object* dest) const = 0;
};

// ---------------------------------------------------------------------------
// JerCodec — table-driven JER encode/decode (X.697)

/// @brief JER codec singleton.
///
/// Stateless and thread-safe.  Currently a stub — all encode/decode paths
/// return a "not implemented" error until individual type handlers are wired in.
///
/// @see X.697 — JSON Encoding Rules (JER).
class JerCodec : public ICodec {
    static const IJerTypeHandler* const prim_dispatch_[32]; ///< Indexed by universal tag number.
    static const IJerTypeHandler* const comp_dispatch_[6];  ///< Indexed by (int)TypeKind.
public:
    static JerCodec& instance() {
        static JerCodec inst;
        return inst;
    }

    const char* name() const override { return "JER"; }

    /// @brief JER-encode @p src as JSON into the std::ostream wrapped by @p dst.
    /// @param dst  Must be a JerEncodeStream wrapping a std::ostream.
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const Asn1Object* src) const override;

    /// @brief JER-decode from the JSON text wrapped by @p src into @p dest.
    /// @param src  Must be a JerDecodeStream holding the full JSON text.
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        Asn1Object* dest) const override;
};

} // namespace asn1
