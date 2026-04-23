#pragma once
#include "../Expected.hpp"
#include "../Error.hpp"
#include "../TypeDescriptor.hpp"

namespace asn1 {

// Convenience alias: decode returns success/failure; value is written into dest.
using DecodeResult = Expected<std::monostate, DecodeError>;

inline DecodeResult decode_ok() { return std::monostate{}; }
inline DecodeResult decode_err(DecodeError e) {
    return make_unexpected<std::monostate, DecodeError>(std::move(e));
}

// ---------------------------------------------------------------------------
// Abstract I/O streams — one subclass per encoding

class IEncodeStream {
public:
    virtual ~IEncodeStream() = default;
};

class IDecodeStream {
public:
    virtual ~IDecodeStream() = default;
    virtual bool at_end() const = 0;
};

// ---------------------------------------------------------------------------
// ICodec — single interface for all encodings

class ICodec {
public:
    virtual ~ICodec() = default;
    virtual const char* name() const = 0;

    // Encode value at src (described by def) into dst.
    virtual void encode(IEncodeStream& dst,
                        const TypeDescriptor& def,
                        const void* src) const = 0;

    // Decode from src into dest (described by def).
    virtual DecodeResult decode(IDecodeStream& src,
                                const TypeDescriptor& def,
                                void* dest) const = 0;
};

} // namespace asn1
