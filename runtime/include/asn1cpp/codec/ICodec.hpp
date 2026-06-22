#pragma once
#include "../Expected.hpp"
#include "../Error.hpp"
#include "../TypeDescriptor.hpp"

namespace asn1 {

/// @brief Result type returned by all decode operations.
/// Wraps \c Expected<std::monostate, DecodeError>: check success with
/// \c .has_value() or \c bool conversion; retrieve the error with \c .error().
using DecodeResult = Expected<std::monostate, DecodeError>;

/// @brief Construct a successful \c DecodeResult.
inline DecodeResult decode_ok() { return std::monostate{}; }

/// @brief Construct a failed \c DecodeResult carrying \p e.
/// @param e  Error describing what went wrong and at which byte offset.
inline DecodeResult decode_err(DecodeError e) {
    return make_unexpected<std::monostate, DecodeError>(std::move(e));
}

// ---------------------------------------------------------------------------
// Abstract I/O streams — one subclass per encoding

/// @brief Abstract output sink for a single encoding.
/// Each codec defines its own concrete subclass (\c BerEncodeStream,
/// \c XerEncodeStream, \c PerEncodeStream).  Pass by reference to \c ICodec::encode().
class IEncodeStream {
public:
    virtual ~IEncodeStream() = default;
};

/// @brief Abstract input source for a single encoding.
/// Each codec defines its own concrete subclass (\c BerDecodeStream,
/// \c XerDecodeStream, \c PerDecodeStream).  Pass by reference to \c ICodec::decode().
class IDecodeStream {
public:
    virtual ~IDecodeStream() = default;
    /// @brief Return true when no more input is available.
    virtual bool at_end() const = 0;
};

// ---------------------------------------------------------------------------
// ICodec — single interface for all encodings

/// @brief Abstract codec interface shared by BER, XER, and PER.
///
/// Obtain a concrete instance via its static \c instance() method, e.g.
/// \c BerCodec::instance().  The codec is stateless — the singleton is safe to
/// call from multiple threads simultaneously.
///
/// Typical encode pattern:
/// @code
/// std::vector<uint8_t> buf;
/// asn1::BerWriter w{buf};
/// asn1::BerEncodeStream s{w};
/// asn1::BerCodec::instance().encode(s, MyType::asn_DEF, &obj);
/// @endcode
///
/// Typical decode pattern:
/// @code
/// asn1::BerReader r{span};
/// asn1::BerDecodeStream s{r};
/// MyType obj{};
/// auto ok = asn1::BerCodec::instance().decode(s, MyType::asn_DEF, &obj);
/// if (!ok) { /* ok.error() */ }
/// @endcode
class ICodec {
public:
    virtual ~ICodec() = default;

    /// @brief Short codec name for diagnostics (e.g. \c "BER", \c "XER").
    virtual const char* name() const = 0;

    /// @brief Encode \p src into \p dst.
    /// @param dst  Encoding-specific output stream (must match this codec).
    /// @param def  TypeDescriptor of the value to encode (e.g. \c MyType::asn_DEF).
    /// @param src  Pointer to the source object; must not be null.
    /// @see X.690 §8 — BER encoding rules.
    virtual void encode(IEncodeStream& dst,
                        const TypeDescriptor& def,
                        const Asn1Object* src) const = 0;

    /// @brief Decode from \p src into \p dest.
    /// \p dest must be default-constructed before the call; the codec writes
    /// into it in-place.  On failure the object may be partially filled.
    /// @param src   Encoding-specific input stream positioned at the start of the value.
    /// @param def   TypeDescriptor describing the expected type.
    /// @param dest  Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — success if \c .has_value(), failure with error if not.
    /// @see X.690 §8 — BER decoding rules.
    virtual DecodeResult decode(IDecodeStream& src,
                                const TypeDescriptor& def,
                                Asn1Object* dest) const = 0;
};

} // namespace asn1
