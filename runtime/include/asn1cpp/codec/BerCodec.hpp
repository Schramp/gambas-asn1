#pragma once
#include <span>
#include "ICodec.hpp"
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "BerTraits.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// BER stream wrappers

/// @brief \c IEncodeStream adapter over a \c BerWriter.
/// Construct one on the stack, pass by reference to \c BerCodec::encode().
/// @code
/// std::vector<uint8_t> buf;
/// asn1::BerWriter w{buf};
/// asn1::BerEncodeStream s{w};
/// asn1::BerCodec::instance().encode(s, MyType::asn_DEF, &obj);
/// @endcode
class BerEncodeStream : public IEncodeStream {
    BerWriter& w_;
public:
    /// @brief Wrap \p w for use with \c BerCodec::encode().
    /// @param w  Output writer; must outlive this stream object.
    explicit BerEncodeStream(BerWriter& w) : w_(w) {}
    /// @brief Access the underlying writer (used internally by \c BerCodec).
    BerWriter& writer() { return w_; }
    /// @return True if any value failed to encode (see \c BerWriter::set_encode_failed).
    bool encode_failed() const { return w_.encode_failed(); }
};

/// @brief \c IDecodeStream adapter over a \c BerReader.
/// Construct one on the stack, pass by reference to \c BerCodec::decode().
/// @code
/// asn1::BerReader r{data_span};
/// asn1::BerDecodeStream s{r};
/// MyType obj{};
/// auto ok = asn1::BerCodec::instance().decode(s, MyType::asn_DEF, &obj);
/// @endcode
class BerDecodeStream : public IDecodeStream {
    BerReader& r_;
public:
    /// @brief Wrap \p r for use with \c BerCodec::decode().
    /// @param r  Reader positioned at the first byte of the TLV to decode;
    ///           must outlive this stream object.
    explicit BerDecodeStream(BerReader& r) : r_(r) {}
    /// @brief Access the underlying reader (used internally by \c BerCodec).
    BerReader& reader() { return r_; }
    /// @brief Return true when the underlying reader has no more input.
    bool at_end() const override { return r_.at_end(); }
};

// ---------------------------------------------------------------------------
// Per-type handler interface — one singleton per type, per codec

class BerCodec;

/// @brief Internal per-type BER handler interface.
/// One stateless singleton exists per ASN.1 type kind (SEQUENCE, CHOICE, …)
/// and per primitive tag.  Not part of the public API — use \c BerCodec directly.
struct IBerTypeHandler {
    virtual ~IBerTypeHandler() = default;
    virtual void encode(const BerCodec& codec, BerWriter& w,
                        const TypeDescriptor& def, const Asn1Object* src) const = 0;
    virtual DecodeResult decode(const BerCodec& codec, BerReader& r,
                                const TypeDescriptor& def, Asn1Object* dest) const = 0;
    /// @brief Decodes a value whose tag and length the caller already
    ///        consumed (an IMPLICIT tag, X.690 §8.14.3). Default: re-tags
    ///        the contents and calls \c decode(). Override for zero-alloc
    ///        fast paths.
    /// @param codec    The codec that dispatched here, for nested members.
    /// @param content  Reader over exactly the value's contents, opened with
    ///                 \c BerReader::sub so it carries the decode nesting depth.
    /// @param def      Descriptor of the value's type.
    /// @param dest     Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — check with \c .has_value().
    virtual DecodeResult decode_value(const BerCodec& codec,
                                      BerReader& content,
                                      const TypeDescriptor& def,
                                      Asn1Object* dest) const;

    /// @brief \c decode_value() for contents whose IMPLICIT tag has the
    ///        constructed bit set. String types override it to join the
    ///        segments of the constructed form (X.690 §8.6.4, §8.7.3,
    ///        §8.23.6); for every other type it is \c decode_value().
    /// @param codec    Codec instance, for recursive decode.
    /// @param content  Reader over the constructed contents.
    /// @param def      Descriptor of the value's type.
    /// @param dest     Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — check with \c .has_value().
    virtual DecodeResult decode_constructed_value(const BerCodec& codec,
                                                  BerReader& content,
                                                  const TypeDescriptor& def,
                                                  Asn1Object* dest) const {
        return decode_value(codec, content, def, dest);
    }

    /// @brief True for a handler whose type may also be encoded in
    ///        constructed form as segments (BIT STRING, OCTET STRING,
    ///        character strings, X.690 §8.6.4, §8.7.3, §8.23.6). Only these
    ///        get \c decode_constructed_value() from \c BerCodec::decode_value;
    ///        a constructed tag over any other type (an IMPLICIT-tagged
    ///        SEQUENCE, say) goes to \c decode_value() directly.
    bool joins_segments() const { return joins_segments_; }

protected:
    constexpr IBerTypeHandler() = default;
    /// @param joins_segments  See \c joins_segments().
    constexpr explicit IBerTypeHandler(bool joins_segments) : joins_segments_(joins_segments) {}

private:
    bool joins_segments_ = false;
};

// ---------------------------------------------------------------------------
// BerCodec — generic BER encode/decode driven by TypeDescriptor tables

/// @brief BER codec singleton.
///
/// All encode/decode logic is table-driven via \c TypeDescriptor; generated
/// files contain only descriptor tables, no codec logic.  The singleton is
/// stateless and thread-safe.
///
/// @see X.690 — BER/DER encoding rules.
class BerCodec : public ICodec {
public:
    /// @brief Return the process-wide \c BerCodec singleton.
    /// The returned reference is valid for the process lifetime.
    static BerCodec& instance() {
        static BerCodec inst;
        return inst;
    }

    /// @brief Return \c "BER".
    const char* name() const override { return "BER"; }

    /// @brief BER-encode \p src into the \c BerWriter wrapped by \p dst.
    /// @param dst  Must be a \c BerEncodeStream wrapping a \c BerWriter.
    /// @param def  TypeDescriptor of the value (e.g. \c MyType::asn_DEF).
    /// @param src  Source object; must not be null.
    /// @see X.690 §8 — BER encoding rules.
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const Asn1Object* src) const override;

    /// @brief BER-decode from \p src into \p dest.
    /// \p dest must be default-constructed.  On success the reader is advanced
    /// past the decoded TLV.
    /// @param src   Must be a \c BerDecodeStream wrapping a \c BerReader.
    /// @param def   TypeDescriptor of the expected type.
    /// @param dest  Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — check with \c .has_value().
    /// @see X.690 §8 — BER decoding rules.
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        Asn1Object* dest) const override;

    /// @brief Decode from a raw value byte span (tag and length already consumed).
    /// Useful when the caller has already parsed the outer TLV and holds only
    /// the value bytes.
    /// @param value  Raw value bytes (no tag, no length prefix).
    /// @param def    TypeDescriptor of the expected type.
    /// @param dest   Pre-allocated, default-constructed target object.
    /// @param constructed  The consumed tag's constructed bit: a string type
    ///               then joins the segments of its constructed form
    ///               (\c IBerTypeHandler::decode_constructed_value).
    /// @return \c DecodeResult — check with \c .has_value(). On success the
    ///         value is checked against \p def's constraints, as decode() does.
    /// @see X.690 §8.14.3 — an IMPLICIT tag replaces the identifier only, so
    ///      the contents decode (and constraints) are the underlying type's.
    DecodeResult decode_value(std::span<const uint8_t> value,
                              const TypeDescriptor& def,
                              Asn1Object* dest,
                              bool constructed = false) const;

    /// @brief \c decode_value() over a reader holding exactly the value's
    ///        contents, so a nested IMPLICIT-tagged member keeps the decode
    ///        nesting depth (\c DecodeDepth) of the reader it came from.
    ///        Counts one nesting level for a constructed \p def, as
    ///        \c decode() does.
    /// @param content  Typically \c r.sub(tlv.value) after reading the
    ///                 member's IMPLICIT tag from \c r.
    /// @param constructed  That IMPLICIT tag's constructed bit: a string
    ///                 type then joins the segments of its constructed form
    ///                 (\c IBerTypeHandler::decode_constructed_value).
    /// @param def      Descriptor of the value's type.
    /// @param dest     Pre-allocated, default-constructed target object.
    /// @return \c DecodeResult — check with \c .has_value().
    DecodeResult decode_value(BerReader& content,
                              const TypeDescriptor& def,
                              Asn1Object* dest,
                              bool constructed = false) const;

private:
    static const IBerTypeHandler* const comp_dispatch_[6];   // indexed by (int)TypeKind
    static const IBerTypeHandler* const prim_dispatch_[32];  // indexed by tag.number
};

} // namespace asn1
