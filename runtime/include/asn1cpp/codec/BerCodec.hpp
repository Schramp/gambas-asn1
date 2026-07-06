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
    // Decode from raw value bytes (tag+length already consumed by caller).
    // Default: re-tags and calls decode(). Override for zero-alloc fast paths.
    virtual DecodeResult decode_value(const BerCodec& codec,
                                      std::span<const uint8_t> value,
                                      const TypeDescriptor& def,
                                      Asn1Object* dest) const;
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
    /// @return \c DecodeResult — check with \c .has_value().
    DecodeResult decode_value(std::span<const uint8_t> value,
                              const TypeDescriptor& def,
                              Asn1Object* dest) const;

private:
    static const IBerTypeHandler* const comp_dispatch_[6];   // indexed by (int)TypeKind
    static const IBerTypeHandler* const prim_dispatch_[32];  // indexed by tag.number
};

/// @brief EXPERIMENTAL zero-copy decode toggle (thread-local, default off).
///
/// When enabled, OCTET STRING decode installs a non-owning \c span view into the
/// input buffer instead of copying. The decoded object then borrows from that
/// buffer, which must outlive it — no use-after-free protection. Set around a
/// decode call; the flag propagates through the whole decode tree (unlike a
/// per-reader flag, it reaches the IMPLICIT-member \c decode_value path too).
void set_ber_decode_borrow(bool on);
bool ber_decode_borrow();

} // namespace asn1
