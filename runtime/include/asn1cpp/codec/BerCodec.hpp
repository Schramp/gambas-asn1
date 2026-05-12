#pragma once
#include <span>
#include "ICodec.hpp"
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "BerTraits.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// BER stream wrappers

class BerEncodeStream : public IEncodeStream {
    BerWriter& w_;
public:
    explicit BerEncodeStream(BerWriter& w) : w_(w) {}
    BerWriter& writer() { return w_; }
};

class BerDecodeStream : public IDecodeStream {
    BerReader& r_;
public:
    explicit BerDecodeStream(BerReader& r) : r_(r) {}
    BerReader& reader() { return r_; }
    bool at_end() const override { return r_.at_end(); }
};

// ---------------------------------------------------------------------------
// BerCodec — generic BER encode/decode driven by TypeDescriptor tables

class BerCodec : public ICodec {
public:
    static BerCodec& instance() {
        static BerCodec inst;
        return inst;
    }

    const char* name() const override { return "BER"; }

    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override;

    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override;

private:
    DecodeResult decode_implicit_member(std::span<const uint8_t> outer_value,
                                        const TypeDescriptor& mdef,
                                        void* mptr) const;
    void encode_implicit_tagged(BerWriter& w, uint32_t ctx_tag_number,
                                const TypeDescriptor& mdef, const void* mptr,
                                const char* parent_name, const char* member_name) const;
    void encode_explicit_tagged(BerWriter& w, const Tag& ctx_tag,
                                const TypeDescriptor& mdef, const void* mptr) const;

    void encode_integer(BerWriter& w, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_integer(BerReader& r, const TypeDescriptor& def, void* dest) const;

    void encode_any(BerWriter& w, const void* src) const;
    DecodeResult decode_any(BerReader& r, void* dest) const;

    void encode_octetstring(BerWriter& w, const void* src) const;
    DecodeResult decode_octetstring(BerReader& r, void* dest) const;

    void encode_boolean(BerWriter& w, const void* src) const;
    DecodeResult decode_boolean(BerReader& r, void* dest) const;

    void encode_null(BerWriter& w, const TypeDescriptor& def) const;
    DecodeResult decode_null(BerReader& r, const TypeDescriptor& def, void* dest) const;

    void encode_real(BerWriter& w, const void* src) const;
    DecodeResult decode_real(BerReader& r, void* dest) const;

    void encode_bitstring(BerWriter& w, const void* src) const;
    DecodeResult decode_bitstring(BerReader& r, void* dest) const;

    void encode_oid(BerWriter& w, const void* src) const;
    DecodeResult decode_oid(BerReader& r, void* dest) const;

    void encode_relative_oid(BerWriter& w, const void* src) const;
    DecodeResult decode_relative_oid(BerReader& r, void* dest) const;

    void encode_utctime(BerWriter& w, const void* src) const;
    DecodeResult decode_utctime(BerReader& r, void* dest) const;

    void encode_generalizedtime(BerWriter& w, const void* src) const;
    DecodeResult decode_generalizedtime(BerReader& r, void* dest) const;

    void encode_asnstring(BerWriter& w, const Tag& tag, const void* src) const;
    DecodeResult decode_asnstring(BerReader& r, const Tag& expected_tag, void* dest) const;

    void encode_enumerated(BerWriter& w, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_enumerated(BerReader& r, const TypeDescriptor& def, void* dest) const;

    void encode_seq_of(BerWriter& w, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_seq_of(BerReader& r, const TypeDescriptor& def, void* dest) const;

    void encode_sequence(BerWriter& w, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_sequence(BerReader& r, const TypeDescriptor& def, void* dest) const;

    void encode_choice(BerWriter& w, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_choice(BerReader& r, const TypeDescriptor& def, void* dest) const;
};

} // namespace asn1
