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
// Per-type handler interface — one singleton per type, per codec

class BerCodec;

struct IBerTypeHandler {
    virtual ~IBerTypeHandler() = default;
    virtual void encode(const BerCodec& codec, BerWriter& w,
                        const TypeDescriptor& def, const void* src) const = 0;
    virtual DecodeResult decode(const BerCodec& codec, BerReader& r,
                                const TypeDescriptor& def, void* dest) const = 0;
    // Decode from raw value bytes (tag+length already consumed by caller).
    // Default: re-tags and calls decode(). Override for zero-alloc fast paths.
    virtual DecodeResult decode_value(const BerCodec& codec,
                                      std::span<const uint8_t> value,
                                      const TypeDescriptor& def,
                                      void* dest) const;
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

    DecodeResult decode_value(std::span<const uint8_t> value,
                              const TypeDescriptor& def,
                              void* dest) const;

private:
    static const IBerTypeHandler* const comp_dispatch_[6];   // indexed by (int)TypeKind
    static const IBerTypeHandler* const prim_dispatch_[32];  // indexed by tag.number
};

} // namespace asn1
