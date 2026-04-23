#pragma once
#include <span>
#include "ICodec.hpp"
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "../types/Integer.hpp"   // detail::encode_integer_bytes, BerTraits<Integer>::decode_value

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

    // ------------------------------------------------------------------
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override
    {
        auto& s = static_cast<BerEncodeStream&>(dst);
        if (def.enum_spec)     { encode_enumerated(s.writer(), def, src); return; }
        if (def.sequence_spec) { encode_sequence   (s.writer(), def, src); return; }
        if (def.choice_spec)   { encode_choice     (s.writer(), def, src); return; }
        if (is_integer_tag(def.tag)) { encode_integer(s.writer(), def, src); return; }
    }

    // ------------------------------------------------------------------
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override
    {
        auto& s = static_cast<BerDecodeStream&>(src);
        if (def.enum_spec)     return decode_enumerated(s.reader(), def, dest);
        if (def.sequence_spec) return decode_sequence   (s.reader(), def, dest);
        if (def.choice_spec)   return decode_choice     (s.reader(), def, dest);
        if (is_integer_tag(def.tag)) return decode_integer(s.reader(), def, dest);
        return decode_err(DecodeError(std::string("BerCodec: no spec for type ") + def.name));
    }

private:
    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }

    // ---- INTEGER -------------------------------------------------------

    void encode_integer(BerWriter& w,
                        const TypeDescriptor& def,
                        const void* src) const
    {
        int64_t v = *static_cast<const int64_t*>(src);
        auto bytes = detail::encode_integer_bytes(v);
        w.write_primitive(def.tag, std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    DecodeResult decode_integer(BerReader& r,
                                const TypeDescriptor& def,
                                void* dest) const
    {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        auto v = BerTraits<Integer>::decode_value(tlv->value);
        if (!v) return decode_err(v.error());
        *static_cast<int64_t*>(dest) = v->value();
        return decode_ok();
    }

    // ---- ENUMERATED ----------------------------------------------------

    void encode_enumerated(BerWriter& w,
                           const TypeDescriptor& def,
                           const void* src) const
    {
        long v = *static_cast<const long*>(src);
        auto bytes = detail::encode_integer_bytes(v);
        w.write_primitive(def.tag,
            std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    DecodeResult decode_enumerated(BerReader& r,
                                   const TypeDescriptor& def,
                                   void* dest) const
    {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        auto v = BerTraits<Integer>::decode_value(tlv->value);
        if (!v) return decode_err(v.error());
        *static_cast<long*>(dest) = static_cast<long>(v->value());
        return decode_ok();
    }

    // ---- SEQUENCE / SET ------------------------------------------------

    void encode_sequence(BerWriter& w,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        const auto& spec = *def.sequence_spec;
        w.write_constructed(def.tag, [&](BerWriter& inner) {
            for (int i = 0; i < spec.count; ++i) {
                const auto& mbr = spec.members[i];
                if (!mbr.type_descriptor) continue;
                if (mbr.optional) continue;  // TODO: optional member encode
                const void* mptr = static_cast<const char*>(src) + mbr.offset;
                const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
                BerEncodeStream ms{inner};
                encode(ms, mdef, mptr);
            }
        });
    }

    DecodeResult decode_sequence(BerReader& r,
                                 const TypeDescriptor& def,
                                 void* dest) const
    {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        BerReader inner = r.sub(tlv->value);
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member decode
            void* mptr = static_cast<char*>(dest) + mbr.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            BerDecodeStream ms{inner};
            auto ok = decode(ms, mdef, mptr);
            if (!ok) return ok;
        }
        return decode_ok();
    }

    // ---- CHOICE --------------------------------------------------------

    void encode_choice(BerWriter& w,
                       const TypeDescriptor& def,
                       const void* src) const
    {
        // CHOICE encode: src points to struct { PR present; variant<...> choice; }
        // PR is an int-sized enum at offset 0; the variant follows.
        // Delegate to member's TypeDescriptor based on present index.
        const auto& spec = *def.choice_spec;
        int idx = *static_cast<const int*>(src);  // PR enum value (0 = NOTHING)
        if (idx <= 0 || idx > spec.count) return;
        // variant<monostate, T1, T2, ...> — active alternative at variant index = idx
        // We can't introspect std::variant layout generically here.
        // CHOICE encode is handled by the generated BerTraits (std::visit) for now;
        // this path is reached only when called generically from a SEQUENCE member.
        (void)w; (void)src;
    }

    DecodeResult decode_choice(BerReader& r,
                               const TypeDescriptor& def,
                               void* dest) const
    {
        // CHOICE decode: peek tag, find matching alternative, decode into dest.
        // dest points to struct { PR present; variant<...> choice; }
        // For now stub — CHOICE decode via generated BerTraits handles this.
        (void)r; (void)def; (void)dest;
        return decode_err(DecodeError("BerCodec: generic CHOICE decode not yet implemented"));
    }
};

} // namespace asn1
