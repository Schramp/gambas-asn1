#pragma once
#include <span>
#include "ICodec.hpp"
#include "BerWriter.hpp"
#include "BerReader.hpp"
#include "../types/Boolean.hpp"     // BerTraits<Boolean>
#include "../types/OctetString.hpp" // BerTraits<OctetString>
#include "../types/Integer.hpp"     // detail::encode_integer_bytes, BerTraits<Integer>::decode_value
#include "../types/Real.hpp"      // BerTraits<Real>
#include "../types/BitString.hpp" // BerTraits<BitString>
#include "../types/Oid.hpp"       // BerTraits<Oid>, BerTraits<RelativeOid>
#include "../types/Time.hpp"      // BerTraits<UtcTime>, BerTraits<GeneralizedTime>
#include "../types/Strings.hpp"  // AsnString<N>, detail::asnstring_view/assign

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
        if (is_boolean_tag(def.tag))  { encode_boolean (s.writer(), src); return; }
        if (is_integer_tag(def.tag)) { encode_integer(s.writer(), def, src); return; }
        if (is_null_tag(def.tag))    { encode_null   (s.writer(), def);     return; }
        if (is_real_tag(def.tag))       { encode_real     (s.writer(), src); return; }
        if (is_bitstring_tag(def.tag))    { encode_bitstring   (s.writer(), src); return; }
        if (is_oid_tag(def.tag))          { encode_oid         (s.writer(), src); return; }
        if (is_relative_oid_tag(def.tag))     { encode_relative_oid    (s.writer(), src); return; }
        if (is_utctime_tag(def.tag))           { encode_utctime         (s.writer(), src); return; }
        if (is_generalizedtime_tag(def.tag))   { encode_generalizedtime (s.writer(), src); return; }
        if (is_octetstring_tag(def.tag))       { encode_octetstring(s.writer(), src); return; }
        if (is_primitive_string_tag(def.tag))  { encode_asnstring  (s.writer(), def.tag, src); return; }
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
        if (is_boolean_tag(def.tag))  return decode_boolean (s.reader(), dest);
        if (is_integer_tag(def.tag)) return decode_integer(s.reader(), def, dest);
        if (is_null_tag(def.tag))    return decode_null  (s.reader(), def, dest);
        if (is_real_tag(def.tag))       return decode_real     (s.reader(), dest);
        if (is_bitstring_tag(def.tag))    return decode_bitstring   (s.reader(), dest);
        if (is_oid_tag(def.tag))          return decode_oid         (s.reader(), dest);
        if (is_relative_oid_tag(def.tag))     return decode_relative_oid    (s.reader(), dest);
        if (is_utctime_tag(def.tag))           return decode_utctime         (s.reader(), dest);
        if (is_generalizedtime_tag(def.tag))   return decode_generalizedtime (s.reader(), dest);
        if (is_octetstring_tag(def.tag))        return decode_octetstring(s.reader(), dest);
        if (is_primitive_string_tag(def.tag))  return decode_asnstring  (s.reader(), def.tag, dest);
        return decode_err(DecodeError(std::string("BerCodec: no spec for type ") + def.name));
    }

private:
    static bool is_boolean_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Boolean;
    }

    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }

    static bool is_null_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Null;
    }

    static bool is_real_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Real;
    }

    static bool is_bitstring_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::BitString;
    }

    static bool is_oid_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Oid;
    }

    static bool is_relative_oid_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::RelativeOid;
    }

    static bool is_utctime_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::UtcTime;
    }

    static bool is_generalizedtime_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::GeneralizedTime;
    }

    static bool is_octetstring_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::OctetString;
    }

    static bool is_primitive_string_tag(const Tag& t) {
        if (t.cls != TagClass::Universal) return false;
        switch (t.number) {
        case UniversalTag::ObjectDescriptor:
        case UniversalTag::Utf8String:
        case UniversalTag::NumericString:
        case UniversalTag::PrintableString:
        case UniversalTag::T61String:
        case UniversalTag::VideotexString:
        case UniversalTag::Ia5String:
        case UniversalTag::GraphicString:
        case UniversalTag::VisibleString:
        case UniversalTag::GeneralString:
        case UniversalTag::UniversalString:
        case UniversalTag::BmpString:
            return true;
        default: return false;
        }
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

    // ---- OCTET STRING --------------------------------------------------

    void encode_octetstring(BerWriter& w, const void* src) const {
        BerTraits<OctetString>::encode(w, *static_cast<const OctetString*>(src));
    }
    DecodeResult decode_octetstring(BerReader& r, void* dest) const {
        auto v = BerTraits<OctetString>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<OctetString*>(dest) = *v;
        return decode_ok();
    }

    // ---- BOOLEAN -------------------------------------------------------

    void encode_boolean(BerWriter& w, const void* src) const {
        BerTraits<Boolean>::encode(w, *static_cast<const Boolean*>(src));
    }

    DecodeResult decode_boolean(BerReader& r, void* dest) const {
        auto v = BerTraits<Boolean>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Boolean*>(dest) = *v;
        return decode_ok();
    }

    // ---- NULL ----------------------------------------------------------

    void encode_null(BerWriter& w, const TypeDescriptor& def) const {
        w.write_primitive(def.tag, {});
    }

    DecodeResult decode_null(BerReader& r, const TypeDescriptor& def, void* /*dest*/) const {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        return decode_ok();
    }

    // ---- REAL ----------------------------------------------------------

    void encode_real(BerWriter& w, const void* src) const {
        BerTraits<Real>::encode(w, *static_cast<const Real*>(src));
    }

    DecodeResult decode_real(BerReader& r, void* dest) const {
        auto v = BerTraits<Real>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Real*>(dest) = *v;
        return decode_ok();
    }

    // ---- BIT STRING ----------------------------------------------------

    void encode_bitstring(BerWriter& w, const void* src) const {
        BerTraits<BitString>::encode(w, *static_cast<const BitString*>(src));
    }

    DecodeResult decode_bitstring(BerReader& r, void* dest) const {
        auto v = BerTraits<BitString>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<BitString*>(dest) = std::move(*v);
        return decode_ok();
    }

    // ---- OID / RELATIVE-OID --------------------------------------------

    void encode_oid(BerWriter& w, const void* src) const {
        BerTraits<Oid>::encode(w, *static_cast<const Oid*>(src));
    }

    DecodeResult decode_oid(BerReader& r, void* dest) const {
        auto v = BerTraits<Oid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Oid*>(dest) = std::move(*v);
        return decode_ok();
    }

    void encode_relative_oid(BerWriter& w, const void* src) const {
        BerTraits<RelativeOid>::encode(w, *static_cast<const RelativeOid*>(src));
    }

    DecodeResult decode_relative_oid(BerReader& r, void* dest) const {
        auto v = BerTraits<RelativeOid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<RelativeOid*>(dest) = std::move(*v);
        return decode_ok();
    }

    // ---- UTCTime / GeneralizedTime -------------------------------------

    void encode_utctime(BerWriter& w, const void* src) const {
        BerTraits<UtcTime>::encode(w, *static_cast<const UtcTime*>(src));
    }

    DecodeResult decode_utctime(BerReader& r, void* dest) const {
        auto v = BerTraits<UtcTime>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<UtcTime*>(dest) = std::move(*v);
        return decode_ok();
    }

    void encode_generalizedtime(BerWriter& w, const void* src) const {
        BerTraits<GeneralizedTime>::encode(w, *static_cast<const GeneralizedTime*>(src));
    }

    DecodeResult decode_generalizedtime(BerReader& r, void* dest) const {
        auto v = BerTraits<GeneralizedTime>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<GeneralizedTime*>(dest) = std::move(*v);
        return decode_ok();
    }

    // ---- Generic primitive string (AsnString<N>) -----------------------

    void encode_asnstring(BerWriter& w, const Tag& tag, const void* src) const {
        auto sv = detail::asnstring_view(src);
        w.write_primitive(tag, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
    }

    DecodeResult decode_asnstring(BerReader& r, const Tag& expected_tag, void* dest) const {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != expected_tag)
            return decode_err(DecodeError(std::string("wrong tag for string type")));
        detail::asnstring_assign(dest, std::string_view(
            reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size()));
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
        // src points to class { enum class PR : int present; T1 alt1; T2 alt2; ... }
        // PR is at offset 0 with underlying type int.
        const auto& spec = *def.choice_spec;
        int idx = *static_cast<const int*>(src);  // PR value (0 = NOTHING)
        if (idx <= 0 || idx > spec.count) return;
        const auto& alt = spec.alternatives[idx - 1];
        if (!alt.type_descriptor) return;
        const void* mptr = static_cast<const char*>(src) + alt.offset;
        const auto& mdef = *static_cast<const TypeDescriptor*>(alt.type_descriptor);
        BerEncodeStream ms{w};
        encode(ms, mdef, mptr);
    }

    DecodeResult decode_choice(BerReader& r,
                               const TypeDescriptor& def,
                               void* dest) const
    {
        // dest points to class { enum class PR : int present; T1 alt1; T2 alt2; ... }
        // Peek tag to find matching alternative, decode into its named field.
        const auto& spec = *def.choice_spec;
        Tag peek = r.peek_tag();
        for (int i = 0; i < spec.count; ++i) {
            const auto& alt = spec.alternatives[i];
            if (!alt.type_descriptor) continue;
            if (peek != alt.tag) continue;
            void* mptr = static_cast<char*>(dest) + alt.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(alt.type_descriptor);
            BerDecodeStream ms{r};
            auto ok = decode(ms, mdef, mptr);
            if (!ok) return ok;
            *static_cast<int*>(dest) = i + 1;  // set PR present
            return decode_ok();
        }
        return decode_err(DecodeError(std::string("BerCodec: no matching CHOICE alternative for ") + def.name));
    }
};

} // namespace asn1
