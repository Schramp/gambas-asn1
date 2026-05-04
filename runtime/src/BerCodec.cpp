#include <cstdio>
#include <vector>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/Debug.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/OctetString.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Real.hpp>
#include <asn1cpp/types/BitString.hpp>
#include <asn1cpp/types/Oid.hpp>
#include <asn1cpp/types/Time.hpp>
#include <asn1cpp/types/Strings.hpp>

namespace asn1 {

void BerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const void* src) const
{
    auto& s = static_cast<BerEncodeStream&>(dst);
    if (def.is_any)        { encode_any        (s.writer(), src);       return; }
    if (def.enum_spec)     { encode_enumerated(s.writer(), def, src); return; }
    if (def.sequence_spec) { encode_sequence   (s.writer(), def, src); return; }
    if (def.choice_spec)   { encode_choice     (s.writer(), def, src); return; }
    if (def.seq_of_spec)   { encode_seq_of     (s.writer(), def, src); return; }
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

DecodeResult BerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              void* dest) const
{
    auto& s = static_cast<BerDecodeStream&>(src);
    if (def.is_any)        return decode_any        (s.reader(), dest);
    if (def.enum_spec)     return decode_enumerated(s.reader(), def, dest);
    if (def.sequence_spec) return decode_sequence   (s.reader(), def, dest);
    if (def.choice_spec)   return decode_choice     (s.reader(), def, dest);
    if (def.seq_of_spec)   return decode_seq_of     (s.reader(), def, dest);
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

bool BerCodec::is_boolean_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Boolean;
}
bool BerCodec::is_integer_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
}
bool BerCodec::is_null_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Null;
}
bool BerCodec::is_real_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Real;
}
bool BerCodec::is_bitstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::BitString;
}
bool BerCodec::is_oid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::Oid;
}
bool BerCodec::is_relative_oid_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::RelativeOid;
}
bool BerCodec::is_utctime_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::UtcTime;
}
bool BerCodec::is_generalizedtime_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::GeneralizedTime;
}
bool BerCodec::is_octetstring_tag(const Tag& t) {
    return t.cls == TagClass::Universal && t.number == UniversalTag::OctetString;
}
bool BerCodec::is_primitive_string_tag(const Tag& t) {
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

void BerCodec::encode_integer(BerWriter& w, const TypeDescriptor& def, const void* src) const {
    int64_t v = *static_cast<const int64_t*>(src);
    auto bytes = detail::encode_integer_bytes(v);
    w.write_primitive(def.tag, std::span<const uint8_t>(bytes.data(), bytes.size()));
}
DecodeResult BerCodec::decode_integer(BerReader& r, const TypeDescriptor& def, void* dest) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    if (tlv->tag != def.tag)
        return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
    auto v = BerTraits<Integer>::decode_value(tlv->value);
    if (!v) return decode_err(v.error());
    *static_cast<int64_t*>(dest) = v->value();
    return decode_ok();
}

void BerCodec::encode_any(BerWriter& w, const void* src) const {
    const OctetString& v = *static_cast<const OctetString*>(src);
    w.append(v.bytes());
}
DecodeResult BerCodec::decode_any(BerReader& r, void* dest) const {
    auto raw = r.read_raw_tlv();
    if (!raw) return decode_err(raw.error());
    *static_cast<OctetString*>(dest) = OctetString(*raw);
    return decode_ok();
}

void BerCodec::encode_octetstring(BerWriter& w, const void* src) const {
    BerTraits<OctetString>::encode(w, *static_cast<const OctetString*>(src));
}
DecodeResult BerCodec::decode_octetstring(BerReader& r, void* dest) const {
    auto v = BerTraits<OctetString>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<OctetString*>(dest) = *v;
    return decode_ok();
}

void BerCodec::encode_boolean(BerWriter& w, const void* src) const {
    BerTraits<Boolean>::encode(w, *static_cast<const Boolean*>(src));
}
DecodeResult BerCodec::decode_boolean(BerReader& r, void* dest) const {
    auto v = BerTraits<Boolean>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<Boolean*>(dest) = *v;
    return decode_ok();
}

void BerCodec::encode_null(BerWriter& w, const TypeDescriptor& def) const {
    w.write_primitive(def.tag, {});
}
DecodeResult BerCodec::decode_null(BerReader& r, const TypeDescriptor& def, void*) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    if (tlv->tag != def.tag)
        return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
    return decode_ok();
}

void BerCodec::encode_real(BerWriter& w, const void* src) const {
    BerTraits<Real>::encode(w, *static_cast<const Real*>(src));
}
DecodeResult BerCodec::decode_real(BerReader& r, void* dest) const {
    auto v = BerTraits<Real>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<Real*>(dest) = *v;
    return decode_ok();
}

void BerCodec::encode_bitstring(BerWriter& w, const void* src) const {
    BerTraits<BitString>::encode(w, *static_cast<const BitString*>(src));
}
DecodeResult BerCodec::decode_bitstring(BerReader& r, void* dest) const {
    auto v = BerTraits<BitString>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<BitString*>(dest) = std::move(*v);
    return decode_ok();
}

void BerCodec::encode_oid(BerWriter& w, const void* src) const {
    BerTraits<Oid>::encode(w, *static_cast<const Oid*>(src));
}
DecodeResult BerCodec::decode_oid(BerReader& r, void* dest) const {
    auto v = BerTraits<Oid>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<Oid*>(dest) = std::move(*v);
    return decode_ok();
}

void BerCodec::encode_relative_oid(BerWriter& w, const void* src) const {
    BerTraits<RelativeOid>::encode(w, *static_cast<const RelativeOid*>(src));
}
DecodeResult BerCodec::decode_relative_oid(BerReader& r, void* dest) const {
    auto v = BerTraits<RelativeOid>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<RelativeOid*>(dest) = std::move(*v);
    return decode_ok();
}

void BerCodec::encode_utctime(BerWriter& w, const void* src) const {
    BerTraits<UtcTime>::encode(w, *static_cast<const UtcTime*>(src));
}
DecodeResult BerCodec::decode_utctime(BerReader& r, void* dest) const {
    auto v = BerTraits<UtcTime>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<UtcTime*>(dest) = std::move(*v);
    return decode_ok();
}

void BerCodec::encode_generalizedtime(BerWriter& w, const void* src) const {
    BerTraits<GeneralizedTime>::encode(w, *static_cast<const GeneralizedTime*>(src));
}
DecodeResult BerCodec::decode_generalizedtime(BerReader& r, void* dest) const {
    auto v = BerTraits<GeneralizedTime>::decode(r);
    if (!v) return decode_err(v.error());
    *static_cast<GeneralizedTime*>(dest) = std::move(*v);
    return decode_ok();
}

void BerCodec::encode_asnstring(BerWriter& w, const Tag& tag, const void* src) const {
    auto sv = detail::asnstring_view(src);
    w.write_primitive(tag, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
}
DecodeResult BerCodec::decode_asnstring(BerReader& r, const Tag& expected_tag, void* dest) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    if (tlv->tag != expected_tag)
        return decode_err(DecodeError(std::string("wrong tag for string type")));
    detail::asnstring_assign(dest, std::string_view(
        reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size()));
    return decode_ok();
}

void BerCodec::encode_enumerated(BerWriter& w, const TypeDescriptor& def, const void* src) const {
    long v = *static_cast<const long*>(src);
    auto bytes = detail::encode_integer_bytes(v);
    w.write_primitive(def.tag, std::span<const uint8_t>(bytes.data(), bytes.size()));
}
DecodeResult BerCodec::decode_enumerated(BerReader& r, const TypeDescriptor& def, void* dest) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    if (tlv->tag != def.tag)
        return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
    auto v = BerTraits<Integer>::decode_value(tlv->value);
    if (!v) return decode_err(v.error());
    *static_cast<long*>(dest) = static_cast<long>(v->value());
    return decode_ok();
}

void BerCodec::encode_seq_of(BerWriter& w, const TypeDescriptor& def, const void* src) const {
    const auto& spec = *def.seq_of_spec;
    std::size_t count = spec.count_fn(src);
    const auto& edef = *spec.element;
    w.write_constructed(def.tag, [&](BerWriter& inner) {
        for (std::size_t i = 0; i < count; ++i) {
            const void* eptr = spec.get_const_fn(src, i);
            BerEncodeStream es{inner};
            encode(es, edef, eptr);
        }
    });
}
DecodeResult BerCodec::decode_seq_of(BerReader& r, const TypeDescriptor& def, void* dest) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    BerReader inner = r.sub(tlv->value);
    const auto& spec = *def.seq_of_spec;
    const auto& edef = *spec.element;
    std::size_t count = 0;
    while (!inner.at_end()) {
        spec.resize_fn(dest, ++count);
        void* eptr = spec.get_fn(dest, count - 1);
        BerDecodeStream es{inner};
        auto res = decode(es, edef, eptr);
        if (!res) return res;
    }
    return decode_ok();
}

void BerCodec::encode_sequence(BerWriter& w, const TypeDescriptor& def, const void* src) const {
    const auto& spec = *def.sequence_spec;
    w.write_constructed(def.tag, [&](BerWriter& inner) {
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            // For unique_ptr<T> optional members, get_ptr returns T* from the unique_ptr.
            const void* mptr = mbr.optional_ops.get_ptr
                ? mbr.optional_ops.get_ptr(const_cast<void*>(src))
                : static_cast<const char*>(src) + mbr.offset;
            const auto& mdef = *mbr.type_descriptor;

            bool tagged = mbr.tag.cls == TagClass::Context;
            if (tagged) {
                bool is_explicit = mdef.choice_spec != nullptr;
                if (is_explicit) {
                    // EXPLICIT: context tag wraps the full member encoding.
                    inner.write_constructed(mbr.tag, [&](BerWriter& w2) {
                        BerEncodeStream ms2{w2};
                        encode(ms2, mdef, mptr);
                    });
                } else {
                    // IMPLICIT: encode normally to buffer, strip natural tag, re-emit with context tag.
                    std::vector<uint8_t> tmp;
                    { BerWriter bw{tmp}; BerEncodeStream ms{bw}; encode(ms, mdef, mptr); }
                    BerReader br{tmp};
                    auto tlv = br.read_tlv();
                    if (!tlv) return;
                    Tag ctx{TagClass::Context, mbr.tag.number, mdef.tag.constructed};
                    inner.write_tag(ctx);
                    inner.write_length(tlv->value.size());
                    inner.append(tlv->value);
                }
            } else {
                BerEncodeStream ms{inner};
                encode(ms, mdef, mptr);
            }
        }
    });
}

DecodeResult BerCodec::decode_sequence(BerReader& r, const TypeDescriptor& def, void* dest) const {
    auto tlv = r.read_tlv();
    if (!tlv) return decode_err(tlv.error());
    BerReader inner = r.sub(tlv->value);
    const auto& spec = *def.sequence_spec;
    for (int i = 0; i < spec.count; ++i) {
        const auto& mbr = spec.members[i];
        if (!mbr.type_descriptor) {
            // No type descriptor — skip TLV in stream if optional member is present.
            if (mbr.optional && mbr.tag.cls == TagClass::Context) {
                Tag pt = inner.peek_tag();
                if (!inner.at_end() && pt.cls == mbr.tag.cls && pt.number == mbr.tag.number) {
                    auto skip = inner.read_tlv();
                    if (!skip) return decode_err(skip.error());
                }
            }
            continue;
        }
        if (mbr.optional) {
            Tag pt = inner.peek_tag();
            bool present = !inner.at_end() && pt.cls == mbr.tag.cls && pt.number == mbr.tag.number;
            mbr.optional_ops.set_present(dest, present);
            if (!present) continue;
        }
        // For unique_ptr<T> optional members, get_ptr returns T* from the allocated object.
        void* mptr = mbr.optional_ops.get_ptr
            ? mbr.optional_ops.get_ptr(dest)
            : static_cast<char*>(dest) + mbr.offset;
        const auto& mdef = *mbr.type_descriptor;

        bool tagged = mbr.tag.cls == TagClass::Context;
        if (tagged) {
            auto outer = inner.read_tlv();
            if (!outer) return decode_err(outer.error());
            bool is_explicit = mdef.choice_spec != nullptr;
            if (is_explicit) {
                // EXPLICIT: inner bytes contain the full member encoding (with its own tag).
                if (debug_flags() & DBG_BER_SEQ)
                    std::fprintf(stderr, "[SEQ-EXPL] %s.%s outer_tag=cls%d.num%u outer_val[0]=%02x\n",
                        def.name, mbr.name, (int)outer->tag.cls, outer->tag.number,
                        outer->value.empty() ? 0xff : (unsigned)outer->value[0]);
                BerReader inner2 = inner.sub(outer->value);
                BerDecodeStream ms{inner2};
                auto ok = decode(ms, mdef, mptr);
                if (!ok) return ok;
            } else {
                // IMPLICIT: inner bytes are the value; prepend natural type tag.
                std::vector<uint8_t> retagged;
                { BerWriter bw{retagged}; bw.write_tag(mdef.tag); bw.write_length(outer->value.size()); }
                retagged.insert(retagged.end(), outer->value.begin(), outer->value.end());
                BerReader retag_reader{retagged};
                BerDecodeStream ms{retag_reader};
                auto ok = decode(ms, mdef, mptr);
                if (!ok) return ok;
            }
        } else {
            BerDecodeStream ms{inner};
            auto ok = decode(ms, mdef, mptr);
            if (!ok) return ok;
        }
    }
    return decode_ok();
}

void BerCodec::encode_choice(BerWriter& w, const TypeDescriptor& def, const void* src) const {
    const auto& spec = *def.choice_spec;
    int idx = *static_cast<const int*>(src);
    if (idx <= 0 || idx > spec.count) return;
    const auto& alt = spec.alternatives[idx - 1];
    if (!alt.type_descriptor) return;
    const void* mptr = static_cast<const char*>(src) + alt.offset;
    const auto& mdef = *alt.type_descriptor;
    BerEncodeStream ms{w};
    encode(ms, mdef, mptr);
}
DecodeResult BerCodec::decode_choice(BerReader& r, const TypeDescriptor& def, void* dest) const {
    const auto& spec = *def.choice_spec;
    Tag peek = r.peek_tag();
    for (int i = 0; i < spec.count; ++i) {
        const auto& alt = spec.alternatives[i];
        if (!alt.type_descriptor) continue;
        if (peek.cls != alt.tag.cls || peek.number != alt.tag.number) continue;
        void* mptr = static_cast<char*>(dest) + alt.offset;
        const auto& mdef = *alt.type_descriptor;
        DecodeResult ok = decode_ok();
        if (alt.tag.cls == TagClass::Context) {
            // Context-tagged alternative: read the context TLV first.
            auto outer = r.read_tlv();
            if (!outer) return decode_err(outer.error());
            bool is_explicit = mdef.choice_spec != nullptr;
            if (is_explicit) {
                // EXPLICIT: outer value bytes contain the full alternative encoding.
                BerReader inner2 = r.sub(outer->value);
                BerDecodeStream ms{inner2};
                ok = decode(ms, mdef, mptr);
            } else {
                // IMPLICIT: prepend natural type tag so leaf decoders see the right tag.
                std::vector<uint8_t> retagged;
                { BerWriter bw{retagged}; bw.write_tag(mdef.tag); bw.write_length(outer->value.size()); }
                retagged.insert(retagged.end(), outer->value.begin(), outer->value.end());
                BerReader retag_reader{retagged};
                BerDecodeStream ms{retag_reader};
                ok = decode(ms, mdef, mptr);
            }
        } else {
            BerDecodeStream ms{r};
            ok = decode(ms, mdef, mptr);
        }
        if (!ok) return ok;
        *static_cast<int*>(dest) = i + 1;
        return decode_ok();
    }
    // Extensible CHOICE: unknown extension alternative — skip TLV, leave present=NOTHING.
    if (spec.ext_at >= 0) {
        if (debug_flags() & DBG_BER_CHOICE)
            std::fprintf(stderr, "[CHOICE-EXT-SKIP] %s: unknown extension cls=%d num=%u — skipping\n",
                def.name, (int)peek.cls, peek.number);
        auto skipped = r.read_tlv();
        if (!skipped) return decode_err(skipped.error());
        return decode_ok();
    }
    if (debug_flags() & DBG_BER_CHOICE) {
        std::fprintf(stderr, "[CHOICE-MISS] %s: peek cls=%d num=%u; alternatives:",
            def.name, (int)peek.cls, peek.number);
        for (int i = 0; i < spec.count; ++i)
            std::fprintf(stderr, " [%d]%u", (int)spec.alternatives[i].tag.cls, spec.alternatives[i].tag.number);
        std::fprintf(stderr, "\n");
    }
    return decode_err(DecodeError(std::string("BerCodec: no matching CHOICE alternative for ") + def.name));
}

} // namespace asn1
