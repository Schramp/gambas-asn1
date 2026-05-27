#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/BerHandlers.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/codec/Debug.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/OctetString.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Real.hpp>
#include <asn1cpp/types/BitString.hpp>
#include <asn1cpp/types/Oid.hpp>
#include <asn1cpp/types/Time.hpp>
#include <asn1cpp/types/Strings.hpp>
#include <asn1cpp/codec/Validation.hpp>
#ifdef ASN1CPP_VALIDATE
#include <asn1cpp/Validate.hpp>
#endif

namespace asn1 {

namespace {

static const char* tag_cls_char(TagClass cls) {
    switch (cls) {
        case TagClass::Universal:   return "U";
        case TagClass::Application: return "A";
        case TagClass::Context:     return "C";
        case TagClass::Private:     return "P";
    }
    return "?";
}

static void dbg_write_tag(const char* parent, const char* member, const Tag& t,
                          bool is_explicit, std::size_t value_bytes) {
    std::fprintf(stderr, "[BER-WRITE] %s.%s tag=%s%u %s %zu bytes\n",
        parent, member,
        tag_cls_char(t.cls), t.number,
        is_explicit ? "EXPLICIT" : "IMPLICIT",
        value_bytes);
}

// ---------------------------------------------------------------------------
// Static helpers (shared by handler classes below)

static void ber_encode_implicit_tagged(const BerCodec& codec, BerWriter& w,
                                       uint32_t ctx_tag_number,
                                       const TypeDescriptor& mdef, const Asn1Object* mptr,
                                       const char* parent_name, const char* member_name) {
    std::vector<uint8_t> tmp;
    { BerWriter bw{tmp}; BerEncodeStream ms{bw}; codec.encode(ms, mdef, mptr); }
    BerReader br{tmp};
    auto tlv = br.read_tlv();
    if (!tlv) return;
    Tag ctx{TagClass::Context, ctx_tag_number, mdef.tag.constructed};
    if (debug_flags() & DBG_BER_WRITE)
        dbg_write_tag(parent_name, member_name, ctx, false, tlv->value.size());
    w.write_tag(ctx);
    w.write_length(tlv->value.size());
    w.append(tlv->value);
}

static void ber_encode_explicit_tagged(const BerCodec& codec, BerWriter& w,
                                       const Tag& ctx_tag,
                                       const TypeDescriptor& mdef, const Asn1Object* mptr) {
    w.write_constructed(ctx_tag, [&](BerWriter& w2) {
        BerEncodeStream ms{w2};
        codec.encode(ms, mdef, mptr);
    });
}

// ---------------------------------------------------------------------------
// Handler classes

struct ErrorBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter&,
                const TypeDescriptor& def, const Asn1Object*) const override {
        std::fprintf(stderr, "BerCodec: unreachable dispatch for type '%s'\n", def.name);
        assert(false && "BerCodec: unreachable dispatch table entry");
    }
    DecodeResult decode(const BerCodec&, BerReader&,
                        const TypeDescriptor& def, Asn1Object*) const override {
        assert(false && "BerCodec: unreachable dispatch table entry");
        return decode_err(DecodeError(std::string("BerCodec: unsupported: ") + def.name));
    }
};

struct BooleanBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<Boolean>::encode(w, *static_cast<const Boolean*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Boolean>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Boolean*>(dest) = *v;
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        if (value.empty()) return decode_err(DecodeError("BOOLEAN: empty value"));
        *static_cast<Boolean*>(dest) = Boolean(value[0] != 0);
        return decode_ok();
    }
};

struct IntegerBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        int64_t v = static_cast<const Integer*>(src)->value();
        auto bytes = detail::encode_integer_bytes(v);
        w.write_primitive(def.tag, std::span<const uint8_t>(bytes.data(), bytes.size()));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        return decode_value_impl(tlv->value, dest);
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        return decode_value_impl(value, dest);
    }
private:
    static DecodeResult decode_value_impl(std::span<const uint8_t> value, Asn1Object* dest) {
        auto v = BerTraits<Integer>::decode_value(value);
        if (!v) return decode_err(v.error());
        static_cast<Integer*>(dest)->set(v->value());
        return decode_ok();
    }
};

struct UIntegerBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<UInteger>::encode(w, *static_cast<const UInteger*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        return decode_value_impl(tlv->value, dest);
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        return decode_value_impl(value, dest);
    }
private:
    static DecodeResult decode_value_impl(std::span<const uint8_t> value, Asn1Object* dest) {
        auto v = BerTraits<UInteger>::decode_value(value);
        if (!v) return decode_err(v.error());
        static_cast<UInteger*>(dest)->set(v->value());
        return decode_ok();
    }
};

struct NullBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object*) const override {
        w.write_primitive(def.tag, {});
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor& def, Asn1Object*) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t>,
                              const TypeDescriptor&, Asn1Object*) const override {
        return decode_ok();
    }
};

struct RealBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<Real>::encode(w, *static_cast<const Real*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Real>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Real*>(dest) = *v;
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Real>::decode_value(value);
        if (!v) return decode_err(v.error());
        *static_cast<Real*>(dest) = *v;
        return decode_ok();
    }
};

struct BitStringBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<BitString>::encode(w, *static_cast<const BitString*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<BitString>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<BitString*>(dest) = std::move(*v);
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<BitString>::decode_value(value);
        if (!v) return decode_err(v.error());
        *static_cast<BitString*>(dest) = std::move(*v);
        return decode_ok();
    }
};

struct OctetStringBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<OctetString>::encode(w, *static_cast<const OctetString*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        static_cast<OctetString*>(dest)->set(tlv->value);
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        static_cast<OctetString*>(dest)->set(value);
        return decode_ok();
    }
};

struct OidBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<Oid>::encode(w, *static_cast<const Oid*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Oid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<Oid*>(dest) = std::move(*v);
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Oid>::decode_value(value);
        if (!v) return decode_err(v.error());
        *static_cast<Oid*>(dest) = std::move(*v);
        return decode_ok();
    }
};

struct RelOidBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        BerTraits<RelativeOid>::encode(w, *static_cast<const RelativeOid*>(src));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<RelativeOid>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<RelativeOid*>(dest) = std::move(*v);
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<RelativeOid>::decode_value(value);
        if (!v) return decode_err(v.error());
        *static_cast<RelativeOid*>(dest) = std::move(*v);
        return decode_ok();
    }
};

struct UtcTimeBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& s = static_cast<const AsnStringBase*>(src)->str();
        w.write_primitive(def.tag, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size());
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(value.data()), value.size());
        return decode_ok();
    }
};

struct GenTimeBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& s = static_cast<const AsnStringBase*>(src)->str();
        w.write_primitive(def.tag, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size());
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(value.data()), value.size());
        return decode_ok();
    }
};

struct AsnStringBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& s = static_cast<const AsnStringBase*>(src)->str();
        w.write_primitive(def.tag, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for string type")));
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(tlv->value.data()), tlv->value.size());
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        static_cast<AsnStringBase*>(dest)->str().assign(
            reinterpret_cast<const char*>(value.data()), value.size());
        return decode_ok();
    }
};

struct AnyBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor&, const Asn1Object* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        w.append(v.bytes());
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor&, Asn1Object* dest) const override {
        // ANY content may be empty or contain multiple TLVs — consume all remaining bytes.
        std::size_t n = r.remaining();
        auto raw = r.read_bytes(n);
        if (!raw) return decode_err(raw.error());
        *static_cast<OctetString*>(dest) = OctetString(std::vector<uint8_t>(raw->begin(), raw->end()));
        return decode_ok();
    }
};

struct EnumeratedBerHandler final : IBerTypeHandler {
    void encode(const BerCodec&, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        long v = static_cast<const EnumValue*>(src)->value();
        auto bytes = detail::encode_integer_bytes(v);
        w.write_primitive(def.tag, std::span<const uint8_t>(bytes.data(), bytes.size()));
    }
    DecodeResult decode(const BerCodec&, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        if (tlv->tag != def.tag)
            return decode_err(DecodeError(std::string("wrong tag for ") + def.name));
        auto v = BerTraits<Integer>::decode_value(tlv->value);
        if (!v) return decode_err(v.error());
        static_cast<EnumValue*>(dest)->set(static_cast<long>(v->value()));
        return decode_ok();
    }
    DecodeResult decode_value(const BerCodec&, std::span<const uint8_t> value,
                              const TypeDescriptor&, Asn1Object* dest) const override {
        auto v = BerTraits<Integer>::decode_value(value);
        if (!v) return decode_err(v.error());
        static_cast<EnumValue*>(dest)->set(static_cast<long>(v->value()));
        return decode_ok();
    }
};

struct SeqOfBerHandler final : IBerTypeHandler {
    void encode(const BerCodec& codec, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.seq_of_spec;
        const auto& seq  = *static_cast<const SeqOfBase*>(src);
        std::size_t count = seq.count();
        const auto& edef = *spec.element;
        bool is_set_of = (def.tag.cls == TagClass::Universal &&
                          def.tag.number == UniversalTag::Set);
        if (debug_flags() & DBG_BER_WRITE)
            std::fprintf(stderr, "[BER-WRITE] %s %s %zu elements of %s\n",
                         def.name, is_set_of ? "SET-OF" : "SEQUENCE-OF",
                         count, edef.name);
        w.write_constructed(def.tag, [&](BerWriter& inner) {
            if (is_set_of && count > 1) {
                std::vector<std::vector<uint8_t>> bufs;
                bufs.reserve(count);
                for (std::size_t i = 0; i < count; ++i) {
                    const Asn1Object* eptr = seq.get_const(i);
                    ValidatePathScope _vps{i};
                    std::vector<uint8_t> tmp;
                    BerWriter ew{tmp};
                    BerEncodeStream es{ew};
                    codec.encode(es, edef, eptr);
                    bufs.push_back(std::move(tmp));
                }
                std::sort(bufs.begin(), bufs.end());
                for (auto& b : bufs) inner.append(b);
                return;
            }
            for (std::size_t i = 0; i < count; ++i) {
                const Asn1Object* eptr = seq.get_const(i);
                ValidatePathScope _vps{i};
                BerEncodeStream es{inner};
                codec.encode(es, edef, eptr);
            }
        });
    }
    DecodeResult decode(const BerCodec& codec, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        return decode_body(codec, r.sub(tlv->value), def, dest);
    }
    DecodeResult decode_value(const BerCodec& codec, std::span<const uint8_t> value,
                              const TypeDescriptor& def, Asn1Object* dest) const override {
        BerReader inner{value};
        return decode_body(codec, inner, def, dest);
    }
private:
    static DecodeResult decode_body(const BerCodec& codec, BerReader inner,
                                    const TypeDescriptor& def, Asn1Object* dest) {
        const auto& spec = *def.seq_of_spec;
        const auto& edef = *spec.element;
        SeqOfBase& seq   = *static_cast<SeqOfBase*>(dest);
        std::size_t old_size = seq.count();
        std::size_t count = 0;
        while (!inner.at_end()) {
            if (count >= old_size) {
                seq.resize(count + 1);
                ++old_size;
            }
            Asn1Object* eptr = seq.get_mut(count);
            ValidatePathScope _vps{count};
            BerDecodeStream es{inner};
            auto res = codec.decode(es, edef, eptr);
            if (!res) return res;
            ++count;
        }
        if (count < old_size)
            seq.resize(count);
        return decode_ok();
    }
};

struct SequenceBerHandler final : IBerTypeHandler {
    void encode(const BerCodec& codec, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.sequence_spec;
        w.write_constructed(def.tag, [&](BerWriter& inner) {
            for (int i = 0; i < spec.count; ++i) {
                const auto& mbr = spec.members[i];
                if (!mbr.type_descriptor) continue;
                if (mbr.optional && !mbr.optional_ops.is_present(src)) {
                    if (debug_flags() & DBG_BER_WRITE)
                        std::fprintf(stderr, "[BER-WRITE] %s.%s absent (optional)\n",
                                     def.name, mbr.name);
                    continue;
                }
                if (mbr.is_default_equal && mbr.is_default_equal(src)) {
                    if (debug_flags() & DBG_BER_WRITE)
                        std::fprintf(stderr, "[BER-WRITE] %s.%s suppressed (== DEFAULT)\n",
                                     def.name, mbr.name);
                    continue;
                }
                if (!mbr.optional && mbr.optional_ops && !mbr.optional_ops.is_present(src)) {
                    std::fprintf(stderr, "BerCodec: mandatory member '%s.%s' is null (not filled)\n",
                                 def.name, mbr.name);
                    return;
                }
                const Asn1Object* mptr = mbr.optional_ops.member_ptr(src, mbr.offset);
                const auto& mdef = *mbr.type_descriptor;
                ValidatePathScope _vps{mbr.name};

                if (mbr.tag.cls == TagClass::Context) {
                    if (mbr.is_explicit) {
                        Tag exp_tag{mbr.tag.cls, mbr.tag.number, true};
                        if (debug_flags() & DBG_BER_WRITE)
                            std::fprintf(stderr, "[BER-WRITE] %s.%s tag=C%u EXPLICIT\n",
                                         def.name, mbr.name, mbr.tag.number);
                        ber_encode_explicit_tagged(codec, inner, exp_tag, mdef, mptr);
                    } else {
                        ber_encode_implicit_tagged(codec, inner, mbr.tag.number, mdef, mptr,
                                                   def.name, mbr.name);
                    }
                } else {
                    if (debug_flags() & DBG_BER_WRITE)
                        std::fprintf(stderr, "[BER-WRITE] %s.%s untagged type=%s\n",
                                     def.name, mbr.name, mdef.name);
                    BerEncodeStream ms{inner};
                    codec.encode(ms, mdef, mptr);
                }
            }
        });
    }
    DecodeResult decode(const BerCodec& codec, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        auto tlv = r.read_tlv();
        if (!tlv) return decode_err(tlv.error());
        return decode_body(codec, r.sub(tlv->value), def, dest);
    }
    DecodeResult decode_value(const BerCodec& codec, std::span<const uint8_t> value,
                              const TypeDescriptor& def, Asn1Object* dest) const override {
        BerReader inner{value};
        return decode_body(codec, inner, def, dest);
    }
private:
    static DecodeResult decode_body(const BerCodec& codec, BerReader inner,
                                    const TypeDescriptor& def, Asn1Object* dest) {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) {
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
                bool present;
                if (inner.at_end()) {
                    present = false;
                } else if (mbr.type_descriptor->choice_spec
                           && mbr.tag.cls == TagClass::Universal
                           && mbr.tag.number == 0) {
                    const auto& cspec = *mbr.type_descriptor->choice_spec;
                    present = false;
                    if (cspec.ber_tags && cspec.ber_tag_count > 0) {
                        for (int j = 0; j < cspec.ber_tag_count; ++j) {
                            if (pt.cls == cspec.ber_tags[j].tag.cls
                                && pt.number == cspec.ber_tags[j].tag.number) {
                                present = true; break;
                            }
                        }
                    } else {
                        for (int j = 0; j < cspec.count; ++j) {
                            if (pt.cls == cspec.alternatives[j].tag.cls
                                && pt.number == cspec.alternatives[j].tag.number) {
                                present = true; break;
                            }
                        }
                    }
                } else {
                    present = pt.cls == mbr.tag.cls && pt.number == mbr.tag.number;
                }
                mbr.optional_ops.set_present(dest, present);
                if (!present) {
                    if (mbr.set_default) mbr.set_default(dest);
                    continue;
                }
            }
            Asn1Object* mptr = mbr.optional_ops.member_ptr(dest, mbr.offset);
            const auto& mdef = *mbr.type_descriptor;
            ValidatePathScope _vps{mbr.name};

            if (mbr.tag.cls == TagClass::Context) {
                auto outer = inner.read_tlv();
                if (!outer) return decode_err(outer.error());
                if (mbr.is_explicit) {
                    if (debug_flags() & DBG_BER_SEQ)
                        std::fprintf(stderr,
                            "[SEQ-EXPL] %s.%s outer_tag=cls%d.num%u outer_val[0]=%02x\n",
                            def.name, mbr.name, (int)outer->tag.cls, outer->tag.number,
                            outer->value.empty() ? 0xff : (unsigned)outer->value[0]);
                    BerReader inner2 = inner.sub(outer->value);
                    BerDecodeStream ms{inner2};
                    auto ok = codec.decode(ms, mdef, mptr);
                    if (!ok) return ok;
                } else {
                    auto ok = codec.decode_value(outer->value, mdef, mptr);
                    if (!ok) return ok;
                }
            } else {
                BerDecodeStream ms{inner};
                auto ok = codec.decode(ms, mdef, mptr);
                if (!ok) return ok;
            }
        }
        return decode_ok();
    }
};

struct ChoiceBerHandler final : IBerTypeHandler {
    void encode(const BerCodec& codec, BerWriter& w,
                const TypeDescriptor& def, const Asn1Object* src) const override {
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = static_cast<const ChoiceInterface*>(src);
        int idx = ch->_present;
        if (idx <= 0 || idx > spec.count) {
            if (debug_flags() & DBG_BER_WRITE)
                std::fprintf(stderr, "[BER-WRITE] %s CHOICE idx=%d out of range (count=%d)\n",
                             def.name, idx, spec.count);
            return;
        }
        const auto& alt = spec.alternatives[idx - 1];
        if (!alt.type_descriptor) return;
        const Asn1Object* mptr = alt.get_const_fn(const_cast<Asn1Object*>(src));
        const auto& mdef = *alt.type_descriptor;
        ValidatePathScope _vps{alt.name};

        if (alt.tag.cls == TagClass::Context) {
            if (alt.is_explicit) {
                Tag exp_tag{alt.tag.cls, alt.tag.number, true};
                if (debug_flags() & DBG_BER_WRITE)
                    std::fprintf(stderr, "[BER-WRITE] %s CHOICE alt[%d]=%s tag=C%u EXPLICIT\n",
                                 def.name, idx - 1, alt.name, alt.tag.number);
                ber_encode_explicit_tagged(codec, w, exp_tag, mdef, mptr);
            } else {
                ber_encode_implicit_tagged(codec, w, alt.tag.number, mdef, mptr,
                                           def.name, alt.name);
            }
        } else {
            if (debug_flags() & DBG_BER_WRITE)
                std::fprintf(stderr, "[BER-WRITE] %s CHOICE alt[%d]=%s untagged type=%s\n",
                             def.name, idx - 1, alt.name, mdef.name);
            BerEncodeStream ms{w};
            codec.encode(ms, mdef, mptr);
        }
    }
    DecodeResult decode(const BerCodec& codec, BerReader& r,
                        const TypeDescriptor& def, Asn1Object* dest) const override {
        const auto& spec = *def.choice_spec;
        ChoiceInterface* ch = static_cast<ChoiceInterface*>(dest);
        Tag peek = r.peek_tag();

        if (spec.tag_index && peek.cls == TagClass::Context) {
            int rel = (int)peek.number - spec.tag_index_base;
            int matched = (rel >= 0 && rel < spec.tag_index_size) ? spec.tag_index[rel] : -1;
            if (matched >= 0) {
                const auto& alt = spec.alternatives[matched];
                if (ch->_present != matched + 1) {
                    ch->emplace_alt(alt);
                }
                Asn1Object* mptr = alt.get_mut_fn(ch);
                const auto& mdef = *alt.type_descriptor;
                ValidatePathScope _vps{alt.name};
                DecodeResult ok = decode_ok();
                if (alt.tag.cls == TagClass::Context) {
                    auto outer = r.read_tlv();
                    if (!outer) return decode_err(outer.error());
                    if (alt.is_explicit) {
                        BerReader inner2 = r.sub(outer->value);
                        BerDecodeStream ms{inner2};
                        ok = codec.decode(ms, mdef, mptr);
                    } else {
                        ok = codec.decode_value(outer->value, mdef, mptr);
                    }
                } else {
                    BerDecodeStream ms{r};
                    ok = codec.decode(ms, mdef, mptr);
                }
                if (!ok) return ok;
                ch->_present = matched + 1;
                return decode_ok();
            }
            goto no_match;
        }

        if (spec.ber_tags) {
            int matched = -1;
            for (int j = 0; j < spec.ber_tag_count; ++j) {
                if (peek.cls == spec.ber_tags[j].tag.cls &&
                    peek.number == spec.ber_tags[j].tag.number) {
                    matched = spec.ber_tags[j].alt_index;
                    break;
                }
            }
            if (matched >= 0) {
                const auto& alt = spec.alternatives[matched];
                if (ch->_present != matched + 1) {
                    ch->emplace_alt(alt);
                }
                Asn1Object* mptr = alt.get_mut_fn(ch);
                const auto& mdef = *alt.type_descriptor;
                ValidatePathScope _vps{alt.name};
                DecodeResult ok = decode_ok();
                if (alt.tag.cls == TagClass::Context) {
                    auto outer = r.read_tlv();
                    if (!outer) return decode_err(outer.error());
                    if (alt.is_explicit) {
                        BerReader inner2 = r.sub(outer->value);
                        BerDecodeStream ms{inner2};
                        ok = codec.decode(ms, mdef, mptr);
                    } else {
                        ok = codec.decode_value(outer->value, mdef, mptr);
                    }
                } else {
                    BerDecodeStream ms{r};
                    ok = codec.decode(ms, mdef, mptr);
                }
                if (!ok) return ok;
                ch->_present = matched + 1;
                return decode_ok();
            }
            goto no_match;
        }

        for (int i = 0; i < spec.count; ++i) {
            const auto& alt = spec.alternatives[i];
            if (!alt.type_descriptor) continue;
            if (peek.cls != alt.tag.cls || peek.number != alt.tag.number) continue;
            if (ch->_present != i + 1) {
                ch->emplace_alt(alt);
            }
            Asn1Object* mptr = alt.get_mut_fn(ch);
            const auto& mdef = *alt.type_descriptor;
            ValidatePathScope _vps{alt.name};
            DecodeResult ok = decode_ok();
            if (alt.tag.cls == TagClass::Context) {
                auto outer = r.read_tlv();
                if (!outer) return decode_err(outer.error());
                if (alt.is_explicit) {
                    BerReader inner2 = r.sub(outer->value);
                    BerDecodeStream ms{inner2};
                    ok = codec.decode(ms, mdef, mptr);
                } else {
                    ok = codec.decode_value(outer->value, mdef, mptr);
                }
            } else {
                BerDecodeStream ms{r};
                ok = codec.decode(ms, mdef, mptr);
            }
            if (!ok) return ok;
            ch->_present = i + 1;
            return decode_ok();
        }

        no_match:
        if (spec.ext_at >= 0) {
            if (debug_flags() & DBG_BER_CHOICE)
                std::fprintf(stderr,
                    "[CHOICE-EXT-SKIP] %s: unknown extension cls=%d num=%u — skipping\n",
                    def.name, (int)peek.cls, peek.number);
            auto skipped = r.read_tlv();
            if (!skipped) return decode_err(skipped.error());
            return decode_ok();
        }
        if (debug_flags() & DBG_BER_CHOICE) {
            std::fprintf(stderr, "[CHOICE-MISS] %s: peek cls=%d num=%u; alternatives:",
                def.name, (int)peek.cls, peek.number);
            for (int i = 0; i < spec.count; ++i)
                std::fprintf(stderr, " [%d]%u",
                    (int)spec.alternatives[i].tag.cls, spec.alternatives[i].tag.number);
            std::fprintf(stderr, "\n");
        }
        return decode_err(DecodeError(
            std::string("BerCodec: no matching CHOICE alternative for ") + def.name));
    }
    DecodeResult decode_value(const BerCodec& codec, std::span<const uint8_t> value,
                              const TypeDescriptor& def, Asn1Object* dest) const override {
        BerReader r{value};
        return decode(codec, r, def, dest);
    }
};

// ---------------------------------------------------------------------------
// Singletons — one per handler class, const and globally alive

static const ErrorBerHandler       s_error;
static const BooleanBerHandler     s_boolean;
static const IntegerBerHandler     s_integer;
static const UIntegerBerHandler    s_uinteger;
static const NullBerHandler        s_null;
static const RealBerHandler        s_real;
static const BitStringBerHandler   s_bitstring;
static const OctetStringBerHandler s_octetstring;
static const OidBerHandler         s_oid;
static const RelOidBerHandler      s_reloid;
static const UtcTimeBerHandler     s_utctime;
static const GenTimeBerHandler     s_gentime;
static const AsnStringBerHandler   s_string;
static const AnyBerHandler         s_any;
static const EnumeratedBerHandler  s_enumerated;
static const SeqOfBerHandler       s_seqof;
static const SequenceBerHandler    s_sequence;
static const ChoiceBerHandler      s_choice;

} // anonymous namespace

// Named handler references — used by generated .cpp files via BerHandlers.hpp.
const IBerTypeHandler& ber_any_handler        = s_any;
const IBerTypeHandler& ber_boolean_handler    = s_boolean;
const IBerTypeHandler& ber_integer_handler    = s_integer;
const IBerTypeHandler& ber_uinteger_handler   = s_uinteger;
const IBerTypeHandler& ber_null_handler       = s_null;
const IBerTypeHandler& ber_real_handler       = s_real;
const IBerTypeHandler& ber_bitstring_handler  = s_bitstring;
const IBerTypeHandler& ber_octetstring_handler= s_octetstring;
const IBerTypeHandler& ber_oid_handler        = s_oid;
const IBerTypeHandler& ber_reloid_handler     = s_reloid;
const IBerTypeHandler& ber_utctime_handler    = s_utctime;
const IBerTypeHandler& ber_gentime_handler    = s_gentime;
const IBerTypeHandler& ber_string_handler     = s_string;
const IBerTypeHandler& ber_enumerated_handler = s_enumerated;
const IBerTypeHandler& ber_seqof_handler      = s_seqof;
const IBerTypeHandler& ber_sequence_handler   = s_sequence;
const IBerTypeHandler& ber_choice_handler     = s_choice;

// ---------------------------------------------------------------------------
// IBerTypeHandler default decode_value — re-tag and call decode()
// Defined outside anonymous namespace; needs BerWriter/BerReader.

DecodeResult IBerTypeHandler::decode_value(const BerCodec& codec,
                                            std::span<const uint8_t> value,
                                            const TypeDescriptor& def,
                                            Asn1Object* dest) const {
    std::vector<uint8_t> retagged;
    { BerWriter bw{retagged}; bw.write_tag(def.tag); bw.write_length(value.size()); }
    retagged.insert(retagged.end(), value.begin(), value.end());
    BerReader r{retagged};
    BerDecodeStream s{r};
    return codec.decode(s, def, dest);
}

// ---------------------------------------------------------------------------
// Dispatch tables

const IBerTypeHandler* const BerCodec::comp_dispatch_[6] = {
    &s_error,      // [0] Primitive — routed to prim_dispatch_, never lands here
    &s_any,        // [1] Any
    &s_enumerated, // [2] Enumerated
    &s_sequence,   // [3] Sequence / SET
    &s_choice,     // [4] Choice
    &s_seqof,      // [5] SeqOf / SET OF
};

const IBerTypeHandler* const BerCodec::prim_dispatch_[32] = {
    &s_error,      // [ 0] EndOfContents
    &s_boolean,    // [ 1] Boolean
    &s_integer,    // [ 2] Integer
    &s_bitstring,  // [ 3] BitString
    &s_octetstring,// [ 4] OctetString  (ANY has TypeKind::Any → comp_dispatch_)
    &s_null,       // [ 5] Null
    &s_oid,        // [ 6] OID
    &s_string,     // [ 7] ObjectDescriptor
    &s_error,      // [ 8] External
    &s_real,       // [ 9] Real
    &s_error,      // [10] Enumerated   — TypeKind::Enumerated → comp_dispatch_
    &s_error,      // [11] EmbeddedPdv
    &s_string,     // [12] Utf8String
    &s_reloid,     // [13] RelativeOid
    &s_error,      // [14] (unassigned)
    &s_error,      // [15] (unassigned)
    &s_error,      // [16] Sequence     — TypeKind::Sequence → comp_dispatch_
    &s_error,      // [17] Set          — TypeKind::Sequence → comp_dispatch_
    &s_string,     // [18] NumericString
    &s_string,     // [19] PrintableString
    &s_string,     // [20] T61String
    &s_string,     // [21] VideotexString
    &s_string,     // [22] Ia5String
    &s_utctime,    // [23] UtcTime
    &s_gentime,    // [24] GeneralizedTime
    &s_string,     // [25] GraphicString
    &s_string,     // [26] VisibleString
    &s_string,     // [27] GeneralString
    &s_string,     // [28] UniversalString
    &s_error,      // [29] CharacterString
    &s_string,     // [30] BmpString
    &s_error,      // [31] LongForm
};

// ---------------------------------------------------------------------------
// BerCodec public entry points

void BerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const Asn1Object* src) const
{
#if defined(ASN1CPP_VALIDATE) && defined(ASN1CPP_VALIDATE_ON_ENCODE)
    if (!def.is_any && !(debug_flags() & DBG_NO_VALIDATE)) {
        int64_t delta = validate(def, src);
        if (delta != 0) {
            bump_validate_fail();
            record_validate_fail(def.name, delta, /*on_decode=*/false);
            if (debug_flags() & DBG_BER_WRITE) {
                std::fprintf(stderr,
                    "[BER-WRITE] VALIDATE FAIL %s tag=%s%u delta=%lld\n",
                    def.name,
                    tag_cls_char(def.tag.cls), def.tag.number,
                    static_cast<long long>(delta));
            }
        }
    }
#endif
    auto& s = static_cast<BerEncodeStream&>(dst);
    BerWriter& w = s.writer();
    def.ber_handler->encode(*this, w, def, src);
}

DecodeResult BerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              Asn1Object* dest) const
{
    auto& s = static_cast<BerDecodeStream&>(src);
    BerReader& r = s.reader();
    DecodeResult res = def.ber_handler->decode(*this, r, def, dest);

#if defined(ASN1CPP_VALIDATE) && defined(ASN1CPP_VALIDATE_ON_DECODE)
    if (res.has_value() && !def.is_any && !(debug_flags() & DBG_NO_VALIDATE)) {
        int64_t delta = validate(def, dest);
        if (delta != 0) {
            bump_validate_fail();
            record_validate_fail(def.name, delta, /*on_decode=*/true);
            if (debug_flags() & DBG_BER_WRITE) {
                std::fprintf(stderr,
                    "[BER-READ] VALIDATE FAIL %s tag=%s%u delta=%lld\n",
                    def.name,
                    tag_cls_char(def.tag.cls), def.tag.number,
                    static_cast<long long>(delta));
            }
        }
    }
#endif
    return res;
}

DecodeResult BerCodec::decode_value(std::span<const uint8_t> value,
                                     const TypeDescriptor& def,
                                     Asn1Object* dest) const {
    return def.ber_handler->decode_value(*this, value, def, dest);
}

} // namespace asn1
