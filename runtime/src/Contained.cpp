#include <asn1cpp/codec/ContainedDecoders.hpp>
#include <cstdio>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/EnumValue.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/Debug.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/Integer.hpp>

namespace asn1 {

namespace {

/// @brief `plain`: the bytes are exactly one value.
ContainedResult decode_plain(const ContainedDecodeArgs& a) {
    return ContainedDecoders::decode_value(a, a.raw, nullptr);
}

/// @brief `zero_padding`: one value, then only 0x00 octets (block-cipher
///        padding). The value is decoded from the whole buffer first and the
///        tail checked afterwards: stripping trailing zeros first would cut a
///        value that legitimately ends in 0x00. A non-zero tail keeps the
///        value and reports it in the message.
ContainedResult decode_zero_padding(const ContainedDecodeArgs& a) {
    std::size_t used = 0;
    auto r = ContainedDecoders::decode_value(a, a.raw, &used);
    if (r.status != ContainedStatus::Decoded) return r;
    for (std::size_t i = used; i < a.raw.size(); ++i)
        if (a.raw[i] != 0)
            return {ContainedStatus::Decoded,
                    "non-zero padding octet at offset " + std::to_string(i) + " of " +
                    std::to_string(a.raw.size())};
    return r;
}

/// @brief `pkcs7`: strip RFC 5652 §6.3 padding (the last octet N, 1..255,
///        repeated N times), then decode the rest as exactly one value.
ContainedResult decode_pkcs7(const ContainedDecodeArgs& a) {
    if (a.raw.empty()) return ContainedResult::failed("PKCS#7: empty contents");
    std::size_t n = a.raw.back();
    if (n == 0 || n > a.raw.size()) return ContainedResult::failed("PKCS#7: bad padding length");
    for (std::size_t i = a.raw.size() - n; i < a.raw.size(); ++i)
        if (a.raw[i] != n) return ContainedResult::failed("PKCS#7: inconsistent padding octets");
    return ContainedDecoders::decode_value(a, a.raw.first(a.raw.size() - n), nullptr);
}

ContainedResult decode_none(const ContainedDecodeArgs&) {
    return ContainedResult::skipped("decoder 'none'");
}

bool encode_plain(const ContainedEncodeArgs& a, std::vector<uint8_t>& out, std::string& err) {
    return ContainedDecoders::encode_value(a, out, err);
}

/// @brief `pkcs7` encode: the value's encoding padded to the registry's
///        block size (RFC 5652 §6.3).
bool encode_pkcs7(const ContainedEncodeArgs& a, std::vector<uint8_t>& out, std::string& err) {
    if (!ContainedDecoders::encode_value(a, out, err)) return false;
    std::size_t bs = a.decoders.pkcs7_block_size;
    if (bs == 0 || bs > 255) { err = "PKCS#7: block size must be 1..255"; return false; }
    std::size_t n = bs - out.size() % bs;
    out.insert(out.end(), n, static_cast<uint8_t>(n));
    return true;
}

/// @brief Read a `when` sibling's value; false when it cannot be read.
bool read_when_value(const ContainedSpec& cs, const Asn1Object* sib, int64_t& v) {
    switch (cs.when_kind) {
    case ContainedSpec::WhenKind::Enumerated: v = static_cast<const EnumValue*>(sib)->value(); return true;
    case ContainedSpec::WhenKind::Integer:    v = static_cast<const Integer*>(sib)->value(); return true;
    case ContainedSpec::WhenKind::UInteger:   v = static_cast<int64_t>(static_cast<const UInteger*>(sib)->value()); return true;
    case ContainedSpec::WhenKind::Boolean:    v = static_cast<const Boolean*>(sib)->value() ? 1 : 0; return true;
    case ContainedSpec::WhenKind::None:       return false;
    }
    return false;
}

ContainedEncoding resolve(ContainedEncoding field, ContainedEncoding outer) {
    return field == ContainedEncoding::Outer ? outer : field;
}

/// @brief Decode one contained field in place.
/// @return false only for a failure on a field with `on_error: fail`.
bool decode_one(const char* field, const ContainedSpec& cs, ContainedBase& cb,
                const Asn1Object* outer, const TypeDescriptor* outer_def,
                ContainedEncoding outer_encoding, const DecodeDepth& depth,
                const ContainedOptions* opts, const char* when_fail, std::string& error) {
    if (cb.status() == ContainedStatus::Decoded && cb.has_value())
        return true;   // decoded from its inline XER/JER form already
    if (!cs.eager || (opts && opts->off)) {
        cb.set_status(ContainedStatus::Skipped, "contained decoding off");
        return true;
    }
    if (when_fail) {
        cb.set_status(ContainedStatus::Skipped, when_fail);
        return true;
    }
    const ContainedDecoders& reg = opts ? opts->registry() : ContainedDecoders::defaults();
    const auto* entry = reg.resolve(cs);
    ContainedResult r;
    if (!entry || !entry->decode) {
        r = ContainedResult::failed(std::string("unknown contained decoder '") + cs.decoder + "'");
    } else {
        Asn1Object* inner = cb.emplace_value_object(*cs.ops);
        ContainedDecodeArgs args{cb.bytes(), cs, *inner, outer, outer_def,
                                 resolve(cs.encoding, outer_encoding), depth, reg, opts};
        r = entry->decode(args);
    }
    if ((debug_flags() & DBG_BER_SEQ) && r.status != ContainedStatus::Decoded)
        std::fprintf(stderr, "[CONTAINED] %s: %s\n", field, r.message.c_str());
    cb.set_status(r.status, r.message);
    if (r.status == ContainedStatus::Failed && cs.fail_on_error) {
        error = std::string(field) + ": " + r.message;
        return false;
    }
    return true;
}

} // namespace

ContainedDecoders::ContainedDecoders() {
    add("plain", decode_plain, encode_plain);
    add("zero_padding", decode_zero_padding, encode_plain);
    add("pkcs7", decode_pkcs7, encode_pkcs7);
    add("none", decode_none);
}

const ContainedDecoders& ContainedDecoders::defaults() {
    static const ContainedDecoders d;
    return d;
}

void ContainedDecoders::add(std::string name, ContainedDecodeFn decode, ContainedEncodeFn encode) {
    auto [it, _] = entries_.insert_or_assign(std::move(name), Entry{std::move(decode), std::move(encode)});
    for (int i = 0; i < kBuiltinCount; ++i)
        if (it->first == kBuiltinNames[i]) builtin_[i] = &it->second;
}

const ContainedDecoders::Entry* ContainedDecoders::resolve(const ContainedSpec& spec) const {
    if (spec.builtin < kBuiltinCount) return builtin_[spec.builtin];
    return find(spec.decoder);
}

const ContainedDecoders::Entry* ContainedDecoders::find(std::string_view name) const {
    auto it = entries_.find(name);
    return it == entries_.end() ? nullptr : &it->second;
}

ContainedResult ContainedDecoders::decode_value(const ContainedDecodeArgs& a,
                                                std::span<const uint8_t> bytes,
                                                std::size_t* consumed) {
    const TypeDescriptor& def = *a.spec.inner_def;
    std::size_t used = 0;
    switch (a.encoding) {
    case ContainedEncoding::Ber:
    case ContainedEncoding::Cer:
    case ContainedEncoding::Der: {
        BerReader r(bytes, a.depth, a.options);
        BerDecodeStream s{r};
        auto ok = BerCodec::instance().decode(s, def, &a.inner);
        if (!ok) return ContainedResult::failed(ok.error().message);
        used = r.pos();
        break;
    }
    case ContainedEncoding::PerUnaligned: {
        PerDecodeStream s(bytes, a.depth, a.options);
        auto ok = PerCodec::instance().decode(s, def, &a.inner);
        if (!ok) return ContainedResult::failed(ok.error().message);
        used = s.bytes_used();
        break;
    }
    case ContainedEncoding::PerAligned:
        return ContainedResult::failed("aligned PER contents are not supported");
    case ContainedEncoding::Outer:
        return ContainedResult::failed("unresolved contents encoding");
    }
    if (consumed) {
        *consumed = used;
    } else if (used < bytes.size()) {
        return ContainedResult::failed(std::to_string(bytes.size() - used) +
                                       " octets after the contained value");
    }
    return ContainedResult::ok();
}

bool ContainedDecoders::encode_value(const ContainedEncodeArgs& a, std::vector<uint8_t>& out,
                                     std::string& error) {
    const TypeDescriptor& def = *a.spec.inner_def;
    switch (a.encoding) {
    case ContainedEncoding::Ber:
    case ContainedEncoding::Cer:
    case ContainedEncoding::Der: {
        BerWriter w(out);
        w.set_contained(a.options);
        BerEncodeStream s{w};
        BerCodec::instance().encode(s, def, &a.inner);
        if (w.encode_failed()) { error = std::string(def.name) + ": BER encode failed"; return false; }
        return true;
    }
    case ContainedEncoding::PerUnaligned: {
        PerEncodeStream s(out);
        s.set_contained(a.options);
        PerCodec::instance().encode(s, def, &a.inner);
        s.flush();
        if (s.encode_failed()) { error = std::string(def.name) + ": PER encode failed"; return false; }
        return true;
    }
    case ContainedEncoding::PerAligned:
        error = "aligned PER contents are not supported";
        return false;
    case ContainedEncoding::Outer:
        error = "unresolved contents encoding";
        return false;
    }
    return false;
}

bool decode_contained_members(const TypeDescriptor& def, Asn1Object* value,
                              ContainedEncoding outer_encoding, const DecodeDepth& depth,
                              const ContainedOptions* opts, std::string& error) {
    const auto& spec = *def.sequence_spec;
    for (int k = 0; k < spec.contained_count; ++k) {
        const auto& mbr = spec.members[spec.contained_members[k]];
        if (!mbr.type_descriptor || !mbr.type_descriptor->contained) continue;
        if (mbr.optional && !mbr.optional_ops.is_present(value)) continue;
        const ContainedSpec& cs = *mbr.type_descriptor->contained;
        auto& cb = *static_cast<ContainedBase*>(mbr.optional_ops.member_ptr(value, mbr.offset));
        const char* when_fail = nullptr;
        std::string when_msg;
        if (cs.when_member >= 0) {
            const auto& sib = spec.members[cs.when_member];
            int64_t v = 0;
            bool present = !sib.optional || sib.optional_ops.is_present(value);
            if (!present || !read_when_value(cs, sib.optional_ops.member_ptr(value, sib.offset), v) ||
                v != cs.when_value) {
                when_msg = std::string("'") + sib.name + "' does not select decoding";
                when_fail = when_msg.c_str();
            }
        }
        if (!decode_one(mbr.name, cs, cb, value, &def, outer_encoding, depth, opts, when_fail, error))
            return false;
    }
    return true;
}

bool decode_contained_alternative(const TypeDescriptor& def, Asn1Object* value,
                                  ContainedEncoding outer_encoding, const DecodeDepth& depth,
                                  const ContainedOptions* opts, std::string& error) {
    const auto& spec = *def.choice_spec;
    const auto* ch = static_cast<const ChoiceInterface*>(value);
    int idx = ch->_present;
    if (idx <= 0 || idx > spec.count) return true;
    const auto& alt = spec.alternatives[idx - 1];
    if (!alt.type_descriptor || !alt.type_descriptor->contained || !alt.get_mut_fn) return true;
    auto& cb = *static_cast<ContainedBase*>(alt.get_mut_fn(value));
    return decode_one(alt.name, *alt.type_descriptor->contained, cb, value, &def, outer_encoding,
                      depth, opts, nullptr, error);
}

std::span<const uint8_t> contained_wire_bytes(const TypeDescriptor& field_def, const ContainedBase& v,
                                              ContainedEncoding outer_encoding,
                                              const ContainedOptions* opts,
                                              std::vector<uint8_t>& scratch, std::string& error) {
    error.clear();
    if (!v.has_value() || !field_def.contained) return v.bytes();
    const ContainedSpec& cs = *field_def.contained;
    // X.682 §11.4: an outer-encoding field's contents follow the encoding
    // being written; bytes known to be in other rules are re-derived.
    bool other_rules = cs.encoding == ContainedEncoding::Outer &&
                       v.raw_encoding() != ContainedEncoding::Outer && v.raw_encoding() != outer_encoding;
    if (!v.dirty() && !other_rules) return v.bytes();
    const ContainedDecoders& reg = opts ? opts->registry() : ContainedDecoders::defaults();
    const auto* entry = reg.resolve(cs);
    std::string err;
    if (entry && entry->encode) {
        ContainedEncodeArgs args{*v.value_object(), cs, resolve(cs.encoding, outer_encoding), reg, opts};
        scratch.clear();
        if (entry->encode(args, scratch, err)) return {scratch.data(), scratch.size()};
    } else {
        err = std::string("decoder '") + cs.decoder + "' cannot encode";
    }
    // A modified value whose bytes cannot be derived must not be written
    // as its stale raw bytes. Unmodified bytes in other rules are kept
    // as they are (a decoder without an encode side, e.g. decryption).
    if (v.dirty()) {
        error = std::string(field_def.name) + ": modified contained value cannot be encoded: " + err;
        return v.bytes();
    }
    if (debug_flags() & DBG_BER_WRITE)
        std::fprintf(stderr, "[CONTAINED] %s: %s; writing the raw bytes\n", field_def.name, err.c_str());
    return v.bytes();
}

} // namespace asn1
