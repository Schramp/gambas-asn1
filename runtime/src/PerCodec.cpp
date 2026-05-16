#include <cassert>
#include <algorithm>
#include <cstring>
#include <numeric>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/Alphabets.hpp>
#include <asn1cpp/ChoiceInterface.hpp>

namespace asn1 {

namespace {

// ---------------------------------------------------------------------------
// Utility functions (previously static members of PerCodec)

static void put_nslength(PerEncodeStream& s, std::size_t n) {
    if (n >= 1 && n <= 64) { s.put_bits(0, 1); s.put_bits(n - 1, 6); }
    else { s.put_bits(1, 1); per_detail::put_length(s, n); }
}

static Expected<std::size_t, DecodeError> get_nslength(PerDecodeStream& s) {
    auto b = s.get_bits(1);
    if (!b) return make_unexpected<std::size_t, DecodeError>(b.error());
    if (*b == 0) {
        auto v = s.get_bits(6);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return *v + 1;
    }
    return per_detail::get_length(s);
}

static void put_nsnnwn(PerEncodeStream& s, int n) {
    if (n <= 63) { s.put_bits(0, 1); s.put_bits(static_cast<uint64_t>(n), 6); }
    else { s.put_bits(1, 1); per_detail::put_length(s, static_cast<std::size_t>(n)); }
}

static Expected<int, DecodeError> get_nsnnwn(PerDecodeStream& s) {
    auto b = s.get_bits(1);
    if (!b) return make_unexpected<int, DecodeError>(b.error());
    if (*b == 0) {
        auto v = s.get_bits(6);
        if (!v) return make_unexpected<int, DecodeError>(v.error());
        return static_cast<int>(*v);
    }
    auto len = per_detail::get_length(s);
    if (!len) return make_unexpected<int, DecodeError>(len.error());
    return static_cast<int>(*len);
}

static int range_bits(int64_t range) {
    if (range <= 1) return 0;
    int bits = 0;
    for (int64_t r = range - 1; r > 0; r >>= 1) ++bits;
    return bits;
}

static void encode_size_field(PerEncodeStream& s, const TypeDescriptor& def, std::size_t len) {
    const Constraints& pc = def.constraints;
    bool size_constrained = pc.flags & Constraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        // Fixed SIZE(n): no length field
    } else if (size_constrained) {
        s.put_bits(len - static_cast<std::size_t>(pc.size_lower), pc.size_range_bits);
    } else {
        per_detail::put_length(s, len);
    }
}

static Expected<std::size_t, DecodeError> decode_size_field(PerDecodeStream& s,
                                                             const TypeDescriptor& def) {
    const Constraints& pc = def.constraints;
    bool size_constrained = pc.flags & Constraints::SIZE_CONSTRAINED;
    if (size_constrained && pc.size_range_bits == 0) {
        return static_cast<std::size_t>(pc.size_lower);
    } else if (size_constrained) {
        auto v = s.get_bits(pc.size_range_bits);
        if (!v) return make_unexpected<std::size_t, DecodeError>(v.error());
        return static_cast<std::size_t>(*v) + static_cast<std::size_t>(pc.size_lower);
    } else {
        return per_detail::get_length(s);
    }
}

static void encode_unconstrained_int(PerEncodeStream& s, int64_t value) {
    uint8_t buf[8]; int len = 0;
    if (value == 0) { buf[0] = 0; len = 1; }
    else {
        uint64_t u = static_cast<uint64_t>(value);
        for (int i = 7; i >= 0; --i) { buf[i] = u & 0xFF; u >>= 8; }
        int start = 0;
        if (value > 0) {
            while (start < 7 && buf[start] == 0x00 && !(buf[start+1] & 0x80)) ++start;
        } else {
            while (start < 7 && buf[start] == 0xFF && (buf[start+1] & 0x80)) ++start;
        }
        len = 8 - start;
        std::memmove(buf, buf + start, len);
    }
    s.put_bits(static_cast<uint64_t>(len), 8);
    for (int i = 0; i < len; ++i) s.put_bits(buf[i], 8);
}

static DecodeResult decode_unconstrained_int(PerDecodeStream& s, void* dest) {
    auto len_bits = s.get_bits(8);
    if (!len_bits) return decode_err(len_bits.error());
    int len = static_cast<int>(*len_bits);
    if (len == 0 || len > 8)
        return decode_err(DecodeError("PER: INTEGER length out of range"));
    int64_t value = 0;
    for (int i = 0; i < len; ++i) {
        auto b = s.get_bits(8);
        if (!b) return decode_err(b.error());
        if (i == 0 && (*b & 0x80)) value = -1;
        value = (value << 8) | static_cast<int64_t>(*b);
    }
    *static_cast<int64_t*>(dest) = value;
    return decode_ok();
}

static uint8_t encode_numeric_char(char c) {
    if (c == ' ') return 0;
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 1);
    return 0;
}

static char decode_numeric_char(uint8_t v) {
    if (v == 0) return ' ';
    if (v >= 1 && v <= 10) return static_cast<char>('0' + (v - 1));
    return '?';
}

static uint8_t encode_ps_char(char c) {
    auto a = PRINTABLE_STRING_ALPHABET;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (a[i] == c) return static_cast<uint8_t>(i);
    return 0;
}

static char decode_ps_char(uint8_t v) {
    auto a = PRINTABLE_STRING_ALPHABET;
    return (v < a.size()) ? a[v] : '?';
}

static std::tuple<int,int> string_params(uint32_t tag_num) {
    switch (tag_num) {
        case UniversalTag::NumericString:   return {4, 1};
        case UniversalTag::PrintableString: return {7, 1};
        case UniversalTag::BmpString:       return {8, 2};
        case UniversalTag::UniversalString: return {8, 4};
        case UniversalTag::UtcTime:
        case UniversalTag::GeneralizedTime:
        case UniversalTag::VisibleString:   return {7, 1};
        default:                            return {8, 1};
    }
}

static int choice_index_bits(int n) {
    if (n <= 1) return 0;
    int bits = 0, m = 1;
    while (m < n) { ++bits; m <<= 1; }
    return bits;
}

static void build_canonical_maps(const ChoiceSpec& spec, int root_count,
                                 std::vector<int>& to_canonical,
                                 std::vector<int>& from_canonical) {
    to_canonical.resize(root_count);
    std::iota(to_canonical.begin(), to_canonical.end(), 0);
    std::stable_sort(to_canonical.begin(), to_canonical.end(),
        [&](int a, int b) {
            const auto& ta = spec.alternatives[a].tag;
            const auto& tb = spec.alternatives[b].tag;
            if (ta.cls != tb.cls) return (int)ta.cls < (int)tb.cls;
            return ta.number < tb.number;
        });
    from_canonical.resize(root_count);
    for (int i = 0; i < root_count; ++i)
        from_canonical[to_canonical[i]] = i;
}

static void encode_open_type(const PerCodec& codec, PerEncodeStream& s,
                              const TypeDescriptor& mdef, const void* mptr) {
    std::vector<uint8_t> tmp;
    PerEncodeStream tmp_s{tmp};
    IEncodeStream& es = tmp_s;
    codec.encode(es, mdef, mptr);
    tmp_s.flush();
    per_detail::put_length(s, tmp.size());
    for (auto b : tmp) s.put_bits(b, 8);
}

static DecodeResult decode_open_type(const PerCodec& codec, PerDecodeStream& s,
                                     const TypeDescriptor& mdef, void* mptr) {
    auto len_r = per_detail::get_length(s);
    if (!len_r) return decode_err(len_r.error());
    auto bytes_r = per_detail::read_bytes(s, *len_r);
    if (!bytes_r) return decode_err(bytes_r.error());
    PerDecodeStream tmp_s{std::span<const uint8_t>{bytes_r->data(), bytes_r->size()}};
    IDecodeStream& ds = tmp_s;
    return codec.decode(ds, mdef, mptr);
}

static DecodeResult skip_open_type(PerDecodeStream& s) {
    auto len_r = per_detail::get_length(s);
    if (!len_r) return decode_err(len_r.error());
    for (std::size_t i = 0; i < *len_r; ++i) {
        auto b = s.get_bits(8);
        if (!b) return decode_err(b.error());
    }
    return decode_ok();
}

// ---------------------------------------------------------------------------
// Handler classes

struct ErrorPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream&,
                const TypeDescriptor& def, const void*) const override {
        assert(false && "PerCodec: unreachable dispatch table entry");
        (void)def;
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream&,
                        const TypeDescriptor& def, void*) const override {
        assert(false && "PerCodec: unreachable dispatch table entry");
        return decode_err(DecodeError(std::string("PerCodec: unsupported: ") + def.name));
    }
};

struct AnyPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor&, const void* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        auto bytes = v.bytes();
        per_detail::put_length(s, bytes.size());
        for (auto b : bytes) s.put_bits(b, 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor&, void* dest) const override {
        auto len_r = per_detail::get_length(s);
        if (!len_r) return decode_err(len_r.error());
        auto bytes_r = per_detail::read_bytes(s, *len_r);
        if (!bytes_r) return decode_err(bytes_r.error());
        *static_cast<OctetString*>(dest) = OctetString(*bytes_r);
        return decode_ok();
    }
};

struct BooleanPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor&, const void* src) const override {
        bool v = *static_cast<const bool*>(src);
        s.put_bits(v ? 1 : 0, 1);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor&, void* dest) const override {
        auto bit = s.get_bits(1);
        if (!bit) return decode_err(bit.error());
        *static_cast<bool*>(dest) = (*bit != 0);
        return decode_ok();
    }
};

struct IntegerPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        int64_t value = *static_cast<const int64_t*>(src);
        const Constraints& pc = def.constraints;
        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (value >= pc.lower_bound && value <= pc.upper_bound);
                s.put_bits(in_root ? 0 : 1, 1);
                if (!in_root) { encode_unconstrained_int(s, value); return; }
            }
            int64_t encoded = value - pc.lower_bound;
            int64_t rcount  = pc.upper_bound - pc.lower_bound + 1;
            s.put_bits(static_cast<uint64_t>(encoded), range_bits(rcount));
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                bool in_root = (value >= pc.lower_bound);
                s.put_bits(in_root ? 0 : 1, 1);
                if (!in_root) { encode_unconstrained_int(s, value); return; }
            }
            encode_unconstrained_int(s, value - pc.lower_bound);
        } else {
            encode_unconstrained_int(s, value);
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const Constraints& pc = def.constraints;
        if (pc.flags & Constraints::CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = s.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) return decode_unconstrained_int(s, dest);
            }
            int64_t rcount = pc.upper_bound - pc.lower_bound + 1;
            auto bits = s.get_bits(range_bits(rcount));
            if (!bits) return decode_err(bits.error());
            *static_cast<int64_t*>(dest) = pc.lower_bound + static_cast<int64_t>(*bits);
            return decode_ok();
        } else if (pc.flags & Constraints::SEMI_CONSTRAINED) {
            if (pc.flags & Constraints::EXTENSIBLE) {
                auto ext = s.get_bits(1);
                if (!ext) return decode_err(ext.error());
                if (*ext) return decode_unconstrained_int(s, dest);
            }
            int64_t adjusted = 0;
            auto r = decode_unconstrained_int(s, &adjusted);
            if (!r) return r;
            *static_cast<int64_t*>(dest) = adjusted + pc.lower_bound;
            return decode_ok();
        } else {
            return decode_unconstrained_int(s, dest);
        }
    }
};

struct NullPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream&,
                const TypeDescriptor&, const void*) const override {
        // NULL: zero bits (X.691 §18.1)
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream&,
                        const TypeDescriptor&, void*) const override {
        return decode_ok();
    }
};

struct RealPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor&, const void* src) const override {
        const Real& v = *static_cast<const Real*>(src);
        if (v.value() == 0.0) return;
        std::vector<uint8_t> ber;
        { BerWriter w{ber}; BerTraits<Real>::encode(w, v); }
        std::size_t content_len = ber[1];
        per_detail::put_length(s, content_len);
        for (std::size_t i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor&, void* dest) const override {
        return per_detail::decode_ber_content<Real>(s, dest);
    }
};

struct BitStringPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const BitString& v = *static_cast<const BitString*>(src);
        std::size_t bit_count = v.bit_count();
        encode_size_field(s, def, bit_count);
        std::size_t remaining = bit_count;
        for (uint8_t b : v.bytes()) {
            int n = static_cast<int>(std::min(remaining, std::size_t{8}));
            s.put_bits(static_cast<uint64_t>(b) >> (8 - n), n);
            remaining -= n;
            if (remaining == 0) break;
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        auto len_r = decode_size_field(s, def);
        if (!len_r) return decode_err(len_r.error());
        std::size_t bit_count = *len_r;
        if (bit_count == 0) { *static_cast<BitString*>(dest) = BitString{}; return decode_ok(); }
        std::vector<uint8_t> bytes;
        bytes.reserve((bit_count + 7) / 8);
        std::size_t remaining = bit_count;
        while (remaining > 0) {
            int n = static_cast<int>(std::min(remaining, std::size_t{8}));
            auto b = s.get_bits(n);
            if (!b) return decode_err(b.error());
            bytes.push_back(static_cast<uint8_t>(*b << (8 - n)));
            remaining -= n;
        }
        uint8_t unused = static_cast<uint8_t>((8 - bit_count % 8) % 8);
        *static_cast<BitString*>(dest) = BitString{std::move(bytes), unused};
        return decode_ok();
    }
};

struct OctetStringPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const OctetString& v = *static_cast<const OctetString*>(src);
        encode_size_field(s, def, v.size());
        for (uint8_t b : v.bytes()) s.put_bits(b, 8);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        auto len_r = decode_size_field(s, def);
        if (!len_r) return decode_err(len_r.error());
        auto bytes = per_detail::read_bytes(s, *len_r);
        if (!bytes) return decode_err(bytes.error());
        *static_cast<OctetString*>(dest) = OctetString{std::move(*bytes)};
        return decode_ok();
    }
};

struct OidPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor&, const void* src) const override {
        per_detail::encode_ber_content<Oid>(s, src);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor&, void* dest) const override {
        return per_detail::decode_ber_content<Oid>(s, dest);
    }
};

struct RelOidPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor&, const void* src) const override {
        per_detail::encode_ber_content<RelativeOid>(s, src);
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor&, void* dest) const override {
        return per_detail::decode_ber_content<RelativeOid>(s, dest);
    }
};

struct StringPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const std::string& str = *reinterpret_cast<const std::string*>(src);
        const Constraints& pc = def.constraints;
        auto [bits, bpc] = string_params(def.tag.number);
        bool has_alpha = pc.alphabet_bits > 0 && !pc.alphabet.empty();
        std::size_t char_count = has_alpha ? str.size() : str.size() / bpc;
        if (pc.flags & Constraints::EXTENSIBLE) {
            bool in_root;
            if (pc.flags & Constraints::SIZE_CONSTRAINED) {
                in_root = (char_count >= static_cast<std::size_t>(pc.size_lower) &&
                           char_count <= static_cast<std::size_t>(pc.size_upper));
            } else if (has_alpha) {
                in_root = true;
                for (unsigned char c : str)
                    if (std::find(pc.alphabet.begin(), pc.alphabet.end(), c) == pc.alphabet.end())
                        { in_root = false; break; }
            } else {
                in_root = true;
            }
            s.put_bits(in_root ? 0 : 1, 1);
            if (!in_root) {
                per_detail::put_length(s, char_count);
                for (unsigned char c : str) s.put_bits(c, 8);
                return;
            }
        }
        encode_size_field(s, def, char_count);
        if (has_alpha) {
            for (unsigned char c : str) {
                int code = 0;
                for (int i = 0; i < static_cast<int>(pc.alphabet.size()); ++i)
                    if (pc.alphabet[i] == c) { code = i; break; }
                s.put_bits(static_cast<uint64_t>(code), pc.alphabet_bits);
            }
        } else if (bpc > 1) {
            for (unsigned char c : str) s.put_bits(c, 8);
        } else if (bits == 4) {
            for (char c : str) s.put_bits(encode_numeric_char(c), 4);
        } else if (bits == 7) {
            for (char c : str) s.put_bits(static_cast<uint8_t>(c), 7);
        } else {
            for (char c : str) s.put_bits(static_cast<uint8_t>(c), 8);
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const Constraints& pc = def.constraints;
        if (pc.flags & Constraints::EXTENSIBLE) {
            auto ext = s.get_bits(1);
            if (!ext) return decode_err(ext.error());
            if (*ext) {
                auto len_r = per_detail::get_length(s);
                if (!len_r) return decode_err(len_r.error());
                std::string result;
                result.reserve(*len_r);
                for (std::size_t i = 0; i < *len_r; ++i) {
                    auto b = s.get_bits(8);
                    if (!b) return decode_err(b.error());
                    result.push_back(static_cast<char>(*b));
                }
                *reinterpret_cast<std::string*>(dest) = std::move(result);
                return decode_ok();
            }
        }
        auto len_r = decode_size_field(s, def);
        if (!len_r) return decode_err(len_r.error());
        std::size_t char_count = *len_r;
        auto [bits, bpc] = string_params(def.tag.number);
        std::string result;
        if (pc.alphabet_bits > 0 && !pc.alphabet.empty()) {
            result.reserve(char_count);
            for (std::size_t i = 0; i < char_count; ++i) {
                auto v = s.get_bits(pc.alphabet_bits);
                if (!v) return decode_err(v.error());
                if (*v < pc.alphabet.size())
                    result.push_back(static_cast<char>(pc.alphabet[*v]));
                else
                    result.push_back('?');
            }
        } else {
            std::size_t byte_count = char_count * bpc;
            result.reserve(byte_count);
            if (bpc > 1) {
                for (std::size_t i = 0; i < byte_count; ++i) {
                    auto b = s.get_bits(8);
                    if (!b) return decode_err(b.error());
                    result.push_back(static_cast<char>(*b));
                }
            } else if (bits == 4) {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = s.get_bits(4);
                    if (!v) return decode_err(v.error());
                    result.push_back(decode_numeric_char(static_cast<uint8_t>(*v)));
                }
            } else if (bits == 7) {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = s.get_bits(7);
                    if (!v) return decode_err(v.error());
                    result.push_back(static_cast<char>(*v));
                }
            } else {
                for (std::size_t i = 0; i < char_count; ++i) {
                    auto v = s.get_bits(8);
                    if (!v) return decode_err(v.error());
                    result.push_back(static_cast<char>(*v));
                }
            }
        }
        *reinterpret_cast<std::string*>(dest) = std::move(result);
        return decode_ok();
    }
};

struct EnumeratedPerHandler final : IPerTypeHandler {
    void encode(const PerCodec&, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        long value = *static_cast<const long*>(src);
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;
        const long* order = spec.per_value_order;
        int ordinal = -1;
        bool is_ext = false;
        if (order) {
            for (int i = 0; i < rcount; ++i)
                if (order[i] == value) { ordinal = i; break; }
        } else {
            for (int i = 0; i < rcount; ++i)
                if (spec.entries[i].value == value) { ordinal = i; break; }
        }
        if (ordinal < 0) {
            for (int i = rcount; i < spec.count; ++i) {
                if (spec.entries[i].value == value) {
                    ordinal = i - rcount;
                    is_ext = true;
                    break;
                }
            }
        }
        if (spec.extensible) s.put_bits(is_ext ? 1 : 0, 1);
        if (!is_ext) {
            s.put_bits(static_cast<uint64_t>(ordinal), range_bits(rcount));
        } else {
            put_nsnnwn(s, ordinal);
        }
    }
    DecodeResult decode(const PerCodec&, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;
        bool is_ext = false;
        if (spec.extensible) {
            auto bit = s.get_bits(1);
            if (!bit) return decode_err(bit.error());
            is_ext = (*bit != 0);
        }
        if (!is_ext) {
            int rb = range_bits(rcount);
            auto idx = s.get_bits(rb);
            if (!idx) return decode_err(idx.error());
            if (*idx >= static_cast<uint64_t>(rcount))
                return decode_err(DecodeError("PER: ENUM index out of range"));
            long value;
            const long* order = spec.per_value_order;
            if (order) value = order[*idx];
            else       value = spec.entries[*idx].value;
            *static_cast<long*>(dest) = value;
            return decode_ok();
        } else {
            auto ord = get_nsnnwn(s);
            if (!ord) return decode_err(ord.error());
            int ext_entry = rcount + *ord;
            if (ext_entry >= spec.count)
                return decode_err(DecodeError("PER: ENUM extension index out of range"));
            *static_cast<long*>(dest) = spec.entries[ext_entry].value;
            return decode_ok();
        }
    }
};

struct SeqOfPerHandler final : IPerTypeHandler {
    void encode(const PerCodec& codec, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const auto& spec = *def.seq_of_spec;
        const SeqOfBase& seq = *static_cast<const SeqOfBase*>(src);
        std::size_t count = seq.count();
        const auto& sc = spec.size_constraints;
        if (sc.flags & Constraints::SIZE_CONSTRAINED) {
            if (sc.size_lower == sc.size_upper) {
                // Fixed size: count implicit
            } else {
                s.put_bits(count - static_cast<std::size_t>(sc.size_lower), sc.size_range_bits);
            }
        } else {
            per_detail::put_length(s, count);
        }
        const auto& edef = *spec.element;
        IEncodeStream& es = s;
        for (std::size_t i = 0; i < count; ++i)
            codec.encode(es, edef, seq.get_const(i));
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const auto& spec = *def.seq_of_spec;
        const auto& sc = spec.size_constraints;
        std::size_t count = 0;
        if (sc.flags & Constraints::SIZE_CONSTRAINED) {
            if (sc.size_lower == sc.size_upper) {
                count = static_cast<std::size_t>(sc.size_lower);
            } else {
                auto v = s.get_bits(sc.size_range_bits);
                if (!v) return decode_err(v.error());
                count = *v + static_cast<std::size_t>(sc.size_lower);
            }
        } else {
            auto v = per_detail::get_length(s);
            if (!v) return decode_err(v.error());
            count = *v;
        }
        SeqOfBase& seq = *static_cast<SeqOfBase*>(dest);
        seq.resize(count);
        const auto& edef = *spec.element;
        IDecodeStream& ds = s;
        for (std::size_t i = 0; i < count; ++i) {
            auto r = codec.decode(ds, edef, seq.get_mut(i));
            if (!r) return r;
        }
        return decode_ok();
    }
};

struct SequencePerHandler final : IPerTypeHandler {
    void encode(const PerCodec& codec, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const auto& spec = *def.sequence_spec;
        int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool has_ext = false;
        if (spec.ext_at >= 0) {
            for (int i = root_end; i < spec.count; ++i) {
                if (spec.members[i].optional_ops.is_present(src)) { has_ext = true; break; }
            }
            s.put_bits(has_ext ? 1 : 0, 1);
        }
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.optional) continue;
            s.put_bits(mbr.optional_ops.is_present(src) ? 1 : 0, 1);
        }
        IEncodeStream& es = s;
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional && !mbr.optional_ops.is_present(src)) continue;
            const void* mptr = mbr.optional_ops.get_ptr
                ? mbr.optional_ops.get_ptr(const_cast<void*>(src))
                : static_cast<const char*>(src) + mbr.offset;
            codec.encode(es, *mbr.type_descriptor, mptr);
        }
        if (has_ext) {
            int n_ext = spec.count - root_end;
            put_nslength(s, static_cast<std::size_t>(n_ext));
            for (int i = root_end; i < spec.count; ++i)
                s.put_bits(spec.members[i].optional_ops.is_present(src) ? 1 : 0, 1);
            for (int i = root_end; i < spec.count; ++i) {
                const auto& mbr = spec.members[i];
                if (!mbr.type_descriptor || !mbr.optional_ops.is_present(src)) continue;
                const void* mptr = mbr.optional_ops.get_ptr
                    ? mbr.optional_ops.get_ptr(const_cast<void*>(src))
                    : static_cast<const char*>(src) + mbr.offset;
                encode_open_type(codec, s, *mbr.type_descriptor, mptr);
            }
        }
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const auto& spec = *def.sequence_spec;
        int root_end = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool ext_flag = false;
        if (spec.ext_at >= 0) {
            auto b = s.get_bits(1);
            if (!b) return decode_err(b.error());
            ext_flag = (*b != 0);
        }
        int roms = 0;
        for (int i = 0; i < root_end; ++i)
            if (spec.members[i].optional) ++roms;
        bool bitmap[64] = {};
        for (int i = 0; i < roms && i < 64; ++i) {
            auto bit = s.get_bits(1);
            if (!bit) return decode_err(bit.error());
            bitmap[i] = (*bit != 0);
        }
        int opt_idx = 0;
        IDecodeStream& ds = s;
        for (int i = 0; i < root_end; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) {
                bool present = bitmap[opt_idx++];
                mbr.optional_ops.set_present(dest, present);
                if (!present) continue;
            }
            void* mptr = mbr.optional_ops.get_ptr
                ? mbr.optional_ops.get_ptr(dest)
                : static_cast<char*>(dest) + mbr.offset;
            auto r = codec.decode(ds, *mbr.type_descriptor, mptr);
            if (!r) return r;
        }
        if (spec.ext_at >= 0) {
            int known_ext = spec.count - root_end;
            if (!ext_flag) {
                for (int i = root_end; i < spec.count; ++i)
                    spec.members[i].optional_ops.set_present(dest, false);
            } else {
                auto n_ext_r = get_nslength(s);
                if (!n_ext_r) return decode_err(n_ext_r.error());
                int n_ext = static_cast<int>(*n_ext_r);
                bool ext_bitmap[64] = {};
                for (int i = 0; i < n_ext && i < 64; ++i) {
                    auto b = s.get_bits(1);
                    if (!b) return decode_err(b.error());
                    ext_bitmap[i] = (*b != 0);
                }
                for (int i = 0; i < n_ext; ++i) {
                    if (!ext_bitmap[i]) {
                        if (i < known_ext)
                            spec.members[root_end + i].optional_ops.set_present(dest, false);
                        continue;
                    }
                    if (i < known_ext) {
                        const auto& mbr = spec.members[root_end + i];
                        mbr.optional_ops.set_present(dest, true);
                        void* mptr = mbr.optional_ops.get_ptr
                            ? mbr.optional_ops.get_ptr(dest)
                            : static_cast<char*>(dest) + mbr.offset;
                        auto r = decode_open_type(codec, s, *mbr.type_descriptor, mptr);
                        if (!r) return r;
                    } else {
                        if (auto r = skip_open_type(s); !r) return r;
                    }
                }
            }
        }
        return decode_ok();
    }
};

struct ChoicePerHandler final : IPerTypeHandler {
    void encode(const PerCodec& codec, PerEncodeStream& s,
                const TypeDescriptor& def, const void* src) const override {
        const auto& spec = *def.choice_spec;
        const ChoiceInterface* ch = reinterpret_cast<const ChoiceInterface*>(src);
        int pr = ch->choice_present();
        if (pr <= 0 || pr > spec.count) return;
        int def_idx = pr - 1;
        int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool in_ext = (spec.ext_at >= 0) && (def_idx >= root_count);
        if (spec.ext_at >= 0) s.put_bits(in_ext ? 1 : 0, 1);
        if (!in_ext) {
            std::vector<int> to_can, from_can;
            build_canonical_maps(spec, root_count, to_can, from_can);
            int canonical_idx = to_can[def_idx];
            int bits = choice_index_bits(root_count);
            if (bits > 0) s.put_bits(static_cast<uint64_t>(canonical_idx), bits);
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) return;
            IEncodeStream& es = s;
            const void* mptr = ch->choice_member_const_ptr(pr);
            codec.encode(es, *alt.type_descriptor, mptr);
        } else {
            int ext_idx = def_idx - root_count;
            if (ext_idx < 64) {
                s.put_bits(0, 1);
                s.put_bits(static_cast<uint64_t>(ext_idx), 6);
            } else {
                s.put_bits(1, 1);
                per_detail::put_length(s, static_cast<std::size_t>(ext_idx));
            }
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor) return;
            const void* mptr = ch->choice_member_const_ptr(pr);
            encode_open_type(codec, s, *alt.type_descriptor, mptr);
        }
    }
    DecodeResult decode(const PerCodec& codec, PerDecodeStream& s,
                        const TypeDescriptor& def, void* dest) const override {
        const auto& spec = *def.choice_spec;
        ChoiceInterface* ch = reinterpret_cast<ChoiceInterface*>(dest);
        int root_count = (spec.ext_at >= 0) ? spec.ext_at : spec.count;
        bool in_ext = false;
        if (spec.ext_at >= 0) {
            auto b = s.get_bits(1);
            if (!b) return decode_err(b.error());
            in_ext = (*b != 0);
        }
        if (!in_ext) {
            std::vector<int> to_can, from_can;
            build_canonical_maps(spec, root_count, to_can, from_can);
            int bits = choice_index_bits(root_count);
            int canonical_idx = 0;
            if (bits > 0) {
                auto v = s.get_bits(bits);
                if (!v) return decode_err(v.error());
                canonical_idx = static_cast<int>(*v);
            }
            if (canonical_idx < 0 || canonical_idx >= root_count)
                return decode_err(DecodeError("CHOICE index out of range"));
            int def_idx = from_can[canonical_idx];
            const auto& alt = spec.alternatives[def_idx];
            if (!alt.type_descriptor)
                return decode_err(DecodeError("CHOICE alternative has no type descriptor"));
            ch->choice_emplace(def_idx + 1);
            ch->choice_set_present(def_idx + 1);
            void* mptr = ch->choice_member_ptr(def_idx + 1);
            IDecodeStream& ds = s;
            auto r = codec.decode(ds, *alt.type_descriptor, mptr);
            if (!r) return r;
            return decode_ok();
        } else {
            auto b = s.get_bits(1);
            if (!b) return decode_err(b.error());
            int ext_idx;
            if (*b == 0) {
                auto v = s.get_bits(6);
                if (!v) return decode_err(v.error());
                ext_idx = static_cast<int>(*v);
            } else {
                auto v = per_detail::get_length(s);
                if (!v) return decode_err(v.error());
                ext_idx = static_cast<int>(*v);
            }
            int def_idx = root_count + ext_idx;
            if (def_idx < spec.count) {
                const auto& alt = spec.alternatives[def_idx];
                if (alt.type_descriptor) {
                    ch->choice_emplace(def_idx + 1);
                    ch->choice_set_present(def_idx + 1);
                    void* mptr = ch->choice_member_ptr(def_idx + 1);
                    auto r = decode_open_type(codec, s, *alt.type_descriptor, mptr);
                    if (!r) return r;
                } else {
                    if (auto r = skip_open_type(s); !r) return r;
                }
            } else {
                if (auto r = skip_open_type(s); !r) return r;
            }
            return decode_ok();
        }
    }
};

// ---------------------------------------------------------------------------
// Singletons

static const ErrorPerHandler      s_error;
static const AnyPerHandler        s_any;
static const BooleanPerHandler    s_boolean;
static const IntegerPerHandler    s_integer;
static const NullPerHandler       s_null;
static const RealPerHandler       s_real;
static const BitStringPerHandler  s_bitstring;
static const OctetStringPerHandler s_octetstring;
static const OidPerHandler        s_oid;
static const RelOidPerHandler     s_reloid;
static const StringPerHandler     s_string;
static const EnumeratedPerHandler s_enumerated;
static const SeqOfPerHandler      s_seqof;
static const SequencePerHandler   s_sequence;
static const ChoicePerHandler     s_choice;

} // anonymous namespace

// ---------------------------------------------------------------------------
// Dispatch tables

const IPerTypeHandler* const PerCodec::comp_dispatch_[6] = {
    &s_error,      // [0] Primitive — routed to prim_dispatch_, never lands here
    &s_any,        // [1] Any
    &s_enumerated, // [2] Enumerated
    &s_sequence,   // [3] Sequence / SET
    &s_choice,     // [4] Choice
    &s_seqof,      // [5] SeqOf / SET OF
};

const IPerTypeHandler* const PerCodec::prim_dispatch_[32] = {
    &s_error,      // [ 0] EndOfContents
    &s_boolean,    // [ 1] Boolean
    &s_integer,    // [ 2] Integer
    &s_bitstring,  // [ 3] BitString
    &s_octetstring,// [ 4] OctetString (ANY has TypeKind::Any → comp_dispatch_)
    &s_null,       // [ 5] Null        (zero bits, X.691 §18.1)
    &s_oid,        // [ 6] OID
    &s_string,     // [ 7] ObjectDescriptor   (is_character_string)
    &s_error,      // [ 8] External
    &s_real,       // [ 9] Real
    &s_error,      // [10] Enumerated   — TypeKind::Enumerated → comp_dispatch_
    &s_error,      // [11] EmbeddedPdv
    &s_error,      // [12] Utf8String   — not in is_character_string
    &s_reloid,     // [13] RelativeOid
    &s_error,      // [14] (unassigned)
    &s_error,      // [15] (unassigned)
    &s_error,      // [16] Sequence     — TypeKind::Sequence → comp_dispatch_
    &s_error,      // [17] Set          — TypeKind::Sequence → comp_dispatch_
    &s_string,     // [18] NumericString
    &s_string,     // [19] PrintableString
    &s_string,     // [20] T61String
    &s_string,     // [21] VideotexString
    &s_error,      // [22] Ia5String    — not in is_character_string
    &s_string,     // [23] UtcTime
    &s_string,     // [24] GeneralizedTime
    &s_string,     // [25] GraphicString
    &s_string,     // [26] VisibleString
    &s_string,     // [27] GeneralString
    &s_string,     // [28] UniversalString
    &s_error,      // [29] CharacterString
    &s_string,     // [30] BmpString
    &s_error,      // [31] LongForm
};

// ---------------------------------------------------------------------------
// PerCodec public entry points

void PerCodec::encode(IEncodeStream& dst,
                      const TypeDescriptor& def,
                      const void* src) const
{
    auto& s = static_cast<PerEncodeStream&>(dst);
    if (def.kind == TypeKind::Primitive)
        prim_dispatch_[def.tag.number]->encode(*this, s, def, src);
    else
        comp_dispatch_[(int)def.kind]->encode(*this, s, def, src);
}

DecodeResult PerCodec::decode(IDecodeStream& src,
                              const TypeDescriptor& def,
                              void* dest) const
{
    auto& s = static_cast<PerDecodeStream&>(src);
    if (def.kind == TypeKind::Primitive)
        return prim_dispatch_[def.tag.number]->decode(*this, s, def, dest);
    return comp_dispatch_[(int)def.kind]->decode(*this, s, def, dest);
}

} // namespace asn1
