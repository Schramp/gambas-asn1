#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <vector>
#include <span>
#include "ICodec.hpp"
#include "PerConstraints.hpp"
#include "../Tag.hpp"
#include "../types/Real.hpp"
#include "../types/BitString.hpp"
#include "../types/OctetString.hpp"
#include "../types/Oid.hpp"
#include "../types/Strings.hpp"
#include "../codec/BerWriter.hpp"
#include "../codec/BerReader.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// Bit-level stream wrappers for PER (UPER / APER)

class PerEncodeStream : public IEncodeStream {
    std::vector<uint8_t>& buf_;
    uint8_t current_{0};
    int     bits_{0};
public:
    explicit PerEncodeStream(std::vector<uint8_t>& buf) : buf_(buf) {}

    void put_bits(uint64_t value, int n) {
        for (int i = n - 1; i >= 0; --i) {
            int bit = (value >> i) & 1;
            current_ |= static_cast<uint8_t>(bit << (7 - bits_));
            if (++bits_ == 8) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
        }
    }

    void flush() {
        if (bits_ > 0 || buf_.empty()) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
    }

    std::vector<uint8_t>& buf() { return buf_; }
};

class PerDecodeStream : public IDecodeStream {
    std::span<const uint8_t> buf_;
    int byte_pos_{0};
    int bit_pos_{0};
public:
    explicit PerDecodeStream(std::span<const uint8_t> buf) : buf_(buf) {}

    bool at_end() const override {
        return byte_pos_ >= static_cast<int>(buf_.size());
    }

    Expected<uint64_t, DecodeError> get_bits(int n) {
        uint64_t result = 0;
        for (int i = 0; i < n; ++i) {
            if (byte_pos_ >= static_cast<int>(buf_.size()))
                return make_unexpected<uint64_t, DecodeError>(
                    DecodeError("PER: unexpected end of data"));
            int bit = (buf_[byte_pos_] >> (7 - bit_pos_)) & 1;
            result = (result << 1) | static_cast<uint64_t>(bit);
            if (++bit_pos_ == 8) { ++byte_pos_; bit_pos_ = 0; }
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// PerCodec

class PerCodec : public ICodec {
public:
    static PerCodec& instance() {
        static PerCodec inst;
        return inst;
    }

    const char* name() const override { return "PER"; }

    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override;

    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override;

private:
    // ---- PER length determinant (X.691 §10.7) — keep inline: called by templates
    static void put_length(PerEncodeStream& s, std::size_t n) {
        if (n <= 127) {
            s.put_bits(n, 8);
        } else if (n <= 16383) {
            s.put_bits(0x80 | (n >> 8), 8);
            s.put_bits(n & 0xFF, 8);
        }
    }

    static Expected<std::size_t, DecodeError> get_length(PerDecodeStream& s) {
        auto first = s.get_bits(8);
        if (!first) return make_unexpected<std::size_t, DecodeError>(first.error());
        if (!(*first & 0x80)) return static_cast<std::size_t>(*first);
        if ((*first & 0xC0) == 0x80) {
            auto second = s.get_bits(8);
            if (!second) return make_unexpected<std::size_t, DecodeError>(second.error());
            return static_cast<std::size_t>((*first & 0x3F) << 8 | *second);
        }
        return make_unexpected<std::size_t, DecodeError>(
            DecodeError("PER: fragmented length not implemented"));
    }

    // ---- Byte-read helper — keep inline: called by templates
    static Expected<std::vector<uint8_t>, DecodeError> read_bytes(PerDecodeStream& s, std::size_t n) {
        std::vector<uint8_t> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            auto b = s.get_bits(8);
            if (!b) return make_unexpected<std::vector<uint8_t>, DecodeError>(b.error());
            out.push_back(static_cast<uint8_t>(*b));
        }
        return out;
    }

    // ---- Non-inline helpers (defined in PerCodec.cpp) ---------------------
    static void put_nslength(PerEncodeStream& s, std::size_t n);
    static Expected<std::size_t, DecodeError> get_nslength(PerDecodeStream& s);
    static void put_nsnnwn(PerEncodeStream& s, int n);
    static Expected<int, DecodeError> get_nsnnwn(PerDecodeStream& s);

    void encode_open_type(PerEncodeStream& s, const TypeDescriptor& mdef, const void* mptr) const;
    DecodeResult decode_open_type(PerDecodeStream& s, const TypeDescriptor& mdef, void* mptr) const;
    static DecodeResult skip_open_type(PerDecodeStream& s);

    static bool is_integer_tag(const Tag& t);
    static bool is_boolean_tag(const Tag& t);
    static bool is_real_tag(const Tag& t);
    static bool is_bitstring_tag(const Tag& t);
    static bool is_octetstring_tag(const Tag& t);
    static bool is_null_tag(const Tag& t);
    static bool is_oid_tag(const Tag& t);
    static bool is_reloid_tag(const Tag& t);
    static bool is_string_tag(const Tag& t);

    static int range_bits(int64_t range);

    static void encode_any(PerEncodeStream& s, const void* src);
    static DecodeResult decode_any(PerDecodeStream& s, void* dest);

    static void encode_boolean(PerEncodeStream& s, const void* src);
    static DecodeResult decode_boolean(PerDecodeStream& s, void* dest);

    static void encode_size_field(PerEncodeStream& s, const TypeDescriptor& def, std::size_t len);
    static Expected<std::size_t, DecodeError> decode_size_field(PerDecodeStream& s, const TypeDescriptor& def);

    static void encode_bitstring(PerEncodeStream& s, const TypeDescriptor& def, const void* src);
    static DecodeResult decode_bitstring(PerDecodeStream& s, const TypeDescriptor& def, void* dest);

    static void encode_octetstring(PerEncodeStream& s, const TypeDescriptor& def, const void* src);
    static DecodeResult decode_octetstring(PerDecodeStream& s, const TypeDescriptor& def, void* dest);

    static uint8_t encode_numeric_char(char c);
    static char    decode_numeric_char(uint8_t v);
    static uint8_t encode_ps_char(char c);
    static char    decode_ps_char(uint8_t v);
    static std::tuple<int,int> string_params(uint32_t tag_num);
    static void encode_string(PerEncodeStream& s, const TypeDescriptor& def, const void* src);
    static DecodeResult decode_string(PerDecodeStream& s, const TypeDescriptor& def, void* dest);

    static void encode_real(PerEncodeStream& s, const void* src);
    static DecodeResult decode_real(PerDecodeStream& s, void* dest);

    static void encode_unconstrained_int(PerEncodeStream& s, int64_t value);
    static DecodeResult decode_unconstrained_int(PerDecodeStream& s, void* dest);
    static void encode_integer(PerEncodeStream& s, const TypeDescriptor& def, const void* src);
    static DecodeResult decode_integer(PerDecodeStream& s, const TypeDescriptor& def, void* dest);

    static void encode_enumerated(PerEncodeStream& s, const TypeDescriptor& def, const void* src);
    static DecodeResult decode_enumerated(PerDecodeStream& s, const TypeDescriptor& def, void* dest);

    void encode_seq_of(PerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_seq_of(PerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    void encode_sequence(PerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_sequence(PerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    static int choice_index_bits(int n);
    static void build_canonical_maps(const ChoiceSpec& spec, int root_count,
                                     std::vector<int>& to_can, std::vector<int>& from_can);
    void encode_choice(PerEncodeStream& s, const TypeDescriptor& def, const void* src) const;
    DecodeResult decode_choice(PerDecodeStream& s, const TypeDescriptor& def, void* dest) const;

    // ---- BER-content round-trip helpers (OID, RELATIVE-OID) — keep inline: templates
    template<typename T>
    static void encode_ber_content(PerEncodeStream& s, const void* src) {
        std::vector<uint8_t> ber;
        { BerWriter w{ber}; BerTraits<T>::encode(w, *static_cast<const T*>(src)); }
        uint8_t content_len = ber[1];
        put_length(s, content_len);
        for (int i = 0; i < content_len; ++i) s.put_bits(ber[2 + i], 8);
    }

    template<typename T>
    static DecodeResult decode_ber_content(PerDecodeStream& s, void* dest) {
        auto len_r = get_length(s);
        if (!len_r) return decode_err(len_r.error());
        auto content = read_bytes(s, *len_r);
        if (!content) return decode_err(content.error());
        std::vector<uint8_t> ber;
        const auto tag = BerTraits<T>::tag();
        ber.push_back(static_cast<uint8_t>(tag.number));
        ber.push_back(static_cast<uint8_t>(*len_r));
        ber.insert(ber.end(), content->begin(), content->end());
        BerReader r{ber};
        auto v = BerTraits<T>::decode(r);
        if (!v) return decode_err(v.error());
        *static_cast<T*>(dest) = *v;
        return decode_ok();
    }

    static void encode_oid   (PerEncodeStream& s, const void* src)    { encode_ber_content<Oid>        (s, src); }
    static void encode_reloid(PerEncodeStream& s, const void* src)    { encode_ber_content<RelativeOid>(s, src); }
    static DecodeResult decode_oid   (PerDecodeStream& s, void* dest) { return decode_ber_content<Oid>        (s, dest); }
    static DecodeResult decode_reloid(PerDecodeStream& s, void* dest) { return decode_ber_content<RelativeOid>(s, dest); }
};

} // namespace asn1
