#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include "ICodec.hpp"
#include "PerConstraints.hpp"
#include "../Tag.hpp"

namespace asn1 {

// ---------------------------------------------------------------------------
// Bit-level stream wrappers for PER (UPER / APER)
//
// Bits are packed MSB-first within each byte, matching X.691 conventions.
// UPER: no byte alignment between values.
// APER: byte-align before values with range >= 256 (not yet enforced here;
//       for small enumerations UPER == APER).

class PerEncodeStream : public IEncodeStream {
    std::vector<uint8_t>& buf_;
    uint8_t current_{0};
    int     bits_{0};   // bits written into current_ (0-7)
public:
    explicit PerEncodeStream(std::vector<uint8_t>& buf) : buf_(buf) {}

    // Write n bits of value, MSB first.
    void put_bits(uint64_t value, int n) {
        for (int i = n - 1; i >= 0; --i) {
            int bit = (value >> i) & 1;
            current_ |= static_cast<uint8_t>(bit << (7 - bits_));
            if (++bits_ == 8) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
        }
    }

    // Zero-pad the current byte and push it (if any bits are pending).
    void flush() {
        if (bits_ > 0) { buf_.push_back(current_); current_ = 0; bits_ = 0; }
    }

    std::vector<uint8_t>& buf() { return buf_; }
};

class PerDecodeStream : public IDecodeStream {
    std::span<const uint8_t> buf_;
    int byte_pos_{0};
    int bit_pos_{0};   // next bit within current byte (0 = MSB)
public:
    explicit PerDecodeStream(std::span<const uint8_t> buf) : buf_(buf) {}

    bool at_end() const override {
        return byte_pos_ >= static_cast<int>(buf_.size());
    }

    // Read n bits, MSB first.
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
// PerCodec — generic PER encode/decode driven by TypeDescriptor tables

class PerCodec : public ICodec {
public:
    static PerCodec& instance() {
        static PerCodec inst;
        return inst;
    }

    const char* name() const override { return "PER"; }

    // ------------------------------------------------------------------
    void encode(IEncodeStream& dst,
                const TypeDescriptor& def,
                const void* src) const override
    {
        auto& s = static_cast<PerEncodeStream&>(dst);
        if (def.enum_spec)     { encode_enumerated(s, def, src); return; }
        if (def.sequence_spec) { encode_sequence   (s, def, src); return; }
        if (def.choice_spec)   { encode_choice     (s, def, src); return; }
        if (is_integer_tag(def.tag)) { encode_integer(s, def, src); return; }
    }

    // ------------------------------------------------------------------
    DecodeResult decode(IDecodeStream& src,
                        const TypeDescriptor& def,
                        void* dest) const override
    {
        auto& s = static_cast<PerDecodeStream&>(src);
        if (def.enum_spec)     return decode_enumerated(s, def, dest);
        if (def.sequence_spec) return decode_sequence   (s, def, dest);
        if (def.choice_spec)   return decode_choice     (s, def, dest);
        if (is_integer_tag(def.tag)) return decode_integer(s, def, dest);
        return decode_err(DecodeError(std::string("PerCodec: no spec for type ") + def.name));
    }

private:
    // ---- bit helpers ---------------------------------------------------

    static bool is_integer_tag(const Tag& t) {
        return t.cls == TagClass::Universal && t.number == UniversalTag::Integer;
    }

    // Minimum bits to represent values in [0, range-1].
    static int range_bits(int64_t range) {
        if (range <= 1) return 0;
        int bits = 0;
        for (int64_t r = range - 1; r > 0; r >>= 1) ++bits;
        return bits;
    }

    // ---- INTEGER -------------------------------------------------------
    //
    // Constrained (per_constraints != nullptr):
    //   encoded = value - lower; write range_bits bits MSB-first (UPER).
    // Unconstrained (per_constraints == nullptr):
    //   length (1 byte, value in bytes) + big-endian minimal two's-complement.

    void encode_integer(PerEncodeStream& s,
                        const TypeDescriptor& def,
                        const void* src) const
    {
        int64_t value = *static_cast<const int64_t*>(src);
        const auto* pc = static_cast<const PerConstraints*>(def.per_constraints);
        if (pc && (pc->flags & PerConstraints::CONSTRAINED)) {
            int64_t encoded = value - pc->lower_bound;
            int64_t rcount  = pc->upper_bound - pc->lower_bound + 1;
            s.put_bits(static_cast<uint64_t>(encoded), range_bits(rcount));
        } else {
            // Unconstrained: minimal big-endian bytes, preceded by byte count.
            uint8_t buf[8]; int len = 0;
            if (value == 0) { buf[0] = 0; len = 1; }
            else {
                uint64_t u = static_cast<uint64_t>(value);
                for (int i = 7; i >= 0; --i) { buf[i] = u & 0xFF; u >>= 8; }
                int start = (value > 0) ? 0 : 0;
                if (value > 0) {
                    while (start < 7 && buf[start] == 0x00 && !(buf[start+1] & 0x80)) ++start;
                } else {
                    while (start < 7 && buf[start] == 0xFF && (buf[start+1] & 0x80)) ++start;
                }
                len = 8 - start;
                std::memmove(buf, buf + start, len);
            }
            s.put_bits(static_cast<uint64_t>(len), 8);  // length byte
            for (int i = 0; i < len; ++i) s.put_bits(buf[i], 8);
        }
    }

    DecodeResult decode_integer(PerDecodeStream& s,
                                const TypeDescriptor& def,
                                void* dest) const
    {
        const auto* pc = static_cast<const PerConstraints*>(def.per_constraints);
        if (pc && (pc->flags & PerConstraints::CONSTRAINED)) {
            int64_t rcount = pc->upper_bound - pc->lower_bound + 1;
            auto bits = s.get_bits(range_bits(rcount));
            if (!bits) return decode_err(bits.error());
            *static_cast<int64_t*>(dest) = pc->lower_bound + static_cast<int64_t>(*bits);
            return decode_ok();
        } else {
            // Unconstrained: read length byte, then that many bytes.
            auto len_bits = s.get_bits(8);
            if (!len_bits) return decode_err(len_bits.error());
            int len = static_cast<int>(*len_bits);
            if (len == 0 || len > 8)
                return decode_err(DecodeError("PER: INTEGER length out of range"));
            int64_t value = 0;
            for (int i = 0; i < len; ++i) {
                auto b = s.get_bits(8);
                if (!b) return decode_err(b.error());
                if (i == 0 && (*b & 0x80)) value = -1;  // sign-extend
                value = (value << 8) | static_cast<int64_t>(*b);
            }
            *static_cast<int64_t*>(dest) = value;
            return decode_ok();
        }
    }

    // ---- ENUMERATED ----------------------------------------------------
    //
    // X.691 §13:
    //   extensible  → 1-bit extension flag; 0 = root, 1 = extension
    //   root value  → constrained-whole-number in [0, root_count-1]
    //   ext value   → normally-small-number (open type; not yet implemented)
    //   non-extensible → constrained-whole-number in [0, count-1]

    void encode_enumerated(PerEncodeStream& s,
                           const TypeDescriptor& def,
                           const void* src) const
    {
        long value = *static_cast<const long*>(src);
        const EnumSpec& spec = *def.enum_spec;
        int rcount = spec.root_count > 0 ? spec.root_count : spec.count;

        // Find ordinal in definition order (per_value_order for root values).
        const long* order = spec.per_value_order;
        int ordinal = -1;
        bool is_ext = false;

        if (order) {
            for (int i = 0; i < rcount; ++i) {
                if (order[i] == value) { ordinal = i; break; }
            }
        } else {
            // No separate order array: entries are already in definition order.
            for (int i = 0; i < rcount; ++i) {
                if (spec.entries[i].value == value) { ordinal = i; break; }
            }
        }

        if (ordinal < 0) {
            // Extension value — find its extension ordinal.
            for (int i = rcount; i < spec.count; ++i) {
                if (spec.entries[i].value == value) {
                    ordinal = i - rcount;
                    is_ext = true;
                    break;
                }
            }
        }

        if (spec.extensible) {
            s.put_bits(is_ext ? 1 : 0, 1);
        }

        if (!is_ext) {
            int rb = range_bits(rcount);
            s.put_bits(static_cast<uint64_t>(ordinal), rb);
        } else {
            // Open-type extension encoding (X.691 §13.3) — not yet implemented.
            // Emit a placeholder 0 byte (normally-small-number = 0).
            s.put_bits(0, 8);
        }
    }

    DecodeResult decode_enumerated(PerDecodeStream& s,
                                   const TypeDescriptor& def,
                                   void* dest) const
    {
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
            if (order) {
                value = order[*idx];
            } else {
                value = spec.entries[*idx].value;
            }
            *static_cast<long*>(dest) = value;
            return decode_ok();
        } else {
            // Extension value: normally-small-number (not yet implemented).
            return decode_err(DecodeError("PER: ENUM extension values not yet implemented"));
        }
    }

    // ---- SEQUENCE / SET -------------------------------------------------
    //
    // Non-extensible, no-optional case: concatenate member encodings.
    // OPTIONAL members and extension bitmap (X.691 §18) deferred to later step.

    void encode_sequence(PerEncodeStream& s,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member PER encode
            const void* mptr = static_cast<const char*>(src) + mbr.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            encode(s, mdef, mptr);
        }
    }

    DecodeResult decode_sequence(PerDecodeStream& s,
                                 const TypeDescriptor& def,
                                 void* dest) const
    {
        const auto& spec = *def.sequence_spec;
        for (int i = 0; i < spec.count; ++i) {
            const auto& mbr = spec.members[i];
            if (!mbr.type_descriptor) continue;
            if (mbr.optional) continue;  // TODO: optional member PER decode
            void* mptr = static_cast<char*>(dest) + mbr.offset;
            const auto& mdef = *static_cast<const TypeDescriptor*>(mbr.type_descriptor);
            auto r = decode(s, mdef, mptr);
            if (!r) return r;
        }
        return decode_ok();
    }

    // ---- CHOICE (stub) -------------------------------------------------

    void encode_choice(PerEncodeStream& s,
                       const TypeDescriptor& def,
                       const void* src) const
    {
        (void)s; (void)def; (void)src;
    }

    DecodeResult decode_choice(PerDecodeStream& s,
                               const TypeDescriptor& def,
                               void* dest) const
    {
        (void)s; (void)def; (void)dest;
        return decode_err(DecodeError("PerCodec: CHOICE not yet implemented"));
    }
};

} // namespace asn1
