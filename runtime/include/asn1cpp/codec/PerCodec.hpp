#pragma once
#include <cstdint>
#include <vector>
#include <span>
#include "ICodec.hpp"

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
        return decode_err(DecodeError(std::string("PerCodec: no spec for type ") + def.name));
    }

private:
    // ---- bit helpers ---------------------------------------------------

    // Minimum bits to represent values in [0, range-1].
    static int range_bits(int range) {
        if (range <= 1) return 0;
        int bits = 0;
        for (int r = range - 1; r > 0; r >>= 1) ++bits;
        return bits;
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

    // ---- SEQUENCE / SET (stub) -----------------------------------------

    void encode_sequence(PerEncodeStream& s,
                         const TypeDescriptor& def,
                         const void* src) const
    {
        (void)s; (void)def; (void)src;
    }

    DecodeResult decode_sequence(PerDecodeStream& s,
                                 const TypeDescriptor& def,
                                 void* dest) const
    {
        (void)s; (void)def; (void)dest;
        return decode_err(DecodeError("PerCodec: SEQUENCE not yet implemented"));
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
