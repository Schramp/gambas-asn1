#pragma once
#include <cstdint>
#include <vector>

namespace asn1 {

// PER constraint metadata for a single type or member.
// Embedded by value in TypeDescriptor; flags==0 means unconstrained.
struct PerConstraints {
    static constexpr int CONSTRAINED      = 1;
    static constexpr int SEMI_CONSTRAINED = 2;
    static constexpr int EXTENSIBLE       = 4;
    static constexpr int SIZE_CONSTRAINED = 8;   // size_lower..size_upper is a finite range

    // INTEGER storage kind — chosen at codegen time from constraint analysis.
    // BerCodec / RandomFiller / validate() read this to cast void* correctly.
    static constexpr int INT_S64       = 0;  // int64_t  — asn1::Integer (default)
    static constexpr int INT_U64       = 1;  // uint64_t — asn1::UInteger
    static constexpr int INT_I128      = 2;  // __int128  — asn1::BigInteger (stub)
    static constexpr int INT_ARBITRARY = 3;  // vector<uint8_t> — asn1::ArbitraryInteger (stub)

    int     flags{0};
    int     range_bits{0};    // ceil(log2(upper - lower + 1)); 0 if unconstrained
    int     int_kind{0};      // INT_S64 / INT_U64 / INT_I128 / INT_ARBITRARY

    // Signed 64-bit bounds — read by asn1::Integer::validate()
    int64_t  lower_bound{0};
    int64_t  upper_bound{0};

    // Unsigned 64-bit bounds — read by asn1::UInteger::validate()
    uint64_t lower_u64{0};
    uint64_t upper_u64{0};

    // Signed 128-bit bounds as hi:lo pairs — for asn1::BigInteger (future)
    // Reconstruct: (__int128)lower_hi << 64 | lower_lo
    int64_t  lower_hi{0};  uint64_t lower_lo{0};
    int64_t  upper_hi{0};  uint64_t upper_lo{0};

    // Size constraint (OCTET STRING, BIT STRING, character strings)
    int     size_range_bits{0};
    int64_t size_lower{0};
    int64_t size_upper{0};

    // FROM alphabet constraint (character strings with restricted charset)
    // alphabet_bits == 0 means no FROM constraint (use per-type default bit width)
    int                   alphabet_bits{0};  // bits per character in UPER (ceil(log2(alphabet.size())))
    std::vector<uint8_t>  alphabet;          // sorted allowed char values; empty = no FROM constraint
};

} // namespace asn1
