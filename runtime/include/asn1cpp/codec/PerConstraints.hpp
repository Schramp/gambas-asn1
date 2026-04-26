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

    int     flags{0};
    int     range_bits{0};    // ceil(log2(upper - lower + 1)); 0 if unconstrained
    int64_t lower_bound{0};
    int64_t upper_bound{0};

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
