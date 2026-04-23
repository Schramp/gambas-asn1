#pragma once
#include <cstdint>

namespace asn1 {

// PER constraint metadata for a single type or member.
// Stored in the descriptor table; generated as nullptr/0 until PER codegen is active.
struct PerConstraints {
    static constexpr int CONSTRAINED      = 1;
    static constexpr int SEMI_CONSTRAINED = 2;
    static constexpr int EXTENSIBLE       = 4;

    int     flags;
    int     range_bits;    // ceil(log2(upper - lower + 1)); 0 if unconstrained
    int64_t lower_bound;
    int64_t upper_bound;

    // Size constraint (OCTET STRING, BIT STRING, character strings)
    int     size_range_bits;
    int64_t size_lower;
    int64_t size_upper;
};

} // namespace asn1
