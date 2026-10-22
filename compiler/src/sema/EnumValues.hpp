#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>
#include "../ast/TypeDef.hpp"

namespace asn1::sema {

/// @brief Numeric value of every ENUMERATED item, in declaration order.
///
/// Root items without a number take the next value after the previous one
/// (starting at 0); extension items continue after the largest root value.
/// The "..." marker entry gets 0 and must be skipped by the caller.
/// @see X.680 §20.2, §20.6
inline std::vector<int64_t> enumerated_values(const std::vector<ast::EnumValue>& evs) {
    int n = static_cast<int>(evs.size());
    int ext_start = n;
    for (int i = 0; i < n; ++i)
        if (evs[i].name == "...") { ext_start = i; break; }
    std::vector<int64_t> vals(n, 0);
    int64_t next = 0;
    for (int i = 0; i < ext_start; ++i) {
        vals[i] = evs[i].number.value_or(next);
        next = vals[i] + 1;
    }
    int64_t max_root = ext_start > 0 ? *std::max_element(vals.begin(), vals.begin() + ext_start) : -1;
    next = max_root + 1;
    for (int i = ext_start + 1; i < n; ++i) {
        if (evs[i].name == "...") continue;
        vals[i] = evs[i].number.value_or(next);
        next = vals[i] + 1;
    }
    return vals;
}

} // namespace asn1::sema
