#pragma once
#include <atomic>

// Thin counter API used by generated set_<member>() helpers and codec internals.
// Kept separate from Validation.hpp so generated headers can include it
// without pulling in codec infrastructure.

namespace asn1 {

namespace detail {
inline std::atomic<unsigned long long>& validate_fail_counter() {
    static std::atomic<unsigned long long> n{0};
    return n;
}
} // namespace detail

inline unsigned long long validate_fail_count() {
    return detail::validate_fail_counter().load(std::memory_order_relaxed);
}
inline void reset_validate_fail_count() {
    detail::validate_fail_counter().store(0, std::memory_order_relaxed);
}
inline void bump_validate_fail() {
    detail::validate_fail_counter().fetch_add(1, std::memory_order_relaxed);
}

} // namespace asn1
