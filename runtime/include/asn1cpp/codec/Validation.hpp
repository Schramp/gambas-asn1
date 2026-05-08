#pragma once
// Compile-time-toggleable validation hooks for asn1cpp codec.
//
// Tiers (controlled via CMake options that emit -D macros):
//   ASN1CPP_VALIDATE              — master switch; without it all hooks vanish.
//   ASN1CPP_VALIDATE_ON_ENCODE    — call validate() inside BerCodec::encode.
//   ASN1CPP_VALIDATE_ON_SET       — call validate() inside type setters (future).
//   ASN1CPP_VALIDATE_REPORT       — collect detailed ValidationReport (future).
//
// API (always declared; bodies stubbed when ASN1CPP_VALIDATE undefined):
//   validate_fail_count()         — running count of validate-fail events.
//   reset_validate_fail_count()   — zero the counter.
//   bump_validate_fail()          — internal; codec calls this on non-zero
//                                   delta from validate(def, obj).
//
// The counter is the bool-tier diagnostic API. It exists so unit tests can
// assert that intentionally-invalid encodes triggered validate-fail without
// scraping stderr.

#include <atomic>

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
