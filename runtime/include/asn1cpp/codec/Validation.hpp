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
#include "ICodec.hpp"

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

// Caller-selectable validation policy for the encode_validated / decode_validated
// helpers below. Lenient = bump counter only (current Postel default); Strict =
// also surface a hard failure to the caller.
enum class ValidationPolicy { Lenient, Strict };

// Encode wrapper that reports whether any validate-fail occurred during this
// encode. When ASN1CPP_VALIDATE is OFF, always returns true. Strict policy is
// not meaningful for encode (output bytes are already written by the time we
// know); the bool is the API. Caller may treat false as a hard error.
inline bool encode_validated(const ICodec& codec, IEncodeStream& dst,
                             const TypeDescriptor& def, const void* src) {
#if defined(ASN1CPP_VALIDATE)
    auto before = validate_fail_count();
    codec.encode(dst, def, src);
    return validate_fail_count() == before;
#else
    codec.encode(dst, def, src);
    return true;
#endif
}

// Decode wrapper. In Strict mode, any validate-fail observed during decode
// (counted via the global counter) is converted into a DecodeError; the
// caller-side dest object remains populated but the result reports failure.
// Lenient mode is identical to calling codec.decode() directly.
inline DecodeResult decode_validated(const ICodec& codec, IDecodeStream& src,
                                     const TypeDescriptor& def, void* dest,
                                     ValidationPolicy policy = ValidationPolicy::Lenient) {
#if defined(ASN1CPP_VALIDATE)
    auto before = validate_fail_count();
    auto res = codec.decode(src, def, dest);
    if (!res) return res;
    if (policy == ValidationPolicy::Strict && validate_fail_count() != before)
        return decode_err(DecodeError("validation failure"));
    return res;
#else
    (void)policy;
    return codec.decode(src, def, dest);
#endif
}

} // namespace asn1
