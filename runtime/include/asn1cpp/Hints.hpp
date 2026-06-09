#pragma once

// Branch-prediction hints. Use ASN1CPP_LIKELY/UNLIKELY around conditions
// that are almost always true/false on the hot path.
// Falls back to plain boolean on compilers without __builtin_expect.
#if defined(__GNUC__) || defined(__clang__)
#  define ASN1CPP_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define ASN1CPP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define ASN1CPP_LIKELY(x)   (x)
#  define ASN1CPP_UNLIKELY(x) (x)
#endif
