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
#include <string>
#include <vector>
#include <cstdint>
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

#if defined(ASN1CPP_VALIDATE_REPORT)

// Per-failure record captured by the codec when a ValidationReport is active.
// path is dotted ("Foo.bar.items[3].n") — composite codec paths push/pop
// member names + element indices as they recurse.
struct ValidationFailure {
    std::string path;
    const char* type_name = nullptr;
    int64_t     delta = 0;
    bool        on_decode = false;
};

struct ValidationReport {
    std::vector<ValidationFailure> failures;
    bool empty() const { return failures.empty(); }
    void clear() { failures.clear(); }
};

namespace detail {
inline ValidationReport*& current_validation_report() {
    thread_local ValidationReport* r = nullptr;
    return r;
}
// Path stack stores tagged segments: either a member name (const char*) or
// an element index (size_t). Formatted lazily in current_validate_path() so
// codec hot paths never call snprintf or construct std::string per element.
struct PathSeg {
    bool is_index;
    union { const char* name; std::size_t index; };
};
inline std::vector<PathSeg>& validate_path_stack() {
    thread_local std::vector<PathSeg> s;
    return s;
}
} // namespace detail

inline void set_validation_report(ValidationReport* r) {
    detail::current_validation_report() = r;
}
inline ValidationReport* current_validation_report() {
    return detail::current_validation_report();
}

inline void push_validate_path(const char* name) {
    detail::validate_path_stack().push_back({false, {.name = name}});
}
inline void push_validate_path(std::size_t index) {
    detail::validate_path_stack().push_back({true, {.index = index}});
}
inline void pop_validate_path() {
    auto& s = detail::validate_path_stack();
    if (!s.empty()) s.pop_back();
}
inline std::string current_validate_path() {
    std::string out;
    for (const auto& seg : detail::validate_path_stack()) {
        if (seg.is_index) {
            out += '['; out += std::to_string(seg.index); out += ']';
        } else {
            if (!out.empty() && seg.name[0] != '[') out += '.';
            out += seg.name;
        }
    }
    return out;
}

inline void record_validate_fail(const char* type_name, int64_t delta, bool on_decode) {
    if (auto* r = current_validation_report()) {
        r->failures.push_back({current_validate_path(), type_name, delta, on_decode});
    }
}

// RAII helpers — push/pop a path segment around a scope.
// Takes const char* for member names, std::size_t for element indices.
// Formatting to string is deferred until current_validate_path() is called.
struct ValidatePathScope {
    explicit ValidatePathScope(const char* name)  { push_validate_path(name); }
    explicit ValidatePathScope(std::size_t index) { push_validate_path(index); }
    ~ValidatePathScope() { pop_validate_path(); }
    ValidatePathScope(const ValidatePathScope&) = delete;
    ValidatePathScope& operator=(const ValidatePathScope&) = delete;
};

// RAII helper — set + clear the active report pointer.
struct ValidationReportScope {
    explicit ValidationReportScope(ValidationReport& r) { set_validation_report(&r); }
    ~ValidationReportScope() { set_validation_report(nullptr); }
    ValidationReportScope(const ValidationReportScope&) = delete;
    ValidationReportScope& operator=(const ValidationReportScope&) = delete;
};

#else

// Stub: when ASN1CPP_VALIDATE_REPORT is OFF, the path-tracking and report
// machinery compiles to no-ops so callers can use the same code path
// unconditionally.
struct ValidationFailure {};
struct ValidationReport { bool empty() const { return true; } void clear() {} };
inline void set_validation_report(ValidationReport*) {}
inline ValidationReport* current_validation_report() { return nullptr; }
inline void push_validate_path(const char*) {}
inline void push_validate_path(std::size_t) {}
inline void pop_validate_path() {}
inline std::string current_validate_path() { return {}; }
inline void record_validate_fail(const char*, int64_t, bool) {}
struct ValidatePathScope {
    explicit ValidatePathScope(const char*)  {}
    explicit ValidatePathScope(std::size_t) {}
};
struct ValidationReportScope { explicit ValidationReportScope(ValidationReport&) {} };

#endif // ASN1CPP_VALIDATE_REPORT

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
