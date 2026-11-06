#pragma once

// The runtime's version. It is the top-level VERSION file's (the CMake
// configure step checks that), the same as the compiler's, because
// generated code uses the runtime API of the compiler that produced it.
#define ASN1CPP_RUNTIME_VERSION_MAJOR 0
#define ASN1CPP_RUNTIME_VERSION_MINOR 1
#define ASN1CPP_RUNTIME_VERSION_PATCH 0
#define ASN1CPP_RUNTIME_VERSION "0.1.0"

namespace asn1 {

/// @brief Whether this runtime is version @p major.@p minor.@p patch. Every
///        generated header checks its compiler's version with it in a
///        static_assert, so generated code does not compile against a
///        runtime of another version.
/// @param major Major version of the compiler that generated the code.
/// @param minor Minor version.
/// @param patch Patch version.
/// @return True when the runtime is that version.
consteval bool runtime_version_is(int major, int minor, int patch) {
    return major == ASN1CPP_RUNTIME_VERSION_MAJOR && minor == ASN1CPP_RUNTIME_VERSION_MINOR
        && patch == ASN1CPP_RUNTIME_VERSION_PATCH;
}

}  // namespace asn1
