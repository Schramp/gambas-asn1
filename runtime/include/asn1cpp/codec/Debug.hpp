#pragma once
#include <cstdlib>

namespace asn1 {

// Debug bitmask — set ASN1CPP_DEBUG=<hex> at runtime to enable traces.
// The value is read once on first call; subsequent calls return the cached result.
enum DebugFlag : unsigned {
    DBG_BER_CHOICE = 1u << 0,   // CHOICE tag miss / alternative dispatch
    DBG_BER_SEQ    = 1u << 1,   // SEQUENCE EXPLICIT wrap/unwrap, tag mismatches
    DBG_XER        = 1u << 2,   // XER parse / emit
    DBG_PER        = 1u << 3,   // PER bit-level ops
};

inline unsigned debug_flags() {
    static unsigned flags = [] {
        const char* e = std::getenv("ASN1CPP_DEBUG");
        if (!e || !*e) return 0u;
        return static_cast<unsigned>(std::strtoul(e, nullptr, 0));
    }();
    return flags;
}

} // namespace asn1
