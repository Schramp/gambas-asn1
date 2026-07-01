#pragma once
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "../TypeDescriptor.hpp"

/// @file BerInspect.hpp
/// @brief Schema-free and schema-aware BER path inspection tools.
///
/// Debug / introspection utilities — not intended for hot paths.
///
/// Schema-free output uses numeric tag notation:
/// - Context tags:     `[N]`
/// - Universal tags:   `U[N]`
/// - Application tags: `A[N]`
/// - Private tags:     `P[N]`
///
/// Schema-aware output resolves ASN.1 field names via `asn_DEF` reverse-lookup
/// (O(N) per level — acceptable for diagnostic use).
///
/// Example (schema-free, leaves_only=true):
/// @code
/// ber_dump_paths(frame, std::cout);
/// // U[16]/[0]/[0]
/// // U[16]/[0]/[1]
/// // U[16]/[1]/[0]
/// @endcode
///
/// Example (schema-aware):
/// @code
/// ber_dump_paths<PS_PDU>(frame, std::cout);
/// // PS_PDU/PSHeader/LIID
/// // PS_PDU/PSHeader/timestamp
/// // PS_PDU/EncryptedPayload
/// @endcode
///
/// Example (glob search — case-insensitive, `*` matches any chars including `/`):
/// @code
/// auto paths = ber_find_paths<PS_PDU>(frame, "*liid*");
/// // → {"PS_PDU/PSHeader/LIID"}
/// @endcode

namespace asn1 {

// ── Internal (non-template) entry points ─────────────────────────────────────

/// @brief Schema-aware dump — internal entry point used by the template below.
void ber_dump_paths_impl(std::span<const uint8_t> buf,
                         const TypeDescriptor*    root_desc,
                         std::ostream&            out,
                         bool                     leaves_only);

/// @brief Schema-aware glob search — internal entry point.
std::vector<std::string> ber_find_paths_impl(std::span<const uint8_t> buf,
                                              const TypeDescriptor*    root_desc,
                                              std::string_view         glob);

// ── Public API ────────────────────────────────────────────────────────────────

/// @brief Schema-free dump: emit one path per TLV (or primitive-only when
///        \p leaves_only is true), using numeric tag notation.
///
/// @param buf         Full BER buffer (outer TLV included).
/// @param out         Destination stream.
/// @param leaves_only Emit only primitive (non-constructed) TLVs (default true).
void ber_dump_paths(std::span<const uint8_t> buf,
                    std::ostream&            out,
                    bool                     leaves_only = true);

/// @brief Schema-aware dump: resolve field names via \p RootT::asn_DEF.
///
/// Unrecognised tags (not present in the descriptor) fall back to numeric
/// notation so that the output is always complete.
///
/// @tparam RootT  Generated ASN.1 type that carries a static \c asn_DEF member.
template<typename RootT>
void ber_dump_paths(std::span<const uint8_t> buf,
                    std::ostream&            out,
                    bool                     leaves_only = true)
{
    ber_dump_paths_impl(buf, &RootT::asn_DEF, out, leaves_only);
}

/// @brief Return all paths in \p buf (schema-aware) that match \p glob.
///
/// Glob rules:
/// - `*` matches any sequence of characters (including `/` — full-path match).
/// - Matching is case-insensitive.
/// - `**` is not a distinct operator; two consecutive `*` behave as one.
///
/// @tparam RootT  Generated ASN.1 type.
/// @param buf   Full BER buffer (outer TLV included).
/// @param glob  Pattern string, e.g. `"*liid*"`, `"PS_PDU/*/timestamp"`.
/// @return      Paths matching the pattern, in traversal order.
template<typename RootT>
std::vector<std::string> ber_find_paths(std::span<const uint8_t> buf,
                                         std::string_view         glob)
{
    return ber_find_paths_impl(buf, &RootT::asn_DEF, glob);
}

} // namespace asn1
