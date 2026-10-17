#pragma once
#include <string>
#include "../TypeDescriptor.hpp"

namespace asn1 {

/// @brief Constructed nesting levels a decode may descend; well above any
///        real schema's depth, well below what an 8 MiB stack survives.
///        The Rust runtime uses the same limit (`nesting::MAX_DECODE_DEPTH`).
inline constexpr int kMaxDecodeDepth = 256;

/// @brief One level of decode nesting, held by every codec's \c decode()
///        while it decodes a SEQUENCE/SET, CHOICE or SEQUENCE OF/SET OF.
///        Past \c kMaxDecodeDepth levels \c exceeded() is true and the codec
///        returns an error instead of recursing, so a forged deeply nested
///        input (a self-referential type, X.680 §29) cannot exhaust the
///        stack. Primitive types do not count.
class DecodeDepthGuard {
    bool counted_;
    static int& depth() { thread_local int d = 0; return d; }
public:
    explicit DecodeDepthGuard(const TypeDescriptor& def)
        : counted_(def.kind != TypeKind::Primitive) {
        if (counted_) ++depth();
    }
    ~DecodeDepthGuard() { if (counted_) --depth(); }
    DecodeDepthGuard(const DecodeDepthGuard&) = delete;
    DecodeDepthGuard& operator=(const DecodeDepthGuard&) = delete;
    /// @return True when this level is past \c kMaxDecodeDepth.
    bool exceeded() const { return counted_ && depth() > kMaxDecodeDepth; }
    /// @return The error message for an exceeded limit.
    static std::string message(const TypeDescriptor& def) {
        return std::string(def.name) + ": nesting deeper than " + std::to_string(kMaxDecodeDepth) + " levels";
    }
};

} // namespace asn1
