#pragma once
#include <string>
#include "../TypeDescriptor.hpp"

namespace asn1 {

/// @brief Constructed nesting levels a decode may descend; well above any
///        real schema's depth, well below what an 8 MiB stack survives.
///        The Rust runtime uses the same limit (`nesting::MAX_DECODE_DEPTH`).
inline constexpr int kMaxDecodeDepth = 256;

/// @brief Constructed levels the decode holding this reader has descended.
///        Each codec's reader or decode stream carries one (\c BerReader,
///        \c XerDecodeStream, \c JerDecodeStream, \c PerDecodeStream); a
///        reader opened over a nested value's bytes (a BER TLV's contents,
///        a PER open type) starts at its parent's depth. Only
///        \c DecodeDepthGuard changes it.
class DecodeDepth {
    int levels_{0};
    friend class DecodeDepthGuard;
public:
    /// @return Constructed levels entered so far, including the one whose
    ///         guard is open (1 inside the outermost constructed value).
    int levels() const { return levels_; }
};

/// @brief One level of decode nesting, held by every codec's \c decode()
///        while it decodes a SEQUENCE/SET, CHOICE or SEQUENCE OF/SET OF.
///        Past \c kMaxDecodeDepth levels \c exceeded() is true and the codec
///        returns an error instead of recursing, so a forged deeply nested
///        input (a self-referential type, X.680 §29) cannot exhaust the
///        stack. Other kinds do not count, matching the Rust walkers.
class DecodeDepthGuard {
    DecodeDepth* depth_;
public:
    /// @param depth  The depth of the reader \p def is decoded from.
    /// @param def    The type being decoded.
    DecodeDepthGuard(DecodeDepth& depth, const TypeDescriptor& def)
        : depth_(counts(def) ? &depth : nullptr) {
        if (depth_) ++depth_->levels_;
    }
    ~DecodeDepthGuard() { if (depth_) --depth_->levels_; }
    DecodeDepthGuard(const DecodeDepthGuard&) = delete;
    DecodeDepthGuard& operator=(const DecodeDepthGuard&) = delete;
    /// @return True when this level is past \c kMaxDecodeDepth.
    bool exceeded() const { return depth_ && depth_->levels_ > kMaxDecodeDepth; }
    /// @return The error message for an exceeded limit.
    static std::string message(const TypeDescriptor& def) {
        return std::string(def.name) + ": nesting deeper than " + std::to_string(kMaxDecodeDepth) + " levels";
    }
private:
    static bool counts(const TypeDescriptor& def) {
        return def.kind == TypeKind::Sequence || def.kind == TypeKind::Choice || def.kind == TypeKind::SeqOf;
    }
};

} // namespace asn1
