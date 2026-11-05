#pragma once
#include <cstddef>
#include <string>
#include "../TypeDescriptor.hpp"

namespace asn1 {

/// @brief Constructed nesting levels a decode may descend; well above any
///        real schema's depth, well below what an 8 MiB stack survives.
///        The Rust runtime uses the same limit (`nesting::MAX_DECODE_DEPTH`).
inline constexpr int kMaxDecodeDepth = 256;

#ifndef ASN1CPP_MAX_ZERO_WIDTH_ITEMS
#define ASN1CPP_MAX_ZERO_WIDTH_ITEMS 200
#endif

/// @brief Item count above which a PER SEQUENCE OF/SET OF may not hold an
///        element encoded in zero bits (NULL, X.691 §18; an INTEGER or
///        ENUMERATED with a single value, §11.1.3). Such elements cost no
///        input, so a few octets of length determinant (X.691 §11.9.3.8)
///        would otherwise allocate millions of them. asn1c applies the same rule with 200
///        (constr_SET_OF_uper.c). Set at build time with
///        \c -DASN1CPP_MAX_ZERO_WIDTH_ITEMS=N. The Rust and Java runtimes use
///        the same limit (\c nesting::MAX_ZERO_WIDTH_ITEMS,
///        \c Nesting.MAX_ZERO_WIDTH_ITEMS).
inline constexpr std::size_t kMaxZeroWidthItems = ASN1CPP_MAX_ZERO_WIDTH_ITEMS;

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
