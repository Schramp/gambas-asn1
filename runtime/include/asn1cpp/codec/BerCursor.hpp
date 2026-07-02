#pragma once
#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <functional>
#include "../Tag.hpp"

/// @file BerCursor.hpp
/// @brief Lazy BER navigation — zero-copy TLV cursor and cached layer expansion.
///
/// Indefinite-length encodings are out of scope; a cursor positioned over an
/// indefinite-length TLV reports \c valid()==false.  Multi-byte (long-form)
/// tags are fully supported (required for ETSI-LI context tags ≥ 31).
///
/// No codec dependency — this header must not include BerCodec.hpp.
///
/// Typical usage:
/// @code
/// // Navigate a SEQUENCE { [0] liid, [1] timestamp } inside a raw frame
/// BerLayer frame{raw_bytes};
/// auto liid_cursor = frame.find(Tag{TagClass::Context, 0});
/// if (liid_cursor.valid())
///     process(liid_cursor.value());
///
/// // Walk an entire nested structure
/// ber_walk(raw_bytes, [](BerCursor c, int depth) {
///     printf("%*stag %u len %zu\n", depth*2, "", c.tag().number, c.length());
/// });
/// @endcode
///
/// @see X.690 §8 — BER TLV structure.

namespace asn1 {

class BerLayer;
class BerMutableLayer;

// ── BerCursor ────────────────────────────────────────────────────────────────

/// @brief Read-only cursor positioned at one TLV within a BER sibling sequence.
///
/// The cursor holds a view from the current TLV's first byte to the end of the
/// sibling buffer, so \c next() is a constant-time pointer advance.
///
/// A default-constructed cursor, a cursor over an empty buffer, or one that
/// reaches the end of its siblings all report \c valid()==false.  All accessors
/// are safe to call on an invalid cursor (tag()/length() return defaults;
/// value() returns an empty span).
///
/// Tag matching (\c find()) compares \c TagClass and tag number only — the
/// constructed bit is an encoding detail, not a type identity.
///
/// @see X.690 §8.1 — Structure of an encoding.
class BerCursor {
public:
    /// @brief Construct an invalid (sentinel) cursor.
    BerCursor() = default;

    /// @brief Construct a cursor over \p buf, positioned at the first TLV.
    /// @param buf  Byte span starting at the first tag byte; may contain
    ///             multiple sibling TLVs.  Must outlive this cursor.
    explicit BerCursor(std::span<const uint8_t> buf);

    /// @brief True when the cursor points at a valid, complete TLV.
    bool   valid()  const { return valid_; }

    /// @brief Tag of the current TLV (class, number, constructed bit).
    Tag    tag()    const { return tag_; }

    /// @brief Number of value bytes in the current TLV (excluding tag+length header).
    size_t length() const { return vlen_; }

    /// @brief Zero-copy view of the value bytes.  Empty when \c valid()==false.
    std::span<const uint8_t> value() const;

    /// @brief Advance to the next sibling TLV.
    /// @return \c *this; becomes invalid when no more siblings exist.
    BerCursor& next();

    /// @brief Return a \c BerLayer that expands the children of this TLV.
    ///
    /// Only meaningful when \c tag().constructed is true.  Calling \c enter()
    /// on a primitive TLV yields a layer that expands to zero children.
    BerLayer enter() const;

    /// @brief Scan forward through siblings for the first TLV matching \p t.
    ///
    /// Matching is on \c TagClass and tag number; the constructed bit is ignored.
    /// Scanning starts at the current position (inclusive) and is linear — no
    /// caching.  Use \c BerLayer::find() for repeated lookups at the same level.
    ///
    /// @param t  Tag to search for.
    /// @return   Cursor positioned at the first match, or an invalid cursor.
    BerCursor find(Tag t) const;

private:
    std::span<const uint8_t> buf_;  ///< Start of current TLV to end of sibling buffer.
    Tag    tag_{};
    size_t hdr_{0};   ///< Bytes consumed by tag + length octets.
    size_t vlen_{0};  ///< Value bytes.
    bool   valid_{false};

    void parse();
};

// ── BerMutableCursor ─────────────────────────────────────────────────────────

/// @brief Mutable BER cursor — same navigation as \c BerCursor plus in-place write.
///
/// The underlying buffer is mutable.  \c write_value() patches the value bytes
/// in-place without touching the tag or length fields, so the replacement must
/// be exactly \c length() bytes.
///
/// @see BerCursor — read-only counterpart with identical navigation semantics.
class BerMutableCursor {
public:
    /// @brief Construct an invalid (sentinel) cursor.
    BerMutableCursor() = default;

    /// @brief Construct a mutable cursor over \p buf, positioned at the first TLV.
    /// @param buf  Mutable byte span starting at the first tag byte.
    ///             Must outlive this cursor.
    explicit BerMutableCursor(std::span<uint8_t> buf);

    /// @brief True when the cursor points at a valid, complete TLV.
    bool   valid()  const { return valid_; }

    /// @brief Tag of the current TLV.
    Tag    tag()    const { return tag_; }

    /// @brief Number of value bytes.
    size_t length() const { return vlen_; }

    /// @brief Read-only view of the value bytes.
    std::span<const uint8_t> value() const;

    /// @brief Mutable view of the value bytes.
    std::span<uint8_t> mutable_value();

    /// @brief Advance to the next sibling TLV.
    /// @return \c *this; becomes invalid when no more siblings exist.
    BerMutableCursor& next();

    /// @brief Return a \c BerMutableLayer over the children of this TLV.
    BerMutableLayer enter();

    /// @brief Scan forward for the first sibling matching \p t (class+number).
    /// @return Mutable cursor at the match, or an invalid cursor.
    BerMutableCursor find(Tag t);

    /// @brief Overwrite the value bytes in place.
    ///
    /// The tag and length fields are never modified, so the BER framing of
    /// enclosing TLVs remains valid.  The replacement must be exactly \c length()
    /// bytes; a size mismatch returns \c false without writing anything.
    ///
    /// @param new_val  Replacement bytes.
    /// @return \c true on success; \c false if \c new_val.size() != length()
    ///         or the cursor is invalid.
    bool write_value(std::span<const uint8_t> new_val);

    /// @brief Return a read-only \c BerCursor over the same buffer position.
    BerCursor as_const() const;

private:
    std::span<uint8_t> buf_;
    Tag    tag_{};
    size_t hdr_{0};
    size_t vlen_{0};
    bool   valid_{false};

    void parse();
};

// ── BerLayer ─────────────────────────────────────────────────────────────────

/// @brief Cached expansion of the direct children of a constructed TLV.
///
/// On the first call to \c find(), \c for_each(), or \c size(), all sibling
/// TLVs in the underlying value bytes are scanned once and cached.  Subsequent
/// calls reuse the cache — the buffer is never re-scanned.
///
/// Construct a \c BerLayer via \c BerCursor::enter() or directly from a known
/// value span:
/// @code
/// BerLayer layer{outer_cursor.value()};
/// auto child = layer.find(Tag{TagClass::Context, 3});
/// @endcode
class BerLayer {
public:
    /// @brief Construct a layer over \p data (typically a TLV's value bytes).
    /// @param data  Byte span covering zero or more sibling TLVs.
    ///              Must outlive this layer.
    explicit BerLayer(std::span<const uint8_t> data);

    /// @brief Find the first child whose class and tag number match \p t.
    ///
    /// Triggers expansion on the first call.  Constructed bit is ignored.
    ///
    /// @return \c BerCursor at the matching child, or an invalid cursor.
    BerCursor find(Tag t) const;

    /// @brief Invoke \p fn once per child in document order.
    ///
    /// Triggers expansion on the first call.
    ///
    /// @param fn  Callable accepting a \c BerCursor positioned at each child.
    void for_each(std::function<void(BerCursor)> fn) const;

    /// @brief Number of direct children (triggers expansion on first call).
    size_t size() const;

private:
    struct Entry { Tag tag; size_t offset; size_t hdr; size_t vlen; };

    std::span<const uint8_t>   data_;
    mutable std::vector<Entry> entries_;
    mutable bool               expanded_{false};

    void expand() const;
};

// ── BerMutableLayer ──────────────────────────────────────────────────────────

/// @brief Mutable variant of \c BerLayer — same expand-once caching plus
///        mutable child cursors for in-place patching.
///
/// @see BerLayer — read-only counterpart.
class BerMutableLayer {
public:
    /// @brief Construct a mutable layer over \p data.
    /// @param data  Mutable byte span covering zero or more sibling TLVs.
    ///              Must outlive this layer.
    explicit BerMutableLayer(std::span<uint8_t> data);

    /// @brief Find the first child matching \p t (class+number).
    /// @return Mutable cursor at the match, or an invalid cursor.
    BerMutableCursor find(Tag t);

    /// @brief Invoke \p fn once per child in document order.
    /// @param fn  Callable accepting a \c BerMutableCursor at each child.
    void for_each(std::function<void(BerMutableCursor)> fn);

    /// @brief Number of direct children (triggers expansion on first call).
    size_t size();

    /// @brief Return a read-only \c BerLayer view over the same buffer.
    BerLayer as_const() const;

private:
    struct Entry { Tag tag; size_t offset; size_t hdr; size_t vlen; };

    std::span<uint8_t>         data_;
    mutable std::vector<Entry> entries_;
    mutable bool               expanded_{false};

    void expand() const;
};

// ── Utilities ────────────────────────────────────────────────────────────────

/// @brief Navigate a multi-level tag path into a nested BER buffer.
///
/// For each tag in \p path: find the first matching sibling at the current
/// level, then descend into its value bytes for the next step.  If any step
/// fails (tag not found, or preceding cursor invalid), returns an invalid cursor.
///
/// @code
/// // Navigate outer[0] → inner[1] → leaf[2]
/// auto c = ber_path(frame, {ctx(0), ctx(1), ctx(2)});
/// if (c.valid()) use(c.value());
/// @endcode
///
/// @param buf   Raw BER byte span (covers one or more sibling TLVs).
/// @param path  Ordered list of tags, outermost first.
/// @return      Cursor at the final matched TLV, or an invalid cursor on failure.
BerCursor ber_path(std::span<const uint8_t>    buf,
                   std::initializer_list<Tag>   path);

/// @brief Callback type for \c ber_walk.
///
/// @param cursor  Cursor positioned at the current TLV.
/// @param depth   Nesting depth from the root (0 = top-level sibling).
using BerVisitor = std::function<void(BerCursor cursor, int depth)>;

/// @brief Recursively walk every TLV in \p buf, invoking \p visitor at each node.
///
/// Children of a constructed TLV are visited after the parent (pre-order).
/// Primitive TLVs are not recursed into.
///
/// @param buf        Raw BER byte span.
/// @param visitor    Callable invoked at each TLV.
/// @param max_depth  Maximum recursion depth; negative = unlimited.
void ber_walk(std::span<const uint8_t> buf,
              BerVisitor               visitor,
              int                      max_depth = -1);

} // namespace asn1
