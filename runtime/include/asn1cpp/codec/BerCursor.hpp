#pragma once
#include <span>
#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <functional>
#include "../Tag.hpp"

/// Lazy BER navigation — TLV cursor and cached layer expansion.
///
/// Indefinite-length encodings are out of scope; cursors over indefinite TLVs
/// are invalid. Multi-byte (long-form) tags are fully supported.
///
/// No codec dependency — this header must not include BerCodec.hpp.

namespace asn1 {

class BerLayer;
class BerMutableLayer;

// ── BerCursor ────────────────────────────────────────────────────────────────

/// @brief Read-only cursor over a BER sibling sequence.
///
/// Points at the current TLV within a span that may contain additional
/// siblings. Call next() to advance; find() to scan forward by tag.
class BerCursor {
public:
    BerCursor() = default;
    explicit BerCursor(std::span<const uint8_t> buf);

    bool   valid()  const { return valid_; }
    Tag    tag()    const { return tag_; }
    size_t length() const { return vlen_; }
    std::span<const uint8_t> value() const;

    /// Advance to next sibling. Returns *this (invalid if no more siblings).
    BerCursor& next();

    /// Return a BerLayer over the children of this (constructed) TLV.
    BerLayer enter() const;

    /// Scan forward through siblings for first match on class+number.
    /// Returns invalid cursor if not found.
    BerCursor find(Tag t) const;

private:
    std::span<const uint8_t> buf_;   // from start of current TLV to end of sibling buffer
    Tag    tag_{};
    size_t hdr_{0};    // bytes consumed by tag + length octets
    size_t vlen_{0};   // value bytes
    bool   valid_{false};

    void parse();
};

// ── BerMutableCursor ─────────────────────────────────────────────────────────

/// @brief Mutable BER cursor — same navigation as BerCursor plus in-place write.
///
/// The underlying buffer is mutable. write_value() patches the value bytes
/// in-place; the length field is not rewritten, so new_val.size() must equal
/// length() exactly.
class BerMutableCursor {
public:
    BerMutableCursor() = default;
    explicit BerMutableCursor(std::span<uint8_t> buf);

    bool   valid()  const { return valid_; }
    Tag    tag()    const { return tag_; }
    size_t length() const { return vlen_; }
    std::span<const uint8_t> value() const;
    std::span<uint8_t>       mutable_value();

    BerMutableCursor& next();
    BerMutableLayer   enter();
    BerMutableCursor  find(Tag t);

    /// Overwrite value bytes in place. Returns false if new_val.size() != length().
    bool write_value(std::span<const uint8_t> new_val);

    /// Return a read-only view of this cursor.
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

/// @brief Cached expansion of a constructed TLV's children.
///
/// On the first call to find() or for_each(), all siblings are scanned once
/// and cached. Subsequent calls use the cache — the buffer is never re-scanned.
class BerLayer {
public:
    explicit BerLayer(std::span<const uint8_t> data);

    /// Find first child matching class+number. Returns invalid BerCursor if absent.
    BerCursor find(Tag t) const;

    /// Invoke fn(cursor) for every child in document order.
    void for_each(std::function<void(BerCursor)> fn) const;

    /// Number of direct children (triggers expand if needed).
    size_t size() const;

private:
    struct Entry { Tag tag; size_t offset; size_t hdr; size_t vlen; };

    std::span<const uint8_t> data_;
    mutable std::vector<Entry> entries_;
    mutable bool expanded_{false};

    void expand() const;
};

// ── BerMutableLayer ──────────────────────────────────────────────────────────

class BerMutableLayer {
public:
    explicit BerMutableLayer(std::span<uint8_t> data);

    BerMutableCursor find(Tag t);
    void             for_each(std::function<void(BerMutableCursor)> fn);
    size_t           size();

    BerLayer as_const() const;

private:
    struct Entry { Tag tag; size_t offset; size_t hdr; size_t vlen; };

    std::span<uint8_t>   data_;
    mutable std::vector<Entry> entries_;
    mutable bool expanded_{false};

    void expand() const;
};

// ── Utilities ────────────────────────────────────────────────────────────────

/// Walk a path of tags into a nested BER buffer.
/// Each tag is found among siblings at that level; the match's value becomes
/// the sibling buffer for the next tag. Returns invalid cursor if any step fails.
BerCursor ber_path(std::span<const uint8_t> buf,
                   std::initializer_list<Tag> path);

/// Callback type for ber_walk: (cursor at current node, depth from root).
using BerVisitor = std::function<void(BerCursor, int depth)>;

/// Recursively walk all TLVs in buf, invoking visitor for each.
/// max_depth < 0 means unlimited.
void ber_walk(std::span<const uint8_t> buf,
              BerVisitor               visitor,
              int                      max_depth = -1);

/// Callback type for ber_find_paths: (path string, cursor at leaf node).
/// path is a slash-separated sequence of tag descriptors, e.g. "[U2]/[C0]/[U4]".
using BerPathVisitor = std::function<void(const std::string& path, BerCursor leaf)>;

/// Walk all paths in buf, invoking visitor for each node with its full path.
/// Path components use the form "[U<n>]" (Universal), "[C<n>]" (Context),
/// "[A<n>]" (Application), "[P<n>]" (Private); constructed tags get a "*" suffix.
/// max_depth < 0 means unlimited.
void ber_find_paths(std::span<const uint8_t> buf,
                    BerPathVisitor           visitor,
                    int                      max_depth = -1);

/// Collect all paths as strings (leaf nodes only when leaf_only=true).
std::vector<std::string> ber_collect_paths(std::span<const uint8_t> buf,
                                           bool leaf_only  = false,
                                           int  max_depth  = -1);

} // namespace asn1
