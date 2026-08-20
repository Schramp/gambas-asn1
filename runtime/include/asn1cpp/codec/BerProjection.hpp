#pragma once
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "../Asn1Optional.hpp"
#include "../Tag.hpp"
#include "../TypeDescriptor.hpp"

/// @file BerProjection.hpp
/// @brief Startup-time path registration and trie construction for lazy BER projection.
///
/// Build a \c BerProjection once at program startup, then share it read-only
/// across threads.  Each worker thread holds its own \c BerProjectionResult
/// which points into this trie.
///
/// Typical usage:
/// @code
/// // Startup (once, not thread-safe):
/// BerProjection proj{MyMessage::asn_DEF};
/// auto h_id  = proj.add_path("Header/sender/id");
/// auto h_ts  = proj.add_path("Header/timestamp");
/// auto h_val = proj.add_path("Body/value");  // Body is a CHOICE; value is one alternative
/// proj.finalize();
///
/// // Per thread:
/// BerProjectionResult res{proj};
/// res.bind(h_id, my_id);
/// while (auto frame = next_frame()) {
///     res.apply(frame);
///     if (my_id.found) use(static_cast<VisibleString&>(my_id));
/// }
/// @endcode
///
/// No codec dependency — this header must not include BerCodec.hpp.

namespace asn1 {

// ── TrieNode ─────────────────────────────────────────────────────────────────

/// @brief One node in the flat arena trie used by \c BerProjection.
///
/// Nodes are stored in a \c std::vector<TrieNode> (cache-friendly, no per-node
/// heap allocation).  Children and siblings are addressed by index; \c SIZE_MAX
/// serves as the null sentinel.
///
/// During \c BerProjectionResult::apply(), the engine walks this trie alongside
/// the BER TLV stream:
/// - At each level, scan siblings for a tag matching the current TLV.
/// - If \c is_choice is true, the matched node's value bytes contain a CHOICE —
///   descend one more level to match an alternative tag among the node's children.
/// - If \c field_index != SIZE_MAX, this is a leaf: populate the bound
///   \c Asn1OptionalBase slot at that index.
struct TrieNode {
    Tag                   tag;                       ///< Wire tag to match (class + number; constructed bit ignored).
    size_t                first_child  = SIZE_MAX;   ///< Index of first child node; SIZE_MAX = leaf.
    size_t                next_sibling = SIZE_MAX;   ///< Index of next sibling node; SIZE_MAX = last sibling.
    size_t                field_index  = SIZE_MAX;   ///< Result-slot index; SIZE_MAX = interior node only.
    bool                  is_choice    = false;      ///< True when this node's value is a CHOICE: children are alternatives.
                                                     ///< Always \c false on leaf nodes — leaves capture value bytes whole;
                                                     ///< no alternative-scanning is needed regardless of the leaf's type kind.
    const TypeDescriptor* node_desc    = nullptr;    ///< TypeDescriptor at this level (used for introspection, e.g. BerInspect path dumping).
};

// ── FieldHandle ───────────────────────────────────────────────────────────────

/// @brief Opaque handle returned by \c BerProjection::add_path().
///
/// Pass to \c BerProjectionResult::bind() to link a target \c Asn1Optional<T>
/// to this field's result slot.  The engine checks \c leaf_descriptor against
/// the bound optional's \c desc to catch type mismatches at bind time.
struct FieldHandle {
    size_t                index;            ///< Slot index in the \c BerProjectionResult slot vector.
    const TypeDescriptor* leaf_descriptor;  ///< \c &T::asn_DEF at the leaf path component.
};

// ── BerProjection ─────────────────────────────────────────────────────────────

/// @brief Read-only, thread-safe trie built once at startup from field paths.
///
/// \c add_path() resolves each "/" -separated field name against the root type's
/// descriptor tables (\c sequence_spec->members or \c choice_spec->alternatives),
/// inserting \c TrieNode entries into a flat arena.  Common path prefixes produce
/// shared trie nodes.
///
/// After all paths are registered, call \c finalize() to seal the trie.
/// The sealed \c BerProjection is immutable and safe to share across threads.
///
/// ### Path format
/// A path is a sequence of ASN.1 member (or alternative) names separated by `/`,
/// navigating from the root type down to the target leaf field.  The root type
/// name itself is **not** part of the path.
///
/// @code
/// // For root type MyMessage:
/// proj.add_path("Header/sender/id");
/// proj.add_path("Body/value");   // Body is a CHOICE; value is one alternative
/// @endcode
///
/// @throws std::runtime_error  If any path component is not found in the
///                             descriptor tables, or if the intermediate type
///                             is neither SEQUENCE nor CHOICE.
class BerProjection {
public:
    /// @brief Construct from the root ASN.1 type descriptor.
    /// @param root  \c TypeDescriptor of the outermost type (e.g. \c MyMessage::asn_DEF).
    ///              Must outlive this \c BerProjection.
    explicit BerProjection(const TypeDescriptor& root);

    /// @brief Register a field path and return its handle.
    ///
    /// Resolves each `/`-separated component against the descriptor tables,
    /// reusing existing trie nodes for shared prefixes.
    ///
    /// @param path  Field path from the root type's members, e.g. \c "Header/sender/id".
    /// @return      Handle carrying the result-slot index and leaf \c TypeDescriptor*.
    /// @throws std::runtime_error  Unknown field name, wrong type kind, or called
    ///                             after \c finalize().
    FieldHandle add_path(std::string_view path);

    /// @brief Seal the trie.  No further \c add_path() calls are permitted.
    ///
    /// Must be called before constructing any \c BerProjectionResult.
    void finalize();

    /// @brief Number of distinct leaf fields registered.
    ///
    /// Equals the slot-vector size that \c BerProjectionResult must allocate.
    ///
    /// @pre \c finalize() has been called.
    size_t leaf_count() const;

    /// @brief Return all registered paths, indexed by their \c FieldHandle::index.
    ///
    /// Duplicate paths (same path registered twice) appear only once.
    /// The vector is stable after \c finalize(); indices match \c FieldHandle::index.
    ///
    /// @pre \c finalize() has been called.
    const std::vector<std::string>& list_paths() const;

    /// @brief Read-only access to the flat node arena (used by \c BerProjectionResult).
    const std::vector<TrieNode>& nodes() const { return nodes_; }

    /// @brief Index of the first root-level trie node (SIZE_MAX if trie is empty).
    size_t root_first_child() const { return root_first_child_; }

private:
    const TypeDescriptor* root_;
    std::vector<TrieNode> nodes_;
    std::vector<std::string> paths_;          ///< Registered paths indexed by FieldHandle::index.
    size_t                root_first_child_{SIZE_MAX};
    size_t                leaf_count_{0};
    bool                  finalized_{false};

    /// @brief Return the index of an existing node with tag \p t in the sibling
    ///        chain starting at \p parent_idx's first_child (or root level when
    ///        \p parent_idx == SIZE_MAX).  If absent, insert a new node and link it.
    size_t ensure_node(size_t               parent_idx,
                       Tag                  t,
                       const TypeDescriptor* desc,
                       bool                 is_choice);
};

// ── BerProjectionResult ───────────────────────────────────────────────────────

/// @brief Per-thread result object that binds field handles to target optionals
///        and drives the trie-based partial BER decode.
///
/// One \c BerProjectionResult per thread.  The shared \c BerProjection trie is
/// read-only and safe to access from multiple threads simultaneously.
///
/// Typical usage:
/// @code
/// // Startup (once per thread):
/// BerProjectionResult res{proj};
/// Asn1Optional<VisibleString>   liid;
/// Asn1Optional<GeneralizedTime> ts;
/// res.bind(h_liid, liid);
/// res.bind(h_ts,   ts);
///
/// // Hot loop — zero allocation:
/// while (auto frame = next_frame()) {
///     res.apply(frame);
///     if (liid.found) route(static_cast<VisibleString&>(liid), frame);
/// }
///
/// // In-place patch (requires mutable frame):
/// res.apply(mutable_frame);
/// if (liid.found) {
///     static_cast<VisibleString&>(liid) = "NEW_VAL";
///     res.commit(h_liid);
/// }
/// @endcode
///
/// @note Only IMPLICIT-tagged fields support \c commit() — EXPLICIT tagging
///       causes a size mismatch (commit returns false, frame unchanged).
class BerProjectionResult {
public:
    /// @brief Construct a result object bound to \p proj.
    ///
    /// \p proj must be finalized before calling this constructor.
    /// Allocates slot storage sized to \c proj.leaf_count().
    ///
    /// @param proj  Finalized projection trie; must outlive this result.
    explicit BerProjectionResult(const BerProjection& proj);

    /// @brief Link field handle \p h to target optional \p target.
    ///
    /// Asserts that \p T is type-compatible with the leaf registered at \p h:
    /// either the same \c TypeDescriptor pointer, or the same non-null
    /// \c ber_handler (catches pointer mismatch for generated per-member
    /// descriptors that describe the same primitive type as the generic one).
    /// May be called multiple times; each call replaces any prior binding for \p h.
    ///
    /// @tparam T  Generated ASN.1 type inheriting \c Asn1Object and carrying \c asn_DEF.
    /// @param h       FieldHandle returned by \c BerProjection::add_path().
    /// @param target  Optional wrapper whose \c found flag and value \c BerCodec fills.
    template<typename T>
    void bind(FieldHandle h, Asn1Optional<T>& target) {
        bind_impl(h, target, &T::asn_DEF);
    }

    /// @brief Apply the projection to a read-only frame.
    ///
    /// Clears all bound optionals (\c found = false), then walks the frame
    /// bytes using the trie.  Each matched leaf is decoded via
    /// \c BerCodec::instance().decode_value() into the bound optional.
    /// After this call, \c commit() is not permitted.
    ///
    /// Zero per-call heap allocation.
    ///
    /// @param frame  Complete BER-encoded outer TLV of the root type.
    void apply(std::span<const uint8_t> frame);

    /// @brief Apply the projection to a mutable frame, enabling \c commit().
    ///
    /// Identical to the read-only overload but additionally records the mutable
    /// frame pointer so that \c commit() may write back encoded values.
    ///
    /// @param frame  Mutable BER buffer; must outlive any subsequent \c commit() call.
    void apply(std::span<uint8_t> frame);

    /// @brief Decode one field on demand without a prior \c bind().
    ///
    /// Requires that \c apply() has already been called on the current frame.
    /// If the field was found during \c apply(), decodes its captured bytes into
    /// \p target.  Otherwise leaves \p target unchanged.
    ///
    /// Useful for rarely-accessed fields where permanent binding is not desired.
    ///
    /// @tparam T  Generated ASN.1 type.
    /// @param h       FieldHandle returned by \c BerProjection::add_path().
    /// @param target  Optional wrapper to decode into.
    template<typename T>
    void load(FieldHandle h, Asn1Optional<T>& target) {
        load_impl(h, target, &T::asn_DEF);
    }

    /// @brief Encode the current value of the bound optional for \p h and
    ///        write it back into the mutable frame in-place.
    ///
    /// The re-encoded value bytes must be exactly the same number of bytes as
    /// the bytes captured during the preceding \c apply(mutable).  Any size
    /// difference returns \c false without modifying the frame.
    ///
    /// @pre A mutable \c apply() must have been called since the last read-only \c apply().
    /// @pre The bound optional's \c found flag must be \c true.
    ///
    /// @param h  FieldHandle whose bound value to commit.
    /// @return   \c true when the frame was updated; \c false on size mismatch,
    ///           unbound handle, or unfound field.
    bool commit(FieldHandle h);

private:
    void bind_impl(FieldHandle h, Asn1OptionalBase& target, const TypeDescriptor* desc);
    void load_impl(FieldHandle h, Asn1OptionalBase& target, const TypeDescriptor* desc);

    /// @brief Trie-driven walk: scan \p buf for trie children of \p trie_first.
    void walk(std::span<const uint8_t> buf, size_t trie_first,
              const uint8_t* frame_base, size_t& found);

    /// @brief One result slot — one per registered path in the trie.
    struct Slot {
        Asn1OptionalBase* binding   = nullptr;   ///< nullptr = unbound
        size_t            value_off = SIZE_MAX;   ///< byte offset of value bytes in the frame
        size_t            value_len = 0;          ///< size of the value bytes
    };

    const BerProjection* proj_;
    std::vector<Slot>    slots_;         ///< indexed by FieldHandle::index
    const uint8_t*       frame_base_  = nullptr;  ///< set by apply(); used by load()
    uint8_t*             mut_frame_   = nullptr;  ///< non-null only after mutable apply()
    std::vector<uint8_t> encode_buf_;   ///< scratch buffer for commit(); reused across calls
};

} // namespace asn1
