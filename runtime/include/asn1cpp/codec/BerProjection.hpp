#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include "../Tag.hpp"
#include "../TypeDescriptor.hpp"

/// @file BerProjection.hpp
/// @brief Startup-time path registration and trie construction for lazy BER projection.
///
/// Build a \c BerProjection once at program startup, then share it read-only
/// across threads.  Each worker thread holds its own \c BerProjectionResult
/// (issue #173) which points into this trie.
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
/// // Per thread — see BerProjectionResult (#173)
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
    const TypeDescriptor* node_desc    = nullptr;    ///< TypeDescriptor at this level (used for introspection and #174).
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

} // namespace asn1
