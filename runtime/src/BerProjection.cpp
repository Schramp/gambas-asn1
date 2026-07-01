#include <asn1cpp/codec/BerProjection.hpp>
#include <cassert>
#include <stdexcept>
#include <string>

namespace asn1 {

// ── internal helpers ──────────────────────────────────────────────────────────

static bool tag_matches(Tag a, Tag b) {
    return a.cls == b.cls && a.number == b.number;
}

// ── BerProjection ─────────────────────────────────────────────────────────────

BerProjection::BerProjection(const TypeDescriptor& root)
    : root_(&root) {}

size_t BerProjection::ensure_node(size_t               parent_idx,
                                   Tag                  t,
                                   const TypeDescriptor* desc,
                                   bool                 is_choice) {
    // Find the first-child index for this parent.
    size_t first = (parent_idx == SIZE_MAX) ? root_first_child_
                                            : nodes_[parent_idx].first_child;

    // Scan existing siblings for a tag match.
    size_t cur  = first;
    size_t prev = SIZE_MAX;
    while (cur != SIZE_MAX) {
        if (tag_matches(nodes_[cur].tag, t))
            return cur;
        prev = cur;
        cur  = nodes_[cur].next_sibling;
    }

    // Not found — append a new node (may reallocate nodes_).
    size_t new_idx = nodes_.size();
    nodes_.push_back(TrieNode{t, SIZE_MAX, SIZE_MAX, SIZE_MAX, is_choice, desc});

    // Link into the sibling chain (use indices, not refs — realloc-safe).
    if (prev == SIZE_MAX) {
        if (parent_idx == SIZE_MAX)
            root_first_child_ = new_idx;
        else
            nodes_[parent_idx].first_child = new_idx;
    } else {
        nodes_[prev].next_sibling = new_idx;
    }

    return new_idx;
}

FieldHandle BerProjection::add_path(std::string_view path) {
    if (finalized_)
        throw std::runtime_error("BerProjection::add_path called after finalize()");
    if (path.empty())
        throw std::runtime_error("BerProjection::add_path: empty path");

    const TypeDescriptor* cur_desc = root_;
    size_t parent_idx = SIZE_MAX;

    while (!path.empty()) {
        auto slash = path.find('/');
        std::string_view component = (slash == std::string_view::npos)
                                   ? path : path.substr(0, slash);
        bool is_leaf = (slash == std::string_view::npos);
        path = is_leaf ? std::string_view{} : path.substr(slash + 1);

        if (component.empty())
            throw std::runtime_error("BerProjection::add_path: empty path component");

        if (!cur_desc)
            throw std::runtime_error(
                std::string("BerProjection: no descriptor while resolving '")
                + std::string(component) + "'");

        // Resolve component against the current type's member or alternative table.
        Tag                   found_tag{};
        const TypeDescriptor* child_desc = nullptr;

        if (cur_desc->sequence_spec) {
            const SequenceSpec& spec = *cur_desc->sequence_spec;
            for (int i = 0; i < spec.count; ++i) {
                if (std::string_view(spec.members[i].name) == component) {
                    found_tag  = spec.members[i].tag;
                    child_desc = spec.members[i].type_descriptor;
                    break;
                }
            }
        } else if (cur_desc->choice_spec) {
            const ChoiceSpec& spec = *cur_desc->choice_spec;
            for (int i = 0; i < spec.count; ++i) {
                if (std::string_view(spec.alternatives[i].name) == component) {
                    found_tag  = spec.alternatives[i].tag;
                    child_desc = spec.alternatives[i].type_descriptor;
                    break;
                }
            }
        } else {
            throw std::runtime_error(
                std::string("BerProjection: '") + cur_desc->name
                + "' is neither SEQUENCE nor CHOICE — cannot navigate to '"
                + std::string(component) + "'");
        }

        if (!child_desc)
            throw std::runtime_error(
                std::string("BerProjection: member '") + std::string(component)
                + "' not found in '" + cur_desc->name + "'");

        // If the child type is a CHOICE, the node for this field acts as a
        // CHOICE container: its children are alternatives, not sequence members.
        bool child_is_choice = (child_desc->choice_spec != nullptr);

        size_t node_idx = ensure_node(parent_idx, found_tag, child_desc, false);

        if (!is_leaf) {
            // Propagate is_choice to this node when its child type is CHOICE.
            if (child_is_choice)
                nodes_[node_idx].is_choice = true;
            parent_idx = node_idx;
            cur_desc   = child_desc;
        } else {
            // Leaf: assign a result-slot index if this path is new.
            if (nodes_[node_idx].field_index == SIZE_MAX)
                nodes_[node_idx].field_index = leaf_count_++;
            return FieldHandle{nodes_[node_idx].field_index, child_desc};
        }
    }

    // Unreachable (path was non-empty on entry and the loop always covers it).
    throw std::runtime_error("BerProjection::add_path: internal error");
}

void BerProjection::finalize() {
    assert(!finalized_ && "BerProjection::finalize() called twice");
    finalized_ = true;
}

size_t BerProjection::leaf_count() const {
    assert(finalized_ && "BerProjection::leaf_count() called before finalize()");
    return leaf_count_;
}

} // namespace asn1
