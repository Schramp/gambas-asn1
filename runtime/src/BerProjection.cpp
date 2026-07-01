#include <asn1cpp/codec/BerProjection.hpp>
#include <asn1cpp/codec/BerCursor.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include <asn1cpp/codec/BerWriter.hpp>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

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

    // Save original path before the parsing loop consumes it.
    std::string original_path{path};

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
            //
            // CHOICE-typed leaves: supported.  When child_desc->choice_spec != nullptr
            // the captured value bytes will contain the active alternative's full TLV,
            // which can be decoded as the CHOICE type via leaf_descriptor.  is_choice
            // is NOT set on leaf nodes — BerProjectionResult captures bytes wholesale
            // at a leaf; no alternative-scanning is needed regardless of type kind.
            //
            // Unsupported: registering the same field as both a leaf ("beta") and an
            // interior node ("beta/left") simultaneously.  That would produce a trie
            // node with field_index != SIZE_MAX and first_child != SIZE_MAX, whose
            // BerProjectionResult semantics are undefined.  Detected at apply() time.
            if (nodes_[node_idx].field_index == SIZE_MAX) {
                nodes_[node_idx].field_index = leaf_count_++;
                paths_.push_back(std::move(original_path));
            }
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

const std::vector<std::string>& BerProjection::list_paths() const {
    assert(finalized_ && "BerProjection::list_paths() called before finalize()");
    return paths_;
}

// ── BerProjectionResult ───────────────────────────────────────────────────────

BerProjectionResult::BerProjectionResult(const BerProjection& proj)
    : proj_(&proj)
{
    slots_.resize(proj.leaf_count());  // asserts finalized() internally
}

void BerProjectionResult::bind_impl(FieldHandle          h,
                                     Asn1OptionalBase&    target,
                                     const TypeDescriptor* desc)
{
    assert(h.index < slots_.size() && "BerProjectionResult::bind: handle out of range");
    assert(h.leaf_descriptor == desc &&
           "BerProjectionResult::bind: T does not match the registered path type");

    Slot& s = slots_[h.index];
    s.binding = &target;
}

void BerProjectionResult::walk(std::span<const uint8_t> buf,
                                size_t                   trie_first,
                                const uint8_t*           frame_base,
                                size_t&                  found)
{
    const auto& nodes = proj_->nodes();
    const size_t total = proj_->leaf_count();

    // Use leaf_count() (not bound_count_) as the exit threshold so that unbound
    // slots still get their value_off/value_len recorded — load() needs them.
    BerCursor c(buf);
    while (c.valid() && found < total) {
        // Scan trie siblings for a tag matching this TLV
        size_t ni = trie_first;
        while (ni != SIZE_MAX) {
            const TrieNode& node = nodes[ni];
            if (tag_matches(node.tag, c.tag())) {
                if (node.field_index != SIZE_MAX) {
                    // Leaf: record location and optionally decode into binding
                    Slot& s = slots_[node.field_index];
                    s.value_off = static_cast<size_t>(c.value().data() - frame_base);
                    s.value_len = c.length();
                    if (s.binding) {
                        auto ok = BerCodec::instance().decode_value(
                            c.value(), *s.binding->desc, s.binding->value_ptr);
                        s.binding->found = ok.has_value();
                    }
                    ++found;
                } else {
                    // Interior: recurse into children
                    walk(c.value(), node.first_child, frame_base, found);
                }
                break;  // this TLV consumed by one trie node
            }
            ni = node.next_sibling;
        }
        c.next();
    }
}

void BerProjectionResult::apply(std::span<const uint8_t> frame)
{
    frame_base_ = frame.data();
    mut_frame_  = nullptr;

    for (auto& s : slots_) {
        s.value_off = SIZE_MAX;
        s.value_len = 0;
        if (s.binding) s.binding->found = false;
    }

    // Enter the root TLV to reach the root type's members
    BerCursor root_c(frame);
    if (!root_c.valid()) return;

    size_t found = 0;
    walk(root_c.value(), proj_->root_first_child(), frame.data(), found);
}

void BerProjectionResult::apply(std::span<uint8_t> frame)
{
    frame_base_ = frame.data();
    mut_frame_  = frame.data();

    for (auto& s : slots_) {
        s.value_off = SIZE_MAX;
        s.value_len = 0;
        if (s.binding) s.binding->found = false;
    }

    BerCursor root_c(frame);
    if (!root_c.valid()) return;

    size_t found = 0;
    walk(root_c.value(), proj_->root_first_child(), frame.data(), found);
}

void BerProjectionResult::load_impl(FieldHandle          h,
                                     Asn1OptionalBase&    target,
                                     const TypeDescriptor* desc)
{
    assert(h.index < slots_.size() && "BerProjectionResult::load: handle out of range");
    assert(h.leaf_descriptor == desc &&
           "BerProjectionResult::load: T does not match the registered path type");
    assert(frame_base_ != nullptr && "BerProjectionResult::load: called before apply()");

    const Slot& s = slots_[h.index];
    target.found = false;
    if (s.value_off == SIZE_MAX) return;  // field absent in last apply()

    auto val = std::span<const uint8_t>(frame_base_ + s.value_off, s.value_len);
    auto ok  = BerCodec::instance().decode_value(val, *desc, target.value_ptr);
    target.found = ok.has_value();
}

bool BerProjectionResult::commit(FieldHandle h)
{
    assert(mut_frame_ != nullptr &&
           "BerProjectionResult::commit: requires mutable apply()");
    assert(h.index < slots_.size() && "BerProjectionResult::commit: handle out of range");

    const Slot& s = slots_[h.index];
    if (!s.binding || !s.binding->found || s.value_off == SIZE_MAX) return false;

    // Encode the current value into the scratch buffer (reused across commit() calls)
    encode_buf_.clear();
    BerWriter w{encode_buf_};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, *s.binding->desc, s.binding->value_ptr);

    // Extract value bytes (strip outer TLV header from the encoded output)
    BerCursor enc_c(std::span<const uint8_t>(encode_buf_.data(), encode_buf_.size()));
    if (!enc_c.valid()) return false;
    auto enc_val = enc_c.value();  // value bytes only (no tag+length header)

    if (enc_val.size() != s.value_len) return false;

    std::memcpy(mut_frame_ + s.value_off, enc_val.data(), s.value_len);
    return true;
}

} // namespace asn1
