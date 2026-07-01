// Tests for BerProjection trie — path resolution, prefix sharing, CHOICE, errors.
//
// Uses hand-crafted TypeDescriptor / SequenceSpec / ChoiceSpec instances so
// no generated code needs to link.  Descriptors model:
//
//   Root ::= SEQUENCE {
//       alpha  [0] Alpha,     -- Alpha is a SEQUENCE
//       beta   [1] Beta       -- Beta is a CHOICE
//   }
//   Alpha ::= SEQUENCE {
//       x  [0] INTEGER,
//       y  [1] VisibleString
//   }
//   Beta ::= CHOICE {
//       left  [0] INTEGER,
//       right [1] OctetString
//   }
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <stdexcept>
#include <asn1cpp/codec/BerProjection.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Strings.hpp>
#include <asn1cpp/types/OctetString.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// ── Minimal descriptor tables ─────────────────────────────────────────────────

// Forward declarations (needed for cross-referencing)
extern const TypeDescriptor root_def;
extern const TypeDescriptor alpha_def;
extern const TypeDescriptor beta_def;

// Alpha members: x [0] INTEGER, y [1] VisibleString
static const MemberDescriptor alpha_members[] = {
    { "x", Tag{TagClass::Context, 0, false}, false, false,
      kInvalidMemberOffset, &Integer::asn_DEF },
    { "y", Tag{TagClass::Context, 1, false}, false, false,
      kInvalidMemberOffset, &VisibleString::asn_DEF },
};
static const SequenceSpec alpha_seq = { alpha_members, 2, -1 };

const TypeDescriptor alpha_def = {
    "Alpha",
    Tag{TagClass::Universal, 16, true},
    nullptr, &alpha_seq, nullptr, nullptr,
    {}, false, TypeKind::Sequence,
};

// Beta alternatives: left [0] INTEGER, right [1] OctetString
static const MemberDescriptor beta_alts[] = {
    { "left",  Tag{TagClass::Context, 0, false}, false, false,
      kInvalidMemberOffset, &Integer::asn_DEF },
    { "right", Tag{TagClass::Context, 1, false}, false, false,
      kInvalidMemberOffset, &OctetString::asn_DEF },
};
static const ChoiceSpec beta_choice = { beta_alts, 2, -1 };

const TypeDescriptor beta_def = {
    "Beta",
    Tag{TagClass::Universal, 16, true},
    nullptr, nullptr, &beta_choice, nullptr,
    {}, false, TypeKind::Choice,
};

// Root members: alpha [0] Alpha, beta [1] Beta
static const MemberDescriptor root_members[] = {
    { "alpha", Tag{TagClass::Context, 0, true}, false, false,
      kInvalidMemberOffset, &alpha_def },
    { "beta",  Tag{TagClass::Context, 1, true}, false, false,
      kInvalidMemberOffset, &beta_def },
};
static const SequenceSpec root_seq = { root_members, 2, -1 };

const TypeDescriptor root_def = {
    "Root",
    Tag{TagClass::Universal, 16, true},
    nullptr, &root_seq, nullptr, nullptr,
    {}, false, TypeKind::Sequence,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_single_path() {
    BerProjection proj{root_def};
    auto h = proj.add_path("alpha/x");
    proj.finalize();

    check("single_field_index",    h.index == 0);
    check("single_leaf_desc",      h.leaf_descriptor == &Integer::asn_DEF);
    check("single_leaf_count",     proj.leaf_count() == 1);
    check("single_node_count",     proj.nodes().size() == 2); // alpha + x
}

static void test_shared_prefix() {
    BerProjection proj{root_def};
    auto h_x = proj.add_path("alpha/x");
    auto h_y = proj.add_path("alpha/y");
    proj.finalize();

    check("shared_hx_index",   h_x.index == 0);
    check("shared_hy_index",   h_y.index == 1);
    check("shared_leaf_count", proj.leaf_count() == 2);
    // 'alpha' node is shared → 3 nodes total (alpha, x, y)
    check("shared_node_count", proj.nodes().size() == 3);
    check("shared_hx_desc",    h_x.leaf_descriptor == &Integer::asn_DEF);
    check("shared_hy_desc",    h_y.leaf_descriptor == &VisibleString::asn_DEF);
}

static void test_two_root_children() {
    BerProjection proj{root_def};
    auto h_x = proj.add_path("alpha/x");
    // 'beta/left' goes through the other root member
    auto h_left = proj.add_path("beta/left");
    proj.finalize();

    check("two_root_hx_idx",       h_x.index == 0);
    check("two_root_hleft_idx",    h_left.index == 1);
    check("two_root_leaf_count",   proj.leaf_count() == 2);
    // 4 nodes: alpha, x, beta, left
    check("two_root_node_count",   proj.nodes().size() == 4);
}

static void test_choice_path() {
    BerProjection proj{root_def};
    auto h_left  = proj.add_path("beta/left");
    auto h_right = proj.add_path("beta/right");
    proj.finalize();

    check("choice_left_idx",    h_left.index  == 0);
    check("choice_right_idx",   h_right.index == 1);
    check("choice_left_desc",   h_left.leaf_descriptor  == &Integer::asn_DEF);
    check("choice_right_desc",  h_right.leaf_descriptor == &OctetString::asn_DEF);
    check("choice_leaf_count",  proj.leaf_count() == 2);

    // Only beta paths added → root_first_child IS the beta node
    const auto& nodes = proj.nodes();
    size_t beta_idx = proj.root_first_child();
    check("choice_is_choice",   beta_idx != SIZE_MAX && nodes[beta_idx].is_choice);
    check("choice_node_count",  nodes.size() == 3); // beta, left, right
}

static void test_duplicate_path() {
    // Same path twice — same FieldHandle must come back
    BerProjection proj{root_def};
    auto h1 = proj.add_path("alpha/x");
    auto h2 = proj.add_path("alpha/x");
    proj.finalize();

    check("dup_same_index",     h1.index == h2.index);
    check("dup_leaf_count",     proj.leaf_count() == 1);
    check("dup_node_count",     proj.nodes().size() == 2);
}

static void test_unknown_field() {
    BerProjection proj{root_def};
    bool threw = false;
    try {
        proj.add_path("alpha/NOSUCHFIELD");
    } catch (const std::runtime_error& e) {
        threw = true;
    }
    check("unknown_field_throws", threw);
}

static void test_add_after_finalize() {
    BerProjection proj{root_def};
    proj.add_path("alpha/x");
    proj.finalize();
    bool threw = false;
    try {
        proj.add_path("alpha/y");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    check("add_after_finalize_throws", threw);
}

static void test_leaf_count_before_finalize() {
    BerProjection proj{root_def};
    proj.add_path("alpha/x");
    // leaf_count() before finalize() should assert — we can't test assert cleanly,
    // but we verify leaf_count is correct after finalize.
    proj.finalize();
    check("leaf_count_after_finalize", proj.leaf_count() == 1);
}

static void test_list_paths() {
    BerProjection proj{root_def};
    auto h_x    = proj.add_path("alpha/x");
    auto h_y    = proj.add_path("alpha/y");
    auto h_left = proj.add_path("beta/left");
    // Duplicate — must not appear twice.
    auto h_x2   = proj.add_path("alpha/x");
    proj.finalize();

    const auto& paths = proj.list_paths();
    check("list_paths_count",       paths.size() == 3);
    check("list_paths_hx_idx",      h_x.index == 0);
    check("list_paths_hx_path",     paths[h_x.index]    == "alpha/x");
    check("list_paths_hy_path",     paths[h_y.index]    == "alpha/y");
    check("list_paths_hleft_path",  paths[h_left.index] == "beta/left");
    check("list_paths_dup_same",    h_x2.index == h_x.index);
    // Duplicate must not push a second entry.
    check("list_paths_dup_count",   paths.size() == 3);
}

static void test_trie_structure() {
    // Verify node linkage for two shared-prefix paths
    BerProjection proj{root_def};
    proj.add_path("alpha/x");
    proj.add_path("alpha/y");
    proj.finalize();

    const auto& nodes = proj.nodes();
    // root_first_child → alpha node
    size_t alpha_idx = proj.root_first_child();
    check("trie_alpha_tag_cls",    nodes[alpha_idx].tag.cls == TagClass::Context);
    check("trie_alpha_tag_num",    nodes[alpha_idx].tag.number == 0);
    check("trie_alpha_no_sibling", nodes[alpha_idx].next_sibling == SIZE_MAX);
    check("trie_alpha_not_leaf",   nodes[alpha_idx].field_index == SIZE_MAX);

    // alpha.first_child → x node
    size_t x_idx = nodes[alpha_idx].first_child;
    check("trie_x_valid",          x_idx != SIZE_MAX);
    check("trie_x_tag_num",        nodes[x_idx].tag.number == 0);
    check("trie_x_is_leaf",        nodes[x_idx].field_index == 0);

    // x.next_sibling → y node
    size_t y_idx = nodes[x_idx].next_sibling;
    check("trie_y_valid",          y_idx != SIZE_MAX);
    check("trie_y_tag_num",        nodes[y_idx].tag.number == 1);
    check("trie_y_is_leaf",        nodes[y_idx].field_index == 1);
    check("trie_y_no_sibling",     nodes[y_idx].next_sibling == SIZE_MAX);
}

int main() {
    printf("=== Single path ===\n");
    test_single_path();

    printf("=== Shared prefix ===\n");
    test_shared_prefix();

    printf("=== Two root children ===\n");
    test_two_root_children();

    printf("=== CHOICE path ===\n");
    test_choice_path();

    printf("=== Duplicate path ===\n");
    test_duplicate_path();

    printf("=== Error: unknown field ===\n");
    test_unknown_field();

    printf("=== Error: add after finalize ===\n");
    test_add_after_finalize();

    printf("=== Leaf count ===\n");
    test_leaf_count_before_finalize();

    printf("=== list_paths ===\n");
    test_list_paths();

    printf("=== Trie structure ===\n");
    test_trie_structure();

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
