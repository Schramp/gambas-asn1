// Tests for BerInspect — ber_dump_paths (schema-free + schema-aware) and ber_find_paths.
//
// Same schema as test_ber_projection_result.cpp:
//   Root ::= SEQUENCE {
//       alpha  [0] IMPLICIT SEQUENCE { x [0] IMPLICIT INTEGER, y [1] IMPLICIT VisibleString },
//       beta   [1] IMPLICIT CHOICE   { left [0] IMPLICIT INTEGER, right [1] IMPLICIT OctetString }
//   }
//
// frame1: x=42 y="hi"  beta/left=7
// frame2: x=99 y="BX"  beta/right={0x01,0x02,0x03}

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <string>
#include <asn1cpp/codec/BerInspect.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Strings.hpp>
#include <asn1cpp/types/OctetString.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s\n", name);
        ++failures;
    }
}

// ── TypeDescriptor tables ─────────────────────────────────────────────────────

extern const TypeDescriptor root_def;
extern const TypeDescriptor alpha_def;
extern const TypeDescriptor beta_def;

static const MemberDescriptor alpha_members[] = {
    { "x", Tag{TagClass::Context, 0, false}, false, false,
      kInvalidMemberOffset, &Integer::asn_DEF },
    { "y", Tag{TagClass::Context, 1, false}, false, false,
      kInvalidMemberOffset, &VisibleString::asn_DEF },
};
static const SequenceSpec alpha_seq = { alpha_members, 2, -1 };

const TypeDescriptor alpha_def = {
    "alpha",
    Tag{TagClass::Universal, 16, true},
    nullptr, &alpha_seq, nullptr, nullptr,
    {}, false, TypeKind::Sequence,
};

static const MemberDescriptor beta_alts[] = {
    { "left",  Tag{TagClass::Context, 0, false}, false, false,
      kInvalidMemberOffset, &Integer::asn_DEF },
    { "right", Tag{TagClass::Context, 1, false}, false, false,
      kInvalidMemberOffset, &OctetString::asn_DEF },
};
static const ChoiceSpec beta_choice = { beta_alts, 2, -1 };

const TypeDescriptor beta_def = {
    "beta",
    Tag{TagClass::Universal, 16, true},
    nullptr, nullptr, &beta_choice, nullptr,
    {}, false, TypeKind::Choice,
};

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

// Stub type to allow ber_dump_paths<Root> / ber_find_paths<Root>
struct Root { static const TypeDescriptor asn_DEF; };
const TypeDescriptor Root::asn_DEF = root_def;

// ── BER frames ────────────────────────────────────────────────────────────────

// frame1: x=42 y="hi" beta/left=7
static const uint8_t frame1[] = {
    0x30, 0x0E,
    0xA0, 0x07,
    0x80, 0x01, 0x2A,
    0x81, 0x02, 0x68, 0x69,
    0xA1, 0x03,
    0x80, 0x01, 0x07,
};

// frame2: x=99 y="BX" beta/right={0x01,0x02,0x03}
static const uint8_t frame2[] = {
    0x30, 0x10,
    0xA0, 0x07,
    0x80, 0x01, 0x63,
    0x81, 0x02, 0x42, 0x58,
    0xA1, 0x05,
    0x81, 0x03, 0x01, 0x02, 0x03,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<std::string> lines_of(const std::string& s) {
    std::vector<std::string> v;
    std::string line;
    for (char c : s) {
        if (c == '\n') { if (!line.empty()) v.push_back(line); line.clear(); }
        else line += c;
    }
    if (!line.empty()) v.push_back(line);
    return v;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_dump_free_leaves_only() {
    std::ostringstream oss;
    ber_dump_paths(std::span<const uint8_t>(frame1, sizeof(frame1)), oss);
    auto lines = lines_of(oss.str());
    // frame1 has 3 leaf TLVs: x(80), y(81), left(80)
    check("free_leaves_count", lines.size() == 3);
    // All should contain '[' since they're numeric context tags
    check("free_leaves_tags", lines[0].find('[') != std::string::npos);
}

static void test_dump_free_all_nodes() {
    std::ostringstream oss;
    ber_dump_paths(std::span<const uint8_t>(frame1, sizeof(frame1)), oss, /*leaves_only=*/false);
    auto lines = lines_of(oss.str());
    // Nodes: Root(constructed), alpha(constructed), x, y, beta(constructed), left → 6
    check("free_all_count", lines.size() == 6);
}

static void test_dump_schema_leaves() {
    std::ostringstream oss;
    ber_dump_paths_impl(std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, oss, true);
    auto lines = lines_of(oss.str());
    check("schema_leaves_count", lines.size() == 3);
    check("schema_path_x",     lines[0] == "Root/alpha/x");
    check("schema_path_y",     lines[1] == "Root/alpha/y");
    check("schema_path_left",  lines[2] == "Root/beta/left");
}

static void test_dump_schema_all_nodes() {
    std::ostringstream oss;
    ber_dump_paths_impl(std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, oss, false);
    auto lines = lines_of(oss.str());
    // Root, Root/alpha, Root/alpha/x, Root/alpha/y, Root/beta, Root/beta/left
    check("schema_all_count",  lines.size() == 6);
    check("schema_root",       lines[0] == "Root");
    check("schema_alpha_node", lines[1] == "Root/alpha");
}

static void test_dump_schema_choice_right() {
    std::ostringstream oss;
    ber_dump_paths_impl(std::span<const uint8_t>(frame2, sizeof(frame2)), &root_def, oss, true);
    auto lines = lines_of(oss.str());
    check("schema_right_count", lines.size() == 3);
    check("schema_path_right",  lines[2] == "Root/beta/right");
}

static void test_find_paths_glob() {
    auto paths = ber_find_paths_impl(
        std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, "*left*");
    check("find_left_count",  paths.size() == 1);
    check("find_left_value",  !paths.empty() && paths[0] == "Root/beta/left");
}

static void test_find_paths_wildcard_all() {
    auto paths = ber_find_paths_impl(
        std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, "*");
    check("find_all_count", paths.size() == 3);
}

static void test_find_paths_no_match() {
    auto paths = ber_find_paths_impl(
        std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, "*timestamp*");
    check("find_none_empty", paths.empty());
}

static void test_find_paths_case_insensitive() {
    // '*' crosses '/' — "*ALPHA*" matches any leaf path containing "alpha"
    // (Root/alpha/x and Root/alpha/y both match)
    auto paths = ber_find_paths_impl(
        std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, "*ALPHA*");
    check("find_case_alpha_count", paths.size() == 2);

    // Uppercase leaf name
    auto paths2 = ber_find_paths_impl(
        std::span<const uint8_t>(frame1, sizeof(frame1)), &root_def, "*X*");
    check("find_case_x", paths2.size() == 1 && paths2[0] == "Root/alpha/x");
}

static void test_find_paths_template() {
    auto paths = ber_find_paths<Root>(
        std::span<const uint8_t>(frame1, sizeof(frame1)), "*y*");
    check("find_template_y", paths.size() == 1 && paths[0] == "Root/alpha/y");
}

static void test_dump_template() {
    std::ostringstream oss;
    ber_dump_paths<Root>(std::span<const uint8_t>(frame1, sizeof(frame1)), oss);
    auto lines = lines_of(oss.str());
    check("dump_template_count", lines.size() == 3);
    check("dump_template_first", lines[0] == "Root/alpha/x");
}

static void test_empty_buf() {
    std::ostringstream oss;
    ber_dump_paths(std::span<const uint8_t>{}, oss);
    check("empty_buf_no_output", oss.str().empty());
}

int main() {
    printf("=== Schema-free dump (leaves only) ===\n");
    test_dump_free_leaves_only();

    printf("=== Schema-free dump (all nodes) ===\n");
    test_dump_free_all_nodes();

    printf("=== Schema-aware dump (leaves only) ===\n");
    test_dump_schema_leaves();

    printf("=== Schema-aware dump (all nodes) ===\n");
    test_dump_schema_all_nodes();

    printf("=== Schema-aware dump (CHOICE right alt) ===\n");
    test_dump_schema_choice_right();

    printf("=== ber_find_paths glob ===\n");
    test_find_paths_glob();

    printf("=== ber_find_paths wildcard-all ===\n");
    test_find_paths_wildcard_all();

    printf("=== ber_find_paths no match ===\n");
    test_find_paths_no_match();

    printf("=== ber_find_paths case-insensitive ===\n");
    test_find_paths_case_insensitive();

    printf("=== ber_find_paths<Root> template ===\n");
    test_find_paths_template();

    printf("=== ber_dump_paths<Root> template ===\n");
    test_dump_template();

    printf("=== empty buffer ===\n");
    test_empty_buf();

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
