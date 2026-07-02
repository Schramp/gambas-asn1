// Tests for BerProjectionResult — bind, apply, load, commit.
//
// Schema (same as test_ber_projection_trie.cpp):
//   Root ::= SEQUENCE {
//       alpha  [0] IMPLICIT SEQUENCE { x [0] IMPLICIT INTEGER, y [1] IMPLICIT VisibleString },
//       beta   [1] IMPLICIT CHOICE   { left [0] IMPLICIT INTEGER, right [1] IMPLICIT OctetString }
//   }
//
// frame1: x=42 y="hi"  beta/left=7
// frame2: x=99 y="BX"  beta/right={0x01,0x02,0x03}

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
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

// ── Descriptor tables (same schema as test_ber_projection_trie.cpp) ──────────

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
    "Alpha",
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
    "Beta",
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

// ── BER frames ───────────────────────────────────────────────────────────────

// frame1: Root { alpha { x=42, y="hi" }, beta/left=7 }
// 30 0F A0 07 80 01 2A 81 02 68 69 A1 03 80 01 07
// alpha: A0 07 (9 bytes total), beta: A1 03 (5 bytes total) → root members = 14 = 0x0E
static const uint8_t frame1_bytes[] = {
    0x30, 0x0E,         // Root SEQUENCE, 14 bytes
    0xA0, 0x07,         //   alpha [0] IMPLICIT SEQUENCE, 7 bytes
    0x80, 0x01, 0x2A,   //     x [0] IMPLICIT INTEGER = 42
    0x81, 0x02, 0x68, 0x69,  //   y [1] IMPLICIT VisibleString = "hi"
    0xA1, 0x03,         //   beta [1] IMPLICIT CHOICE, 3 bytes
    0x80, 0x01, 0x07,   //     left [0] IMPLICIT INTEGER = 7
};

// frame2: Root { alpha { x=99, y="BX" }, beta/right={0x01,0x02,0x03} }
// alpha_members: 80 01 63  81 02 42 58  → 7 bytes
// alpha: A0 07 80 01 63 81 02 42 58 → 9 bytes
// right: 81 03 01 02 03 → 5 bytes
// beta:  A1 05 81 03 01 02 03 → 7 bytes
// root members: 9 + 7 = 16 bytes
// root: 30 10 ...
static const uint8_t frame2_bytes[] = {
    0x30, 0x10,              // Root SEQUENCE, 16 bytes
    0xA0, 0x07,              //   alpha [0] IMPLICIT SEQUENCE, 7 bytes
    0x80, 0x01, 0x63,        //     x [0] IMPLICIT INTEGER = 99
    0x81, 0x02, 0x42, 0x58,  //     y [1] IMPLICIT VisibleString = "BX"
    0xA1, 0x05,              //   beta [1] IMPLICIT CHOICE, 5 bytes
    0x81, 0x03, 0x01, 0x02, 0x03,  // right [1] IMPLICIT OCTET STRING = {1,2,3}
};

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_basic_apply() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));

    check("basic_x_found",   x.found);
    check("basic_x_value",   x.found && static_cast<Integer&>(x).value() == 42);
}

static void test_shared_prefix() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    auto hy = proj.add_path("alpha/y");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer>       x;
    Asn1Optional<VisibleString> y;
    res.bind(hx, x);
    res.bind(hy, y);

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));

    check("prefix_x_found",  x.found);
    check("prefix_x_value",  x.found && static_cast<Integer&>(x).value() == 42);
    check("prefix_y_found",  y.found);
    const std::string& ystr = static_cast<VisibleString&>(y).str();
    check("prefix_y_value",  y.found && ystr == "hi");
}

static void test_choice_left() {
    BerProjection proj{root_def};
    auto hleft  = proj.add_path("beta/left");
    auto hright = proj.add_path("beta/right");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer>     left;
    Asn1Optional<OctetString> right;
    res.bind(hleft,  left);
    res.bind(hright, right);

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));

    check("choice_left_found",   left.found);
    check("choice_left_value",   left.found && static_cast<Integer&>(left).value() == 7);
    check("choice_right_absent", !right.found);
}

static void test_choice_right() {
    BerProjection proj{root_def};
    auto hleft  = proj.add_path("beta/left");
    auto hright = proj.add_path("beta/right");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer>     left;
    Asn1Optional<OctetString> right;
    res.bind(hleft,  left);
    res.bind(hright, right);

    res.apply(std::span<const uint8_t>(frame2_bytes, sizeof(frame2_bytes)));

    check("choice_right_found",  right.found);
    check("choice_left_absent",  !left.found);
    const OctetString& os = static_cast<OctetString&>(right);
    check("choice_right_value",  right.found && os.bytes().size() == 3
                                             && os.bytes()[0] == 0x01
                                             && os.bytes()[2] == 0x03);
}

static void test_multi_frame_reuse() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));
    check("reuse_frame1_found",  x.found);
    check("reuse_frame1_value",  x.found && static_cast<Integer&>(x).value() == 42);

    res.apply(std::span<const uint8_t>(frame2_bytes, sizeof(frame2_bytes)));
    check("reuse_frame2_found",  x.found);
    check("reuse_frame2_value",  x.found && static_cast<Integer&>(x).value() == 99);

    // Re-apply frame1 — must not bleed frame2 values
    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));
    check("reuse_no_bleed",      x.found && static_cast<Integer&>(x).value() == 42);
}

static void test_commit_same_length() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);

    std::vector<uint8_t> frame(frame1_bytes, frame1_bytes + sizeof(frame1_bytes));
    res.apply(std::span<uint8_t>(frame));

    check("commit_pre_x_found",  x.found);
    check("commit_pre_x_value",  x.found && static_cast<Integer&>(x).value() == 42);

    // Modify x to 43 (still 1 byte — same size)
    static_cast<Integer&>(x) = Integer{43};
    bool ok = res.commit(hx);
    check("commit_returned_true", ok);

    // Verify by re-applying the (now patched) frame
    res.apply(std::span<uint8_t>(frame));
    check("commit_patched_value", x.found && static_cast<Integer&>(x).value() == 43);
}

static void test_commit_size_mismatch() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);

    std::vector<uint8_t> frame(frame1_bytes, frame1_bytes + sizeof(frame1_bytes));
    std::vector<uint8_t> original = frame;

    res.apply(std::span<uint8_t>(frame));

    // Modify x to 1000 (2-byte encoding) — size mismatch
    static_cast<Integer&>(x) = Integer{1000};
    bool ok = res.commit(hx);
    check("mismatch_returned_false", !ok);
    check("mismatch_frame_unchanged", frame == original);
}

static void test_load() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    auto hy = proj.add_path("alpha/y");
    proj.finalize();

    BerProjectionResult res{proj};
    // No bind() calls — using load() instead

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));

    Asn1Optional<Integer>       x;
    Asn1Optional<VisibleString> y;
    res.load(hx, x);
    res.load(hy, y);

    check("load_x_found",  x.found);
    check("load_x_value",  x.found && static_cast<Integer&>(x).value() == 42);
    check("load_y_found",  y.found);
    check("load_y_value",  y.found && static_cast<VisibleString&>(y).str() == "hi");
}

static void test_unbound_field_absent() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    auto hy = proj.add_path("alpha/y");  // registered but not bound
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);  // hy not bound

    res.apply(std::span<const uint8_t>(frame1_bytes, sizeof(frame1_bytes)));

    // x should still be found even though hy is unbound
    check("unbound_x_found", x.found);
    check("unbound_x_value", x.found && static_cast<Integer&>(x).value() == 42);

    // load() for unbound slot should also work (slot location was recorded)
    Asn1Optional<VisibleString> y;
    res.load(hy, y);
    check("unbound_load_y_found", y.found);
    check("unbound_load_y_value", y.found && static_cast<VisibleString&>(y).str() == "hi");
}

int main() {
    printf("=== Basic apply ===\n");
    test_basic_apply();

    printf("=== Shared prefix ===\n");
    test_shared_prefix();

    printf("=== CHOICE dispatch — left alt ===\n");
    test_choice_left();

    printf("=== CHOICE dispatch — right alt ===\n");
    test_choice_right();

    printf("=== Multi-frame reuse ===\n");
    test_multi_frame_reuse();

    printf("=== Commit same length ===\n");
    test_commit_same_length();

    printf("=== Commit size mismatch ===\n");
    test_commit_size_mismatch();

    printf("=== Load without bind ===\n");
    test_load();

    printf("=== Unbound field location still recorded ===\n");
    test_unbound_field_absent();

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
