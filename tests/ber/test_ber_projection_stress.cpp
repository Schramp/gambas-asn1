// Stress test: BerProjectionResult — 1000 frames, no state bleed.
//
// Same schema as test_ber_projection_result.cpp:
//   Root ::= SEQUENCE {
//       alpha [0] IMPLICIT SEQUENCE { x [0] IMPLICIT INTEGER, y [1] IMPLICIT VisibleString },
//       beta  [1] IMPLICIT CHOICE   { left [0] IMPLICIT INTEGER, right [1] IMPLICIT OctetString }
//   }
//
// Alternates between frame1 (x=42, y="hi", beta/left=7) and
// frame2 (x=99, y="BX", beta/right={1,2,3}) for 1000 iterations each.

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <vector>
#include <asn1cpp/codec/BerProjection.hpp>
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
    "alpha", Tag{TagClass::Universal, 16, true},
    nullptr, &alpha_seq, nullptr, nullptr, {}, false, TypeKind::Sequence,
};

static const MemberDescriptor beta_alts[] = {
    { "left",  Tag{TagClass::Context, 0, false}, false, false,
      kInvalidMemberOffset, &Integer::asn_DEF },
    { "right", Tag{TagClass::Context, 1, false}, false, false,
      kInvalidMemberOffset, &OctetString::asn_DEF },
};
static const ChoiceSpec beta_choice = { beta_alts, 2, -1 };

const TypeDescriptor beta_def = {
    "beta", Tag{TagClass::Universal, 16, true},
    nullptr, nullptr, &beta_choice, nullptr, {}, false, TypeKind::Choice,
};

static const MemberDescriptor root_members[] = {
    { "alpha", Tag{TagClass::Context, 0, true}, false, false,
      kInvalidMemberOffset, &alpha_def },
    { "beta",  Tag{TagClass::Context, 1, true}, false, false,
      kInvalidMemberOffset, &beta_def },
};
static const SequenceSpec root_seq = { root_members, 2, -1 };

const TypeDescriptor root_def = {
    "Root", Tag{TagClass::Universal, 16, true},
    nullptr, &root_seq, nullptr, nullptr, {}, false, TypeKind::Sequence,
};

// ── BER frames ────────────────────────────────────────────────────────────────

static const uint8_t frame1[] = {
    0x30, 0x0E,
    0xA0, 0x07, 0x80, 0x01, 0x2A, 0x81, 0x02, 0x68, 0x69,
    0xA1, 0x03, 0x80, 0x01, 0x07,
};

static const uint8_t frame2[] = {
    0x30, 0x10,
    0xA0, 0x07, 0x80, 0x01, 0x63, 0x81, 0x02, 0x42, 0x58,
    0xA1, 0x05, 0x81, 0x03, 0x01, 0x02, 0x03,
};

// ── Stress test ───────────────────────────────────────────────────────────────

static void test_1000_frames_no_bleed() {
    BerProjection proj{root_def};
    auto hx    = proj.add_path("alpha/x");
    auto hy    = proj.add_path("alpha/y");
    auto hleft = proj.add_path("beta/left");
    auto hright= proj.add_path("beta/right");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer>     x;
    Asn1Optional<VisibleString> y;
    Asn1Optional<Integer>     left;
    Asn1Optional<OctetString> right;
    res.bind(hx,     x);
    res.bind(hy,     y);
    res.bind(hleft,  left);
    res.bind(hright, right);

    int bleed = 0;
    for (int i = 0; i < 1000; ++i) {
        if (i % 2 == 0) {
            res.apply(std::span<const uint8_t>(frame1, sizeof(frame1)));
            if (!x.found || static_cast<Integer&>(x).value() != 42)  ++bleed;
            if (!y.found)                                              ++bleed;
            if (!left.found || static_cast<Integer&>(left).value() != 7) ++bleed;
            if (right.found)                                           ++bleed;
        } else {
            res.apply(std::span<const uint8_t>(frame2, sizeof(frame2)));
            if (!x.found || static_cast<Integer&>(x).value() != 99)  ++bleed;
            if (!y.found)                                              ++bleed;
            if (left.found)                                            ++bleed;
            if (!right.found)                                          ++bleed;
        }
    }
    check("1000_frames_no_bleed", bleed == 0);
    if (bleed)
        printf("    %d bleed event(s) detected\n", bleed);
}

static void test_commit_stress() {
    BerProjection proj{root_def};
    auto hx = proj.add_path("alpha/x");
    proj.finalize();

    BerProjectionResult res{proj};
    Asn1Optional<Integer> x;
    res.bind(hx, x);

    int wrong = 0;
    for (int i = 0; i < 500; ++i) {
        std::vector<uint8_t> frame(frame1, frame1 + sizeof(frame1));
        res.apply(std::span<uint8_t>(frame));

        // Patch x to i+1 (always 1-byte values 1..127)
        int64_t new_val = (i % 127) + 1;
        static_cast<Integer&>(x).set(new_val);
        bool ok = res.commit(hx);
        if (!ok) { ++wrong; continue; }

        // Re-apply and verify the patch stuck
        res.apply(std::span<uint8_t>(frame));
        if (!x.found || static_cast<Integer&>(x).value() != new_val) ++wrong;
    }
    check("commit_stress_500", wrong == 0);
    if (wrong)
        printf("    %d wrong commit(s)\n", wrong);
}

int main() {
    printf("=== 1000-frame no-bleed stress ===\n");
    test_1000_frames_no_bleed();

    printf("=== 500-iteration commit stress ===\n");
    test_commit_stress();

    printf("\n%s — %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
