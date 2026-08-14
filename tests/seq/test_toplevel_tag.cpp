// BER encode tests for a top-level type's own [N] IMPLICIT tag reaching its
// standalone TypeDescriptor.  Schema: tests/asn1/toplevel_tag_test.asn1
//
// gambas-asn1#339: emit_integer_cpp / emit_enumerated_cpp / emit_sequence_cpp /
// emit_seq_of_cpp used to hardcode each type's natural universal tag in its own
// asn_DEF_<Name>, ignoring a top-level [N] IMPLICIT declaration on the type
// itself — even though the *member* table entry for the same type already
// resolved the override correctly (compute_member_tag/natural_tag_for).
// Confirmed against asn1c ground truth: asn_DEF_MyInt's canonical tag there is
// context-5, not universal-2 (asn1c's tags[] array drops the trailing
// universal fallback for the canonical count, keeps it in all_tags).
#include <cstdio>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "MyInt.hpp"
#include "MyEnum.hpp"
#include "MySeq.hpp"
#include "MySeqOf.hpp"
#include "MyExplicitInt.hpp"
#include "Wrapper.hpp"
#include "WrapperTso.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename T>
static std::vector<uint8_t> encode(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    return buf;
}

template<typename T>
static bool decode(std::span<const uint8_t> bytes, const TypeDescriptor& def, T& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}

int main() {
    printf("\n── Top-level type's own [N] IMPLICIT tag ───────────────────────\n");

    // MyInt ::= [5] IMPLICIT INTEGER, standalone-encoded (not via a member).
    // Expected: 0x85 (Context, tag=5, primitive), not 0x02 (universal INTEGER).
    {
        MyInt v{};
        v.set(7);
        auto enc = encode(v, asn_DEF_MyInt);
        check("MyInt standalone: context-5 primitive tag (0x85)",
              !enc.empty() && enc[0] == 0x85);
        check("MyInt standalone: not universal INTEGER tag (0x02)",
              !enc.empty() && enc[0] != 0x02);
    }

    // MyEnum ::= [6] IMPLICIT ENUMERATED, standalone-encoded.
    // Expected: 0x86 (Context, tag=6, primitive), not 0x0a (universal ENUMERATED).
    {
        MyEnum v{MyEnum::b};
        auto enc = encode(v, MyEnum::asn_DEF);
        check("MyEnum standalone: context-6 primitive tag (0x86)",
              !enc.empty() && enc[0] == 0x86);
    }

    // MySeq ::= [7] IMPLICIT SEQUENCE { x INTEGER }, standalone-encoded.
    // Expected: 0xa7 (Context, tag=7, constructed), not 0x30 (universal SEQUENCE).
    {
        MySeq v{};
        v.x.set(1);
        auto enc = encode(v, MySeq::asn_DEF);
        check("MySeq standalone: context-7 constructed tag (0xa7)",
              !enc.empty() && enc[0] == 0xa7);
    }

    // MySeqOf ::= [8] IMPLICIT SEQUENCE OF INTEGER, standalone-encoded.
    // Expected: 0xa8 (Context, tag=8, constructed), not 0x30 (universal SEQUENCE).
    {
        MySeqOf v{9};
        auto enc = encode(v, asn_DEF_MySeqOf);
        check("MySeqOf standalone: context-8 constructed tag (0xa8)",
              !enc.empty() && enc[0] == 0xa8);
    }

    // MyExplicitInt ::= [9] EXPLICIT INTEGER, standalone-encoded.
    // gambas-asn1#352: EXPLICIT wraps a nested TLV using the natural tag,
    // it does not substitute for it. Confirmed against real asn1c output
    // for the same schema/value: a9 03 02 01 2a.
    // Expected: a9 03 02 01 2a
    //   a9       Context 9, constructed (the EXPLICIT wrapper)
    //   03       wrapper length = 3
    //   02 01 2a Universal INTEGER, len 1, value 42 (the natural encoding)
    {
        MyExplicitInt v(42);
        auto enc = encode(v, asn_DEF_MyExplicitInt);
        std::vector<uint8_t> expect = {0xa9, 0x03, 0x02, 0x01, 0x2a};
        check("MyExplicitInt standalone: matches asn1c ground truth byte-for-byte",
              enc == expect);

        MyExplicitInt got{};
        check("MyExplicitInt standalone: decode ok", decode(enc, asn_DEF_MyExplicitInt, got));
        check("MyExplicitInt standalone: round-trip value", got.value() == 42);
    }

    printf("\n── Same types embedded as SEQUENCE members (must still be correct) ─\n");

    // Wrapper wraps all four by natural (untagged) member reference — the
    // member table must still resolve each field to its type's own tag,
    // exactly as it did before this fix (regression guard, not new behavior).
    {
        Wrapper v{};
        v.i.set(7);
        v.e = MyEnum::b;
        v.s.x.set(1);
        v.so = MySeqOf{9};
        auto enc = encode(v, Wrapper::asn_DEF);
        check("Wrapper: non-empty encode", !enc.empty());

        Wrapper got{};
        check("Wrapper: decode ok", decode(enc, Wrapper::asn_DEF, got));
        check("Wrapper: i round-trip",  got.i.value() == 7);
        check("Wrapper: e round-trip",  got.e == MyEnum::b);
        check("Wrapper: s.x round-trip", got.s.x.value() == 1);
        check("Wrapper: so round-trip", got.so.size() == 1);
    }

    printf("\n── Anonymous inline SET OF member (synthetic-type tag contamination) ─\n");

    // Wrapper.tso ::= [10] SET OF INTEGER — codegen builds a synthetic wrapper
    // type (WrapperTso) by copying this member's AST node, which used to drag
    // the member's own [10] tag onto the synthetic type's own .tag field.
    // That broke BerCodec's is_set_of() detection (checks the type's own
    // natural universal Set tag) and silently disabled DER canonical sorting
    // (X.690 §11.6) for every anonymous-inline SET OF member with its own tag
    // — the overwhelmingly common case in real ETSI LI schemas.
    {
        Wrapper v{};
        v.i.set(7);
        v.e = MyEnum::b;
        v.s.x.set(1);
        v.so = MySeqOf{9};
        // Insertion order [300, 5] is NOT DER-canonical: encoded octets for 5
        // are {02,01,05} and for 300 are {02,02,01,2C} — comparing byte-by-byte,
        // 01 < 02 at the second position, so 5 must sort before 300.
        v.tso = std::make_unique<WrapperTso>(WrapperTso{300, 5});
        auto enc = encode(v, Wrapper::asn_DEF);
        check("Wrapper.tso: non-empty encode", !enc.empty());

        Wrapper got{};
        check("Wrapper.tso: decode ok", decode(enc, Wrapper::asn_DEF, got));
        check("Wrapper.tso: present after decode", got.tso != nullptr);
        if (got.tso) {
            check("Wrapper.tso: DER-canonical sort on wire (5 before 300)",
                  got.tso->size() == 2 && (*got.tso)[0].value() == 5
                                        && (*got.tso)[1].value() == 300);
        }
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
