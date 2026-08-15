// Regression test for gambas-asn1#448: AUTOMATIC TAGS was wrongly forcing
// EXPLICIT tagging for a CHOICE alternative referencing an *already-tagged*
// type — X.680 §22.5/§28.4 says IMPLICIT applies there, substituting for
// the referenced type's own declared tag, same as any other already-tagged
// reference (EXPLICIT is only required for a genuinely *untagged* CHOICE/
// ANY, which has no tag to substitute onto).
//
// Schema: tests/tests-asn1c-compiler/203-automatic-tags-OK.asn1
//   RecChoice ::= [0] CHOICE { a INTEGER, b INTEGER, c RecChoice }
// Alternative `c` references RecChoice, which already carries its own
// `[0]`. Before this fix, `c` was forced EXPLICIT, and since
// RecChoice::asn_DEF.is_explicit was *also* true (RecChoice's own [0]),
// BerCodec::encode's is_explicit wrap fired twice — a genuine
// double-wrapped encoding (gambas-asn1#436/#447's own self-referential
// CHOICE work surfaced this while ground-truth-verifying against real
// asn1c). See tests/rust/self_ref_choice_203/src/main.rs for the Rust-side
// twin of this test.
//
// Expected BER bytes confirmed byte-exact against real asn1c output
// (`asn1c -fcompound-names` + `converter-example -ixer -oder`).
#include <cstdio>
#include <vector>
#include <sstream>
#include <span>
#include <algorithm>
#include <asn1cpp/asn1cpp.hpp>
#include "RecChoice.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else       { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main() {
    RecChoice r;
    r.set_present(RecChoice::PR::c);
    r.c().set_present(RecChoice::PR::a);
    r.c().a() = Integer{7};

    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream es{w};
    BerCodec::instance().encode(es, RecChoice::asn_DEF, &r);

    static const uint8_t expected[] = {0xa0, 0x05, 0xa2, 0x03, 0x80, 0x01, 0x07};
    check("BER matches asn1c ground truth (single-wrapped, not double)",
          buf.size() == sizeof(expected) && std::equal(buf.begin(), buf.end(), expected));

    RecChoice dec;
    BerReader br{buf}; BerDecodeStream ds{br};
    auto ok = BerCodec::instance().decode(ds, RecChoice::asn_DEF, &dec);
    check("BER decode ok", (bool)ok);
    check("alt c", ok && dec.present() == RecChoice::PR::c);
    check("inner alt a", ok && dec.present() == RecChoice::PR::c &&
                         dec.c().present() == RecChoice::PR::a);
    check("inner value", ok && dec.present() == RecChoice::PR::c &&
                         dec.c().present() == RecChoice::PR::a &&
                         (int64_t)dec.c().a() == 7);

    auto buf2 = std::vector<uint8_t>{};
    BerWriter w2{buf2}; BerEncodeStream es2{w2};
    BerCodec::instance().encode(es2, RecChoice::asn_DEF, &dec);
    check("BER round-trip idempotent", buf == buf2);

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
