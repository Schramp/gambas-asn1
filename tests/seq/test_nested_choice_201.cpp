// Regression test for gambas-asn1#450: AUTOMATIC TAGS lost its module-wide
// default (falling back to the class's default-initialized EXPLICIT) while
// generating a promoted/inline nested type
// (Generator::generate_inline_types ran before current_tag_default_ was
// set for this module) — causing two sibling CHOICE alternatives that
// share a natural tag (both plain SEQUENCE references, no `[n]` of their
// own) to collide on the wire instead of getting distinct AUTOMATIC TAGS.
// Fixed at the Generator level (shared by both C++ and Rust backends —
// see tests/rust/nested_choice_201/src/main.rs for the Rust-side twin of
// this test).
//
// Schema: tests/tests-asn1c-compiler/201-nested-choice-name-collision-OK.asn1
//   HandoverCommand ::= SEQUENCE {
//       rrcTransId         INTEGER,
//       criticalExtensions CHOICE {
//           r8                 SEQUENCE { data OCTET STRING },
//           criticalExtensions CHOICE {
//               r11                SEQUENCE { data2 OCTET STRING },
//               criticalExtensions SEQUENCE {}
//           }
//       }
//   }
//
// Expected BER bytes confirmed byte-exact against real asn1c output
// (`asn1c -fcompound-names` + `converter-example -ixer -oder`).
#include <cstdio>
#include <vector>
#include <sstream>
#include <span>
#include <algorithm>
#include <asn1cpp/asn1cpp.hpp>
#include "HandoverCommand.hpp"
#include "HandoverCommandCriticalExtensions.hpp"
#include "HandoverCommandCriticalExtensionsCriticalExtensions.hpp"
#include "HandoverCommandCriticalExtensionsCriticalExtensionsCriticalExtensions.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else       { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main() {
    HandoverCommand hc;
    hc.rrcTransId = Integer{7};
    hc.criticalExtensions.set_present(HandoverCommandCriticalExtensions::PR::criticalExtensions);
    auto& mid = hc.criticalExtensions.criticalExtensions();
    // Previously the wire-ambiguous alternative: shared a tag with "r11"
    // before this fix.
    mid.set_present(HandoverCommandCriticalExtensionsCriticalExtensions::PR::criticalExtensions);

    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream es{w};
    BerCodec::instance().encode(es, HandoverCommand::asn_DEF, &hc);

    static const uint8_t expected[] = {0x30, 0x09, 0x80, 0x01, 0x07, 0xa1, 0x04, 0xa1, 0x02, 0xa1, 0x00};
    check("BER matches asn1c ground truth",
          buf.size() == sizeof(expected) && std::equal(buf.begin(), buf.end(), expected));

    HandoverCommand dec;
    BerReader r{buf}; BerDecodeStream ds{r};
    auto ok = BerCodec::instance().decode(ds, HandoverCommand::asn_DEF, &dec);
    check("BER decode ok", (bool)ok);
    check("outer alt criticalExtensions",
          ok && dec.criticalExtensions.present() == HandoverCommandCriticalExtensions::PR::criticalExtensions);
    check("middle alt criticalExtensions (previously misdispatched to r11)",
          ok && dec.criticalExtensions.present() == HandoverCommandCriticalExtensions::PR::criticalExtensions &&
          dec.criticalExtensions.criticalExtensions().present() ==
              HandoverCommandCriticalExtensionsCriticalExtensions::PR::criticalExtensions);

    auto buf2 = std::vector<uint8_t>{};
    BerWriter w2{buf2}; BerEncodeStream es2{w2};
    BerCodec::instance().encode(es2, HandoverCommand::asn_DEF, &dec);
    check("BER round-trip idempotent", buf == buf2);

    std::ostringstream oss;
    XerEncodeStream xs{oss};
    XerCodec::instance().encode(xs, HandoverCommand::asn_DEF, &hc);
    HandoverCommand xdec;
    XerDecodeStream xds{oss.str()};
    auto xok = XerCodec::instance().decode(xds, HandoverCommand::asn_DEF, &xdec);
    check("XER decode ok", (bool)xok);
    check("XER middle alt criticalExtensions",
          xok && xdec.criticalExtensions.present() == HandoverCommandCriticalExtensions::PR::criticalExtensions &&
          xdec.criticalExtensions.criticalExtensions().present() ==
              HandoverCommandCriticalExtensionsCriticalExtensions::PR::criticalExtensions);

    printf("\n%s  %d failure(s)\n", failures ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m", failures);
    return failures ? 1 : 0;
}
