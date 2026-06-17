// Tests that -fprefix=<name> wraps generated types in namespace <name> (issue #16).
// Generated from per_ext_test.asn1 with -fprefix=testns; all types accessed as
// testns::TypeName to confirm the namespace wrapper is in place and functional.
#include <cstdio>
#include <memory>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include "SeqWithExt.hpp"
#include "ChoiceWithExt.hpp"
#include "InnerSeq.hpp"
#include "SeqDeepExt.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main() {
    printf("\n── -fprefix namespace test (issue #16) ───────────────────────────────\n");

    // Confirm types are in namespace testns by constructing and using them.
    testns::SeqWithExt r{};
    r.id   = Integer{7};
    r.flag = Boolean{true};
    r.note = std::make_unique<VisibleString>("hi");

    // BER round-trip through the namespaced type's asn_DEF.
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, testns::SeqWithExt::asn_DEF, &r);
    check("fprefix: BER encode non-empty", !buf.empty());

    testns::SeqWithExt r2{};
    BerReader rd{buf};
    BerDecodeStream ds{rd};
    bool ok = BerCodec::instance().decode(ds, testns::SeqWithExt::asn_DEF, &r2).has_value();
    check("fprefix: BER decode ok",       ok);
    check("fprefix: id==7",               ok && (int64_t)r2.id == 7);
    check("fprefix: flag==true",          ok && r2.flag.value());
    check("fprefix: note==\"hi\"",        ok && r2.note != nullptr && r2.note->str() == "hi");

    // CHOICE in the namespace.
    testns::ChoiceWithExt c{};
    c.set_present(testns::ChoiceWithExt::PR::num);
    c.num() = Integer{42};
    check("fprefix: CHOICE constructible", c.present() == testns::ChoiceWithExt::PR::num);
    check("fprefix: CHOICE num==42",       (int64_t)c.num() == 42);

    // Nested type in the namespace.
    testns::SeqDeepExt deep{};
    deep.id   = Integer{1};
    deep.name = VisibleString{"x"};
    deep.detail = std::make_unique<testns::InnerSeq>();
    deep.detail->a = Integer{10};
    deep.detail->b = Boolean{false};
    deep.detail->c = Integer{20};
    check("fprefix: nested type constructible", deep.detail != nullptr);
    check("fprefix: InnerSeq.a==10", (int64_t)deep.detail->a == 10);

    printf("\n  %d failure(s).\n", failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
