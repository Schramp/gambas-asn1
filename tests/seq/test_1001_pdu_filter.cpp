// Tests -pdu=RootType filter (issue #14):
//   generated with -pdu=RootType from pdu_filter_test.asn1
//   → RootType, Dep1, Dep2 present; Unrelated absent.
// This file only includes the reachable types (build fails if they're missing).
// Absence of Unrelated.hpp is verified by the pdu_filter_absent cmake test.
#include <cstdio>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/BerCodec.hpp>
#include "RootType.hpp"
#include "Dep1.hpp"
#include "Dep2.hpp"

using namespace asn1;

static int failures = 0;
static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

int main() {
    printf("\n── -pdu filter test (issue #14) ─────────────────────────────────────\n");

    // Build RootType → Dep1 → Dep2 chain.
    RootType r{};
    r.id = Integer{42};
    r.dep.name = VisibleString{"hello"};
    r.dep.sub.value = Integer{7};

    // BER round-trip.
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream es{w};
    BerCodec::instance().encode(es, RootType::asn_DEF, &r);
    check("pdu-filter: BER encode non-empty", !buf.empty());

    RootType r2{};
    BerReader rd{buf};
    BerDecodeStream ds{rd};
    bool ok = BerCodec::instance().decode(ds, RootType::asn_DEF, &r2).has_value();
    check("pdu-filter: BER decode ok",           ok);
    check("pdu-filter: id==42",                  ok && (int64_t)r2.id == 42);
    check("pdu-filter: dep.name==\"hello\"",     ok && r2.dep.name.str() == "hello");
    check("pdu-filter: dep.sub.value==7",        ok && (int64_t)r2.dep.sub.value == 7);

    printf("\n  %d failure(s).\n", failures);
    if (failures) return 1;
    printf("  All tests passed.\n");
    return 0;
}
