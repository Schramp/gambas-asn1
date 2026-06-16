// Cross-module named-value constraint resolution (issue #89 codegen fix).
//
// Schema: four modules.
//   ModBase:       deepVal = 7
//   ModMid:        chainedVal ::= deepVal (hop 2), maxCount = 99 (collision name)
//   ModLimits:     maxCount = 10 (should win for ModConstrained), baseOffset = 5
//   ModConstrained imports maxCount/baseOffset FROM ModLimits, chainedVal FROM ModMid
//
// CountedField members and expected constraint bounds:
//   count   INTEGER (0..maxCount)          → lower=0, upper=10  (ModLimits wins, not ModMid=99)
//   offset  INTEGER (baseOffset..maxCount) → lower=5, upper=10
//   deep    INTEGER (0..chainedVal)        → lower=0, upper=7   (three-hop: chainedVal→deepVal→7)
#include <cstdio>
#include <asn1cpp/asn1cpp.hpp>
#include "CountedField.hpp"

static int failures = 0;
static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

int main() {
    const auto& spec = *CountedField::asn_DEF.sequence_spec;
    check("CountedField has 3 members", spec.count == 3);

    // Member 0: count INTEGER (0..maxCount=10) — ModLimits wins over ModMid.maxCount=99
    const asn1::TypeDescriptor* count_td = spec.members[0].type_descriptor;
    check("count td non-null", count_td != nullptr);
    if (count_td) {
        const auto& c = count_td->constraints;
        check("count CONSTRAINED", (c.flags & asn1::Constraints::CONSTRAINED) != 0);
        check("count lower_bound == 0",  c.lower_bound == 0);
        check("count upper_bound == 10", c.upper_bound == 10);  // NOT 99 from ModMid
    }

    // Member 1: offset INTEGER (baseOffset=5..maxCount=10)
    const asn1::TypeDescriptor* offset_td = spec.members[1].type_descriptor;
    check("offset td non-null", offset_td != nullptr);
    if (offset_td) {
        const auto& c = offset_td->constraints;
        check("offset CONSTRAINED", (c.flags & asn1::Constraints::CONSTRAINED) != 0);
        check("offset lower_bound == 5",  c.lower_bound == 5);
        check("offset upper_bound == 10", c.upper_bound == 10);
    }

    // Member 2: deep INTEGER (0..chainedVal) — three-hop: chainedVal→deepVal→7
    const asn1::TypeDescriptor* deep_td = spec.members[2].type_descriptor;
    check("deep td non-null", deep_td != nullptr);
    if (deep_td) {
        const auto& c = deep_td->constraints;
        check("deep CONSTRAINED", (c.flags & asn1::Constraints::CONSTRAINED) != 0);
        check("deep lower_bound == 0", c.lower_bound == 0);
        check("deep upper_bound == 7", c.upper_bound == 7);  // three hops resolved
    }

    if (failures == 0) { printf("\nAll tests passed.\n"); return 0; }
    printf("\n%d test(s) FAILED.\n", failures);
    return 1;
}
