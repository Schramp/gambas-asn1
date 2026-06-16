// Cross-module named-value constraint resolution (issue #89 codegen fix).
//
// Schema: ModLimits defines maxCount=10, baseOffset=5.
//         ModConstrained imports them and uses them as constraint bounds:
//           count  INTEGER (0..maxCount)       → lower=0, upper=10
//           offset INTEGER (baseOffset..maxCount) → lower=5, upper=10
//
// If the generator used the flat global_ map and a same-named value existed
// in another module, it could pick the wrong bound. This test verifies the
// generated TypeDescriptor tables carry the correct bounds.
#include <cstdio>
#include <asn1cpp/asn1cpp.hpp>
#include "CountedField.hpp"

static int failures = 0;
static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

int main() {
    // The generated member table for CountedField has two entries: count, offset.
    const auto& spec = *CountedField::asn_DEF.sequence_spec;
    check("CountedField has 2 members", spec.count == 2);

    // Member 0: count INTEGER (0..maxCount=10)
    const asn1::TypeDescriptor* count_td = spec.members[0].type_descriptor;
    check("count td non-null", count_td != nullptr);
    if (count_td) {
        const auto& c = count_td->constraints;
        check("count is CONSTRAINED",
              (c.flags & asn1::Constraints::CONSTRAINED) != 0);
        check("count lower_bound == 0", c.lower_bound == 0);
        check("count upper_bound == 10", c.upper_bound == 10);
    }

    // Member 1: offset INTEGER (baseOffset=5..maxCount=10)
    const asn1::TypeDescriptor* offset_td = spec.members[1].type_descriptor;
    check("offset td non-null", offset_td != nullptr);
    if (offset_td) {
        const auto& c = offset_td->constraints;
        check("offset is CONSTRAINED",
              (c.flags & asn1::Constraints::CONSTRAINED) != 0);
        check("offset lower_bound == 5", c.lower_bound == 5);
        check("offset upper_bound == 10", c.upper_bound == 10);
    }

    if (failures == 0) { printf("\nAll tests passed.\n"); return 0; }
    printf("\n%d test(s) FAILED.\n", failures);
    return 1;
}
