// REAL value-range constraints (real_constraint_test.asn1); mirrors
// tests/rust/real_constraint/src/main.rs. Checks validate() against the
// descriptor tables of named REAL types and of inline-constrained
// members, and that RandomFiller only draws values inside the ranges.
#include <cmath>
#include <cstdio>
#include <limits>
#include <random>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/RandomFiller.hpp>
#include "Ranges.hpp"
#include "Pct.hpp"
#include "Finite.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static int64_t v(const TypeDescriptor& def, double d) {
    Real r{d};
    return validate(def, &r);
}

static const TypeDescriptor& member(int i) { return *Ranges::s_members[i].type_descriptor; }

int main() {
    constexpr double inf = std::numeric_limits<double>::infinity();
    constexpr double nan = std::numeric_limits<double>::quiet_NaN();
    printf("=== REAL value-range constraints ===\n");

    check("Pct (0..100): 0, 50 and 100 valid", v(asn_DEF_Pct, 0) == 0 && v(asn_DEF_Pct, 50) == 0 && v(asn_DEF_Pct, 100) == 0);
    check("Pct: -2.5 below by 3", v(asn_DEF_Pct, -2.5) == 3);
    check("Pct: 100.25 above by 1", v(asn_DEF_Pct, 100.25) == -1);
    check("Pct: NaN outside", v(asn_DEF_Pct, nan) == 1);
    check("Pct: PLUS-INFINITY above, saturated", v(asn_DEF_Pct, inf) == -std::numeric_limits<int64_t>::max());

    check("Finite: 1e300 valid", v(asn_DEF_Finite, 1e300) == 0);
    check("Finite: PLUS-INFINITY excluded", v(asn_DEF_Finite, inf) < 0);
    check("Finite: MINUS-INFINITY excluded", v(asn_DEF_Finite, -inf) > 0);
    check("Finite: NaN excluded", v(asn_DEF_Finite, nan) != 0);

    const auto& unit = member(0);
    check("unit (0<..<1): 0.5 valid", v(unit, 0.5) == 0);
    check("unit: open endpoints 0 and 1 excluded", v(unit, 0) > 0 && v(unit, 1) < 0);
    const auto& big = member(1);
    check("big (1.5E3..MAX): 1500 and PLUS-INFINITY valid", v(big, 1500) == 0 && v(big, inf) == 0);
    check("big: 1499 below", v(big, 1499) == 1);
    const auto& both = member(2);
    check("both (-10..10)(0..5): intersection 0..5", v(both, 0) == 0 && v(both, 5) == 0 && v(both, -1) > 0 && v(both, 6) < 0);
    check("ext (-1..1, ...): extensible accepts 5", v(member(3), 5) == 0);
    check("pct member uses Pct's table", &member(4) == &asn_DEF_Pct);

    std::mt19937 rng(42);
    FillConfig cfg;
    cfg.magic_real_prob = 0.5;
    RandomFiller filler(rng, cfg);
    bool all_valid = true;
    for (int i = 0; i < 500; ++i) {
        Ranges r;
        filler.fill(&r, Ranges::asn_DEF, 0, true);
        all_valid = all_valid && v(unit, r.unit.value()) == 0 && v(both, r.both.value()) == 0 &&
                    v(asn_DEF_Pct, r.pct.value()) == 0 && v(asn_DEF_Finite, r.fin.value()) == 0;
        if (r.big) all_valid = all_valid && v(big, r.big->value()) == 0;
    }
    check("RandomFiller draws only in-range values (500 records)", all_valid);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
