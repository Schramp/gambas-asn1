// INT64_MIN in generated C++ (int64_min_literal_test.asn1): a PER value-range
// bound, a DEFAULT value, an ENUMERATED value and a named number all equal
// -2^63 after code generation, and a record holding them round-trips in PER
// and BER. The ctest int64_min_literal_clang also compiles the generated
// files with clang, which rejects a bare -9223372036854775808 in a braced
// initializer.
#include <cstdio>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "LowRange.hpp"
#include "MinEnum.hpp"
#include "MinRec.hpp"
#include "Named.hpp"

using namespace asn1;

static constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
// int64_t is exact-width two's complement (C++20 [basic.fundamental],
// [cstdint.syn]), so its minimum is -2^63, bit pattern 0x8000000000000000,
// on every conforming compiler.
static_assert(kMin == -9223372036854775807 - 1);
static_assert(static_cast<uint64_t>(kMin) == 0x8000000000000000u);
static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static MinRec make_rec() {
    MinRec v{};
    v.range = kMin;
    v.kind = MinEnum::lowest;
    v.named = Named_lowest;
    return v;
}

static bool same(const MinRec& a, const MinRec& b) {
    return a.range.value() == b.range.value() && a.kind.present() == b.kind.present()
        && a.named.value() == b.named.value();
}

int main() {
    printf("=== INT64_MIN literals ===\n");
    check("LowRange PER lower bound", asn_DEF_LowRange.constraints.lower_bound == kMin);
    check("LowRange PER upper bound", asn_DEF_LowRange.constraints.upper_bound == -1);
    check("named number lowest", Named_lowest == kMin);
    check("ENUMERATED lowest", static_cast<int64_t>(MinEnum::lowest) == kMin);
    check("ENUMERATED value map", MinEnum::asn_MAP_value2enum[0].value == kMin);

    MinRec v = make_rec();
    std::vector<uint8_t> per;
    {
        PerEncodeStream s{per};
        IEncodeStream& es = s;
        PerCodec::instance().encode(es, MinRec::asn_DEF, &v);
        s.flush();
    }
    MinRec back{};
    {
        PerDecodeStream s{std::span<const uint8_t>{per}};
        check("PER decode", PerCodec::instance().decode(s, MinRec::asn_DEF, &back).has_value());
    }
    check("PER round trip", same(v, back));
    check("PER: absent DEFAULT lo reads as -2^63", back.lo && back.lo->value() == kMin);

    std::vector<uint8_t> ber;
    {
        BerWriter w(ber);
        BerEncodeStream s{w};
        BerCodec::instance().encode(s, MinRec::asn_DEF, &v);
    }
    MinRec bback{};
    {
        BerReader r{std::span<const uint8_t>{ber}};
        BerDecodeStream s{r};
        check("BER decode", BerCodec::instance().decode(s, MinRec::asn_DEF, &bback).has_value());
    }
    check("BER round trip", same(v, bback));

    MinRec d = make_rec();
    d.lo = std::make_unique<Integer>(kMin);
    std::vector<uint8_t> ber_default;
    {
        BerWriter w(ber_default);
        BerEncodeStream s{w};
        BerCodec::instance().encode(s, MinRec::asn_DEF, &d);
    }
    check("BER: lo equal to DEFAULT -2^63 is omitted", ber_default == ber);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
