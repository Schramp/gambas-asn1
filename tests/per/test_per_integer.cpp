// PER (UPER) integer encoding tests.
// Constructs TypeDescriptors matching what the generator emits for:
//   tests/asn1/narrow_int.asn1  — NarrowInterval ::= INTEGER (123456..123457)
//   Interval ::= INTEGER (1..123456)   from asn1c test 07-int-OK.asn1
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include <asn1cpp/codec/PerConstraints.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond, const char* detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name, *detail ? ": " : "", detail);
        ++failures;
    }
}

// Encode int64_t via PER using the given TypeDescriptor.
static std::vector<uint8_t> per_encode(const TypeDescriptor& def, int64_t v) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    PerCodec::instance().encode(s, def, &v);
    s.flush();
    return buf;
}

// Decode int64_t via PER.
static bool per_decode(const TypeDescriptor& def,
                       std::span<const uint8_t> bytes, int64_t& out) {
    PerDecodeStream s{bytes};
    auto r = PerCodec::instance().decode(s, def, &out);
    return r.has_value();
}

static bool encodes_as(const TypeDescriptor& def, int64_t v,
                        std::initializer_list<uint8_t> expected) {
    auto got = per_encode(def, v);
    std::vector<uint8_t> exp(expected);
    return got == exp;
}

static bool roundtrips(const TypeDescriptor& def, int64_t v) {
    auto enc = per_encode(def, v);
    int64_t dec = 0;
    if (!per_decode(def, enc, dec)) return false;
    return dec == v;
}

// ---- NarrowInterval: INTEGER (123456..123457) --------------------------------
// range=2, range_bits=1; encoded = value - 123456 (0 or 1), 1 bit.

static const TypeDescriptor DEF_NarrowInterval = {
    "NarrowInterval",
    Tag::universal(2, false),
    nullptr, nullptr, nullptr,
    {PerConstraints::CONSTRAINED, 1, 123456, 123457}
};

// ---- Interval: INTEGER (1..123456) ------------------------------------------
// range=123456, range_bits=17.

static const TypeDescriptor DEF_Interval = {
    "Interval",
    Tag::universal(2, false),
    nullptr, nullptr, nullptr,
    {PerConstraints::CONSTRAINED, 17, 1, 123456}
};

int main() {
    printf("\n── PER INTEGER — NarrowInterval (123456..123457, 1 bit) ────────\n");

    check("123456 encodes as 0x00 (bit 0, padded)",
          encodes_as(DEF_NarrowInterval, 123456, {0x00}));

    check("123457 encodes as 0x80 (bit 1, padded)",
          encodes_as(DEF_NarrowInterval, 123457, {0x80}));

    check("123456 round-trip", roundtrips(DEF_NarrowInterval, 123456));
    check("123457 round-trip", roundtrips(DEF_NarrowInterval, 123457));

    printf("\n── PER INTEGER — Interval (1..123456, 17 bits) ─────────────────\n");

    check("1      encodes as 00 00 00", encodes_as(DEF_Interval, 1,      {0x00, 0x00, 0x00}));
    check("42     encodes as 00 14 80", encodes_as(DEF_Interval, 42,     {0x00, 0x14, 0x80}));
    check("123456 encodes as f1 1f 80", encodes_as(DEF_Interval, 123456, {0xf1, 0x1f, 0x80}));

    check("1      round-trip", roundtrips(DEF_Interval, 1));
    check("42     round-trip", roundtrips(DEF_Interval, 42));
    check("123456 round-trip", roundtrips(DEF_Interval, 123456));

    printf("\n");
    if (failures) {
        printf("  %d test(s) FAILED\n", failures);
        return 1;
    }
    printf("  All tests passed.\n");
    return 0;
}
