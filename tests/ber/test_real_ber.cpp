// BER REAL contents-octet decoding (X.690 §8.5) and storage classes. Both
// vector tables are shared with rust-runtime/wire/src/real.rs
// (`decode_vectors`, `storage_vectors`): both runtimes must give the same
// double bit for bit (or both an error), the same storage class, and the
// same CER/DER re-encoding (X.690 §11.3).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

struct Vector {
    const char*          label;
    std::vector<uint8_t> contents;
    bool                 ok;
    uint64_t             bits;   ///< IEEE 754 bit pattern when ok.
};

static uint64_t bits_of(double d) { uint64_t b; std::memcpy(&b, &d, 8); return b; }

static std::vector<uint8_t> with_zeros(std::vector<uint8_t> head, int zeros, std::vector<uint8_t> tail = {}) {
    head.insert(head.end(), zeros, 0x00);
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

int main() {
    printf("=== BER REAL decode (X.690 §8.5) ===\n");
    const std::vector<Vector> vectors = {
        {"plus zero, no contents (§8.5.2)",            {},                                   true,  0x0000000000000000},
        {"1.0, exponent format a",                     {0x80, 0x00, 0x01},                   true,  0x3FF0000000000000},
        {"-1.0 (§8.5.7.1)",                            {0xC0, 0x00, 0x01},                   true,  0xBFF0000000000000},
        {"2.0 via scaling factor F=1 (§8.5.7.3)",      {0x84, 0x00, 0x01},                   true,  0x4000000000000000},
        {"1.0, format d, X=1 (§8.5.7.4 d)",            {0x83, 0x01, 0x00, 0x01},             true,  0x3FF0000000000000},
        {"1.0, format d, X=2",                         {0x83, 0x02, 0x00, 0x00, 0x01},       true,  0x3FF0000000000000},
        {"1.0, format d, X=5",                         {0x83, 0x05, 0, 0, 0, 0, 0, 0x01},    true,  0x3FF0000000000000},
        {"1.0, format d, exponent -1 in 9 octets",     {0x83, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02},
                                                                                             true,  0x3FF0000000000000},
        {"2^72, 10-octet mantissa (§8.5.7.5 NOTE 1)",  with_zeros({0x80, 0x00, 0x01}, 9),    true,  0x4470000000000000},
        {"2^-64, 11-octet mantissa, exponent -80",     with_zeros({0x80, 0xB0}, 8, {0x01, 0x00, 0x00}),
                                                                                             true,  0x3BF0000000000000},
        {"2^53+1 rounds to even 2^53",                 {0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x01}, true, 0x4340000000000000},
        {"2^53+3 rounds up to 2^53+4",                 {0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x03}, true, 0x4340000000000002},
        {"leading zero mantissa octets",               {0x80, 0x00, 0x00, 0x00, 0x01},       true,  0x3FF0000000000000},
        {"zero mantissa is zero",                      {0xC0, 0x00, 0x00},                   true,  0x8000000000000000},
        {"largest double (2^53-1) * 2^971",            {0x81, 0x03, 0xCB, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                                                                                             true,  0x7FEFFFFFFFFFFFFF},
        {"smallest subnormal 2^-1074",                 {0x81, 0xFB, 0xCE, 0x01},             true,  0x0000000000000001},
        {"3 * 2^-1076 rounds to 2^-1074",              {0x81, 0xFB, 0xCC, 0x03},             true,  0x0000000000000001},
        {"subnormal 3 * 2^-1074",                      {0x81, 0xFB, 0xCE, 0x03},             true,  0x0000000000000003},
        {"smallest normal 2^-1022",                    {0x81, 0xFC, 0x02, 0x01},             true,  0x0010000000000000},
        {"2^1024: Binary, value +inf",                 {0x81, 0x04, 0x00, 0x01},             true,  0x7FF0000000000000},
        {"exponent ~2^31: Binary, value +inf",         {0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01}, true, 0x7FF0000000000000},
        {"2^-1076: Binary, value +0",                  {0x81, 0xFB, 0xCC, 0x01},             true,  0x0000000000000000},
        {"format d without length octet",              {0x83},                               false, 0},
        {"format d, X=0",                              {0x83, 0x00, 0x01},                   false, 0},
        {"format d, truncated exponent",               {0x83, 0x02, 0x00},                   false, 0},
        {"format b, truncated exponent",               {0x81, 0x00},                         false, 0},
        {"special value with extra octet",             {0x40, 0x00},                         false, 0},
        {"reserved special value 0x44 (§8.5.9)",       {0x44},                               false, 0},
        {"decimal NR1 14 (§8.5.8)", {0x01, 0x31, 0x34}, true, 0x402C000000000000},
        {"decimal NR1 with spaces and sign", {0x01, 0x20, 0x20, 0x2D, 0x31, 0x34}, true, 0xC02C000000000000},
        {"decimal NR1 -0", {0x01, 0x2D, 0x30}, true, 0x8000000000000000},
        {"decimal NR2 14.56", {0x02, 0x31, 0x34, 0x2E, 0x35, 0x36}, true, 0x402D1EB851EB851F},
        {"decimal NR2 ISO 6093 comma 14,56", {0x02, 0x31, 0x34, 0x2C, 0x35, 0x36}, true, 0x402D1EB851EB851F},
        {"decimal NR2 .5", {0x02, 0x2E, 0x35}, true, 0x3FE0000000000000},
        {"decimal NR2 5.", {0x02, 0x35, 0x2E}, true, 0x4014000000000000},
        {"decimal NR3 14.56E0", {0x03, 0x31, 0x34, 0x2E, 0x35, 0x36, 0x45, 0x30}, true, 0x402D1EB851EB851F},
        {"decimal NR3 1456e-2, no decimal mark", {0x03, 0x31, 0x34, 0x35, 0x36, 0x65, 0x2D, 0x32}, true, 0x402D1EB851EB851F},
        {"decimal NR3 +1.456E+1", {0x03, 0x2B, 0x31, 0x2E, 0x34, 0x35, 0x36, 0x45, 0x2B, 0x31}, true, 0x402D1EB851EB851F},
        {"decimal NR1 with a mark is malformed", {0x01, 0x31, 0x2E, 0x35}, false, 0},
        {"decimal NR2 without a mark is malformed", {0x02, 0x31, 0x34}, false, 0},
        {"decimal NR3 without exponent is malformed", {0x03, 0x31, 0x34, 0x2E, 0x35, 0x36}, false, 0},
        {"decimal NR3 without exponent digits", {0x03, 0x31, 0x45}, false, 0},
        {"decimal trailing space is malformed", {0x01, 0x31, 0x34, 0x20}, false, 0},
        {"decimal empty field", {0x01}, false, 0},
        {"decimal NR3 1E400: value +inf", {0x03, 0x31, 0x45, 0x34, 0x30, 0x30}, true, 0x7FF0000000000000},
        {"decimal NR3 1E-400: value +0", {0x03, 0x31, 0x45, 0x2D, 0x34, 0x30, 0x30}, true, 0x0000000000000000},
        {"base 8, exponent 0 (§8.5.7.2)", {0x90, 0x00, 0x01}, true, 0x3FF0000000000000},
        {"base 8, exponent 1 is 8", {0x90, 0x01, 0x01}, true, 0x4020000000000000},
        {"base 8, exponent 1, F=2 is 32", {0x98, 0x01, 0x01}, true, 0x4040000000000000},
        {"base 16, exponent 1 is 16", {0xA0, 0x01, 0x01}, true, 0x4030000000000000},
        {"base 16, exponent -1 is 1/16", {0xA0, 0xFF, 0x01}, true, 0x3FB0000000000000},
        {"reserved base 11", {0xB0, 0x00, 0x01}, false, 0},
        {"reserved decimal form 0", {0x00, 0x31}, false, 0},
        {"reserved decimal form 4", {0x04, 0x31}, false, 0},
        {"PLUS-INFINITY (§8.5.9)",                     {0x40},                               true,  0x7FF0000000000000},
        {"MINUS-INFINITY",                             {0x41},                               true,  0xFFF0000000000000},
        {"minus zero",                                 {0x43},                               true,  0x8000000000000000},
    };

    for (const auto& v : vectors) {
        auto got = BerTraits<Real>::decode_value(v.contents);
        bool pass = v.ok ? (got.has_value() && bits_of(got->value()) == v.bits) : !got.has_value();
        if (!pass && got.has_value())
            printf("        got bits 0x%016llx\n", static_cast<unsigned long long>(bits_of(got->value())));
        check(v.label, pass);
    }
    auto nan = BerTraits<Real>::decode_value(std::vector<uint8_t>{0x42});
    check("NOT-A-NUMBER", nan.has_value() && std::isnan(nan->value()));

    printf("\n=== storage class and CER/DER re-encoding (X.690 §11.3) ===\n");
    using S = Real::Storage;
    struct StorageVector {
        const char*          label;
        std::vector<uint8_t> contents;
        S                    storage;
        std::vector<uint8_t> reencoded;
    };
    auto ascii = [](uint8_t head, const char* t) {
        std::vector<uint8_t> v{head};
        v.insert(v.end(), t, t + std::strlen(t));
        return v;
    };
    const std::vector<StorageVector> storage_vectors = {
        {"1.0 is Double", {0x80, 0x00, 0x01}, S::Double, {0x80, 0x00, 0x01}},
        {"2^72, 10-octet mantissa, is exact: Double", with_zeros({0x80, 0x00, 0x01}, 9), S::Double, {0x80, 0x48, 0x01}},
        {"2^60+1 needs 61 bits: Binary, kept exactly",
         {0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01}, S::Binary, {0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01}},
        {"Binary mantissa normalized odd, base 16 to base 2",
         {0xA0, 0x01, 0x20, 0, 0, 0, 0, 0, 0, 0x02}, S::Binary, {0x80, 0x05, 0x10, 0, 0, 0, 0, 0, 0, 0x01}},
        {"2^1024: Binary", {0x81, 0x04, 0x00, 0x01}, S::Binary, {0x81, 0x04, 0x00, 0x01}},
        {"-2^-1076: Binary", {0xC1, 0xFB, 0xCC, 0x01}, S::Binary, {0xC1, 0xFB, 0xCC, 0x01}},
        {"exponent 2^31 in format d: Binary, 4 exponent octets",
         {0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01}, S::Binary, {0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01}},
        {"NR2 14.56: Decimal, NR3 1456.E-2", ascii(0x02, "14.56"), S::Decimal, ascii(0x03, "1456.E-2")},
        {"NR1 100: Decimal, NR3 1.E2", ascii(0x01, "100"), S::Decimal, ascii(0x03, "1.E2")},
        {"NR1 -7: Decimal, NR3 -7.E+0", ascii(0x01, "-7"), S::Decimal, ascii(0x03, "-7.E+0")},
        {"NR3 0.0012E3 normalizes to 12.E-1", ascii(0x03, "0.0012E3"), S::Decimal, ascii(0x03, "12.E-1")},
        {"NR3 1E400: Decimal beyond the double range", ascii(0x03, "1E400"), S::Decimal, ascii(0x03, "1.E400")},
        {"X.680 pi {3141592653589793238462643383279, 10, -30}",
         ascii(0x03, "3141592653589793238462643383279E-30"), S::Decimal,
         ascii(0x03, "3141592653589793238462643383279.E-30")},
        {"NR1 000 is plus zero (Double)", ascii(0x01, "000"), S::Double, {}},
    };
    for (const auto& v : storage_vectors) {
        auto got = BerTraits<Real>::decode_value(v.contents);
        std::vector<uint8_t> out;
        if (got) {
            BerWriter w(out);
            BerTraits<Real>::encode(w, *got);
        }
        BerReader rd{std::span<const uint8_t>(out)};
        auto tlv = rd.read_tlv();
        bool pass = got && got->storage() == v.storage && tlv &&
                    std::vector<uint8_t>(tlv->value.begin(), tlv->value.end()) == v.reencoded;
        check(v.label, pass);
    }

    auto pi = BerTraits<Real>::decode_value(ascii(0x03, "3141592653589793238462643383279E-30"));
    check("pi: base 10, exact digits, nearest double",
          pi && pi->base() == 10 && pi->exact()->mantissa == "3141592653589793238462643383279" &&
          pi->exact()->exponent == -30 && pi->value() == 3.141592653589793);
    auto dec = Real::decimal(false, "1456", -2);
    check("Decimal 14.56 differs from the Double 14.56 (X.680 §20.5 NOTE 1)",
          !(dec == Real{14.56}) && dec.numerically_equal(Real{14.56}));
    check("Decimal equality compares normalized components",
          Real::decimal(false, "14560", -3) == dec && !(Real::decimal(true, "1456", -2) == dec));
    check("Binary of an exact double is Double", Real::binary(false, std::vector<uint8_t>{0x03}, -1) == Real{1.5});
    Real r = dec;
    r.set(2.0);
    check("set() makes a Double", r.storage() == S::Double && r == Real{2.0});

    // Short mantissas take a direct IEEE path; it must agree with the general
    // normalizing Real::binary at every scale, including subnormal and
    // out-of-range ones. Same inputs as the Rust
    // short_mantissa_path_matches_general_binary test.
    {
        uint64_t x = 0x9E3779B97F4A7C15ull;
        std::vector<uint64_t> mantissas = {1, 3, 0xFF, (1ull << 53) - 1, (1ull << 53) + 1, (1ull << 54) - 2, ~0ull};
        for (int i = 0; i < 64; ++i) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            mantissas.push_back(x >> (x % 60));
        }
        std::vector<int64_t> exps;
        for (int64_t e = -1200; e < 1100; e += 7) exps.push_back(e);
        for (int64_t e = -1140; e < -1060; ++e) exps.push_back(e);
        for (int64_t e = 960; e < 1030; ++e) exps.push_back(e);
        bool all = true;
        for (uint64_t m : mantissas)
            for (int64_t e : exps)
                for (bool negative : {false, true}) {
                    uint8_t mb[8];
                    for (int k = 0; k < 8; ++k) mb[k] = static_cast<uint8_t>(m >> (56 - 8 * k));
                    std::vector<uint8_t> v = {static_cast<uint8_t>(0x81 | (negative ? 0x40 : 0)),
                                              static_cast<uint8_t>(static_cast<uint16_t>(e) >> 8),
                                              static_cast<uint8_t>(e)};
                    v.insert(v.end(), mb, mb + 8);
                    auto got = detail::decode_real_contents(v);
                    if (!got || !(*got == Real::binary(negative, mb, e))) {
                        if (all) printf("        first mismatch m=%#llx e=%lld neg=%d\n",
                                        static_cast<unsigned long long>(m), static_cast<long long>(e), negative);
                        all = false;
                    }
                }
        check("short-mantissa path matches Real::binary at every scale", all);
    }

    printf("\n=== BER REAL encode of subnormal doubles (X.690 §8.5.7) ===\n");
    {
        double tiny;
        uint64_t one = 1;
        std::memcpy(&tiny, &one, 8);
        auto enc = encode<BER>(Real{tiny});
        check("2^-1074 encodes as 09 04 81 FB CE 01",
              enc == std::vector<uint8_t>{0x09, 0x04, 0x81, 0xFB, 0xCE, 0x01});
        for (uint64_t b : {uint64_t{1}, uint64_t{3}, uint64_t{0x000123456789ABCD},
                           uint64_t{0x000FFFFFFFFFFFFF}, uint64_t{0x8000000000000001}}) {
            double d;
            std::memcpy(&d, &b, 8);
            auto dec = decode<BER, Real>(encode<BER>(Real{d}));
            char label[64];
            std::snprintf(label, sizeof label, "subnormal %#llx round-trips", static_cast<unsigned long long>(b));
            check(label, dec && bits_of(dec->value()) == b);
        }
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
