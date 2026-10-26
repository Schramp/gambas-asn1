// BER REAL contents-octet decoding (X.690 §8.5). The vector table is shared
// with rust-runtime/wire/src/real.rs (`DECODE_VECTORS`): both runtimes must
// give the same double, bit for bit, or both an error.
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
        {"2^1024 is out of range",                     {0x81, 0x04, 0x00, 0x01},             false, 0},
        {"exponent ~2^31 is out of range",             {0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01}, false, 0},
        {"2^-1076 rounds to zero: out of range",       {0x81, 0xFB, 0xCC, 0x01},             false, 0},
        {"format d without length octet",              {0x83},                               false, 0},
        {"format d, X=0",                              {0x83, 0x00, 0x01},                   false, 0},
        {"format d, truncated exponent",               {0x83, 0x02, 0x00},                   false, 0},
        {"format b, truncated exponent",               {0x81, 0x00},                         false, 0},
        {"special value with extra octet",             {0x40, 0x00},                         false, 0},
        {"reserved special value 0x44 (§8.5.9)",       {0x44},                               false, 0},
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

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
