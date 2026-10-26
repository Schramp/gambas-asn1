// REAL DEFAULT values (real_default_test.asn1); mirrors
// tests/rust/real_default/src/main.rs. Defaults has five DEFAULT REAL
// members and a mandatory `tag` INTEGER.
#include <cmath>
#include <cstdio>
#include <limits>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "Defaults.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::vector<uint8_t> ber_enc(const Defaults& v) {
    std::vector<uint8_t> out;
    BerWriter w(out);
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, Defaults::asn_DEF, &v);
    return out;
}

static bool ber_dec(std::span<const uint8_t> bytes, Defaults& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Defaults::asn_DEF, &out).has_value();
}

int main() {
    constexpr double inf = std::numeric_limits<double>::infinity();
    printf("=== REAL DEFAULT ===\n");

    // SEQUENCE { tag [5] 7 }: every DEFAULT member absent.
    const std::vector<uint8_t> only_tag = {0x30, 0x03, 0x85, 0x01, 0x07};
    Defaults d{};
    check("decode with every DEFAULT absent", ber_dec(only_tag, d));
    check("kilo reads as 1.5E3",   d.kilo && d.kilo->value() == 1500.0);
    check("two reads as 2",        d.two && d.two->value() == 2.0);
    check("inf reads as PLUS-INFINITY",   d.inf && d.inf->value() == inf);
    check("negInf reads as MINUS-INFINITY", d.negInf && d.negInf->value() == -inf);
    check("zero reads as +0",      d.zero && d.zero->value() == 0.0 && !std::signbit(d.zero->value()));

    check("members equal to their defaults are not encoded", ber_enc(d) == only_tag);

    Defaults m{};
    m.tag = 7;
    m.zero = std::make_unique<Real>(-0.0);
    auto bytes = ber_enc(m);
    check("minus zero differs from the zero default and is encoded",
          bytes == std::vector<uint8_t>({0x30, 0x06, 0x84, 0x01, 0x43, 0x85, 0x01, 0x07}));
    Defaults back{};
    check("minus zero round-trips",
          ber_dec(bytes, back) && back.zero && std::signbit(back.zero->value()));

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
