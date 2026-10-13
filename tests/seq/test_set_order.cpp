// SET component order (per_set_order_test.asn1, IMPLICIT TAGS, components
// declared out of tag order).
//
//   - BER decode accepts the components in any order (X.690 §8.11.2): the
//     same value arrives in declaration order and in canonical order.
//   - BER encode writes canonical tag order (X.680 §8.6, as DER requires,
//     X.690 §10.3).
//   - PER encodes the root components in canonical tag order (X.691 §20).
//
// Expected bytes are asn1c's DER / UPER output for the same value
// (third = 2, first = FALSE, zeroth = 199, second absent).
#include <cstdio>
#include <span>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
#include "Rec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static bool ber_dec(std::span<const uint8_t> bytes, Rec& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, Rec::asn_DEF, &out).has_value();
}

static std::vector<uint8_t> ber_enc(const Rec& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, Rec::asn_DEF, &v);
    return buf;
}

static std::vector<uint8_t> per_enc(const Rec& v) {
    std::vector<uint8_t> buf;
    PerEncodeStream s{buf};
    IEncodeStream& es = s;
    PerCodec::instance().encode(es, Rec::asn_DEF, &v);
    s.flush();
    return buf;
}

static bool is_expected(const Rec& v) {
    return v.third.value() == 2 && !v.first.value() && v.zeroth.value() == 199 && !v.second;
}

int main() {
    const std::vector<uint8_t> declaration_order = {
        0x31, 0x0a, 0x83, 0x01, 0x02, 0x81, 0x01, 0x00, 0x80, 0x02, 0x00, 0xc7};
    const std::vector<uint8_t> canonical_order = {
        0x31, 0x0a, 0x80, 0x02, 0x00, 0xc7, 0x81, 0x01, 0x00, 0x83, 0x01, 0x02};

    Rec a{};
    check("BER decode, declaration order", ber_dec(declaration_order, a) && is_expected(a));
    Rec b{};
    check("BER decode, canonical order", ber_dec(canonical_order, b) && is_expected(b));
    check("BER encode writes canonical order (asn1c DER)", ber_enc(a) == canonical_order);
    check("PER encodes root components in canonical order (asn1c UPER 63 90)",
          per_enc(a) == std::vector<uint8_t>{0x63, 0x90});

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
