// BER + XER round-trip tests for SEQUENCE containing a NULL member.
// Schema: tests/asn1/null_test.asn1  —  type from generated HasNull.hpp / HasNull.cpp.
// BER wire format: HasNull { present=NULL } → 30 02 05 00
//   0x30 = SEQUENCE, 0x02 = length 2, 0x05 = NULL tag, 0x00 = length 0
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "HasNull.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_encode(const HasNull& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasNull, &v);
    return buf;
}

static bool ber_decode(std::span<const uint8_t> bytes, HasNull& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasNull, &out).has_value();
}

static std::string xer_encode(const HasNull& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, asn_DEF_HasNull, &v);
    return oss.str();
}

static bool xer_decode(const std::string& xml, HasNull& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, asn_DEF_HasNull, &out).has_value();
}

int main() {
    printf("\n── NULL member — HasNull BER ────────────────────────────────────\n");

    HasNull v{Null{}};
    auto enc = ber_encode(v);

    check("HasNull BER encodes as 30 02 05 00",
          enc == std::vector<uint8_t>({0x30, 0x02, 0x05, 0x00}));

    HasNull got{};
    check("HasNull BER round-trip decodes ok", ber_decode(enc, got));
    check("HasNull round-trip present == Null{}", got.present == Null{});

    printf("\n── NULL member — HasNull XER ────────────────────────────────────\n");

    auto xml = xer_encode(v);
    check("HasNull XER encode contains <present></present>",
          xml.find("<present></present>") != std::string::npos);

    HasNull xgot{};
    check("HasNull XER decode ok", xer_decode(xml, xgot));
    check("HasNull XER round-trip present == Null{}", xgot.present == Null{});

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
