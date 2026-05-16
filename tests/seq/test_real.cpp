// BER + XER round-trip tests for SEQUENCE containing a REAL member.
// Schema: tests/asn1/real_test.asn1  —  type from generated HasReal.hpp / HasReal.cpp.
// BER wire format: HasReal{0.0} → 30 02 09 00  (zero: empty content)
//                  HasReal{1.0} → 30 07 09 05 80 00 01  (binary: info=0x80, exp=0x00, mant=0x01)
//   wait — let the test compute and verify round-trips; only 0.0 bytes are trivially known.
#include <cstdio>
#include <cmath>
#include <sstream>
#include <string>
#include <vector>
#include <span>
#include <asn1cpp/asn1cpp.hpp>
#include "HasReal.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_encode(const HasReal& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasReal, &v);
    return buf;
}

static bool ber_decode(std::span<const uint8_t> bytes, HasReal& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasReal, &out).has_value();
}

static bool ber_roundtrip(double d) {
    HasReal v; v.value = Real{d};
    auto enc = ber_encode(v);
    HasReal got{};
    if (!ber_decode(enc, got)) return false;
    if (std::isnan(d)) return std::isnan(got.value.value());
    return got.value.value() == d;
}

static std::string xer_encode_real(const HasReal& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, asn_DEF_HasReal, &v);
    return oss.str();
}

static bool xer_decode_real(const std::string& xml, HasReal& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, asn_DEF_HasReal, &out).has_value();
}

static bool xer_roundtrip(double d) {
    HasReal v; v.value = Real{d};
    auto xml = xer_encode_real(v);
    HasReal got{};
    if (!xer_decode_real(xml, got)) return false;
    if (std::isnan(d)) return std::isnan(got.value.value());
    return got.value.value() == d;
}

int main() {
    printf("\n── REAL member — HasReal BER ────────────────────────────────────\n");

    // 0.0 encodes as SEQUENCE { REAL{} } = 30 02 09 00
    HasReal zero; zero.value = Real{0.0};
    auto enc_zero = ber_encode(zero);
    check("HasReal{0.0} BER encodes as 30 02 09 00",
          enc_zero == std::vector<uint8_t>({0x30, 0x02, 0x09, 0x00}));

    check("HasReal{0.0} BER round-trip",   ber_roundtrip(0.0));
    check("HasReal{1.0} BER round-trip",   ber_roundtrip(1.0));
    check("HasReal{-1.0} BER round-trip",  ber_roundtrip(-1.0));
    check("HasReal{3.14} BER round-trip",  ber_roundtrip(3.14));
    check("HasReal{1e100} BER round-trip", ber_roundtrip(1e100));
    check("HasReal{+inf} BER round-trip",  ber_roundtrip(std::numeric_limits<double>::infinity()));
    check("HasReal{-inf} BER round-trip",  ber_roundtrip(-std::numeric_limits<double>::infinity()));

    printf("\n── REAL member — HasReal XER ────────────────────────────────────\n");

    { HasReal _v; _v.value = Real{0.0};
      auto xml_zero = xer_encode_real(_v);
      check("HasReal{0.0} XER contains <value>0</value>",
            xml_zero.find("<value>0</value>") != std::string::npos); }

    { HasReal _v; _v.value = Real{3.14};
      auto xml_pi = xer_encode_real(_v);
      check("HasReal{3.14} XER contains <value>3.14</value>",
            xml_pi.find("<value>3.14</value>") != std::string::npos); }

    { HasReal _v; _v.value = Real{std::numeric_limits<double>::infinity()};
      auto xml_pinf = xer_encode_real(_v);
      check("HasReal{+inf} XER contains <PLUS-INFINITY/>",
            xml_pinf.find("<PLUS-INFINITY/>") != std::string::npos); }

    { HasReal _v; _v.value = Real{-std::numeric_limits<double>::infinity()};
      auto xml_ninf = xer_encode_real(_v);
      check("HasReal{-inf} XER contains <MINUS-INFINITY/>",
            xml_ninf.find("<MINUS-INFINITY/>") != std::string::npos); }

    { HasReal _v; _v.value = Real{std::numeric_limits<double>::quiet_NaN()};
      auto xml_nan = xer_encode_real(_v);
      check("HasReal{NaN} XER contains <NOT-A-NUMBER/>",
            xml_nan.find("<NOT-A-NUMBER/>") != std::string::npos); }

    check("HasReal{0.0} XER round-trip",   xer_roundtrip(0.0));
    check("HasReal{1.0} XER round-trip",   xer_roundtrip(1.0));
    check("HasReal{3.14} XER round-trip",  xer_roundtrip(3.14));
    check("HasReal{+inf} XER round-trip",  xer_roundtrip(std::numeric_limits<double>::infinity()));
    check("HasReal{-inf} XER round-trip",  xer_roundtrip(-std::numeric_limits<double>::infinity()));
    check("HasReal{NaN} XER round-trip",   xer_roundtrip(std::numeric_limits<double>::quiet_NaN()));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
