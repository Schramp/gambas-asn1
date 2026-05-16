// BER + XER round-trip tests for SEQUENCE containing UTCTime and GeneralizedTime members.
// Schema: tests/asn1/time_test.asn1
//
// UTCTime "240115Z" (7 bytes) → tag 0x17, len 7
//   SEQUENCE: 30 09 17 07 32 34 30 31 31 35 5A
//
// GeneralizedTime "20240115Z" (9 bytes) → tag 0x18, len 9
//   SEQUENCE: 30 0B 18 09 32 30 32 34 30 31 31 35 5A
#include <cstdio>
#include <sstream>
#include <vector>
#include <span>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "HasUtcTime.hpp"
#include "HasGeneralizedTime.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> ber_encode_utc(const HasUtcTime& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasUtcTime, &v);
    return buf;
}

static bool ber_decode_utc(std::span<const uint8_t> bytes, HasUtcTime& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasUtcTime, &out).has_value();
}

static std::vector<uint8_t> ber_encode_gen(const HasGeneralizedTime& v) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, asn_DEF_HasGeneralizedTime, &v);
    return buf;
}

static bool ber_decode_gen(std::span<const uint8_t> bytes, HasGeneralizedTime& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, asn_DEF_HasGeneralizedTime, &out).has_value();
}

int main() {
    printf("\n── UTCTime — HasUtcTime BER ─────────────────────────────────────\n");

    // "240115Z" = 0x32 0x34 0x30 0x31 0x31 0x35 0x5A (7 bytes)
    // SEQUENCE: 30 09 17 07 <7 bytes>
    HasUtcTime v_utc; v_utc.ts = UtcTime{"240115Z"};
    auto enc_utc = ber_encode_utc(v_utc);
    check("HasUtcTime{\"240115Z\"} BER encodes as 30 09 17 07 ...",
          enc_utc.size() == 11 && enc_utc[0] == 0x30 && enc_utc[2] == 0x17 && enc_utc[3] == 0x07);

    HasUtcTime got_utc{};
    check("HasUtcTime BER round-trip decodes ok", ber_decode_utc(enc_utc, got_utc));
    check("HasUtcTime round-trip value matches",  got_utc.ts.str() == "240115Z");

    check("HasUtcTime \"240115143000Z\" round-trip", [&]{
        HasUtcTime v; v.ts = UtcTime{"240115143000Z"};
        auto enc = ber_encode_utc(v);
        HasUtcTime got{};
        return ber_decode_utc(enc, got) && got.ts.str() == "240115143000Z";
    }());

    printf("\n── GeneralizedTime — HasGeneralizedTime BER ─────────────────────\n");

    // "20240115Z" = 9 bytes; SEQUENCE: 30 0B 18 09 <9 bytes>
    HasGeneralizedTime v_gen; v_gen.ts = GeneralizedTime{"20240115Z"};
    auto enc_gen = ber_encode_gen(v_gen);
    check("HasGeneralizedTime{\"20240115Z\"} BER encodes as 30 0B 18 09 ...",
          enc_gen.size() == 13 && enc_gen[0] == 0x30 && enc_gen[2] == 0x18 && enc_gen[3] == 0x09);

    HasGeneralizedTime got_gen{};
    check("HasGeneralizedTime BER round-trip decodes ok", ber_decode_gen(enc_gen, got_gen));
    check("HasGeneralizedTime round-trip value matches",  got_gen.ts.str() == "20240115Z");

    check("HasGeneralizedTime \"20240115143000.5Z\" round-trip", [&]{
        HasGeneralizedTime v; v.ts = GeneralizedTime{"20240115143000.5Z"};
        auto enc = ber_encode_gen(v);
        HasGeneralizedTime got{};
        return ber_decode_gen(enc, got) && got.ts.str() == "20240115143000.5Z";
    }());

    printf("\n── UTCTime XER ──────────────────────────────────────────────────\n");

    {
        HasUtcTime v; v.ts = UtcTime{"240115Z"};
        std::ostringstream oss;
        XerEncodeStream xs{oss};
        XerCodec::instance().encode(xs, asn_DEF_HasUtcTime, &v);
        auto xml = oss.str();
        check("HasUtcTime XER encode contains \"240115Z\"",
              xml.find("240115Z") != std::string::npos);

        HasUtcTime got{};
        XerDecodeStream ds{xml};
        check("HasUtcTime XER decode ok",
              XerCodec::instance().decode(ds, asn_DEF_HasUtcTime, &got).has_value());
        check("HasUtcTime XER round-trip value", got.ts.str() == "240115Z");
    }

    printf("\n── GeneralizedTime XER ──────────────────────────────────────────\n");

    {
        HasGeneralizedTime v; v.ts = GeneralizedTime{"20240115143000.5Z"};
        std::ostringstream oss;
        XerEncodeStream xs{oss};
        XerCodec::instance().encode(xs, asn_DEF_HasGeneralizedTime, &v);
        auto xml = oss.str();
        check("HasGeneralizedTime XER encode contains \"20240115143000.5Z\"",
              xml.find("20240115143000.5Z") != std::string::npos);

        HasGeneralizedTime got{};
        XerDecodeStream ds{xml};
        check("HasGeneralizedTime XER decode ok",
              XerCodec::instance().decode(ds, asn_DEF_HasGeneralizedTime, &got).has_value());
        check("HasGeneralizedTime XER round-trip value", got.ts.str() == "20240115143000.5Z");
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
