// BER round-trip tests for primitive types — mirrors the style of test_anon.py
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <span>
#include <string>
#include <asn1cpp/asn1cpp.hpp>

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

// Round-trip: encode then decode, verify the value is preserved
template<typename T>
bool roundtrip(const T& v) {
    auto encoded = encode<BER>(v);
    auto decoded = decode<BER, T>(encoded);
    if (!decoded) return false;
    return *decoded == v;
}

// Encode to bytes and compare with hand-crafted expected bytes
template<typename T>
bool encodes_as(const T& v, std::initializer_list<uint8_t> expected) {
    auto encoded = encode<BER>(v);
    std::vector<uint8_t> exp(expected);
    return encoded == exp;
}

int main() {
    // =========================================================================
    printf("\n── INTEGER ─────────────────────────────────────────────────────\n");
    // =========================================================================

    check("INTEGER 0 encodes as 02 01 00",
          encodes_as(Integer{0}, {0x02, 0x01, 0x00}));

    check("INTEGER 127 encodes as 02 01 7F",
          encodes_as(Integer{127}, {0x02, 0x01, 0x7F}));

    // 128 needs 0x00 sign-extension byte: 02 02 00 80
    check("INTEGER 128 encodes as 02 02 00 80",
          encodes_as(Integer{128}, {0x02, 0x02, 0x00, 0x80}));

    check("INTEGER -1 encodes as 02 01 FF",
          encodes_as(Integer{-1}, {0x02, 0x01, 0xFF}));

    check("INTEGER -128 encodes as 02 01 80",
          encodes_as(Integer{-128}, {0x02, 0x01, 0x80}));

    // -129 = 0xFF7F: 02 02 FF 7F
    check("INTEGER -129 encodes as 02 02 FF 7F",
          encodes_as(Integer{-129}, {0x02, 0x02, 0xFF, 0x7F}));

    check("INTEGER 0 round-trip",    roundtrip(Integer{0}));
    check("INTEGER 42 round-trip",   roundtrip(Integer{42}));
    check("INTEGER -200 round-trip", roundtrip(Integer{-200}));
    check("INTEGER 1000000 round-trip", roundtrip(Integer{1000000}));
    check("INTEGER INT64_MIN round-trip", roundtrip(Integer{INT64_MIN}));

    // =========================================================================
    printf("\n── BOOLEAN ─────────────────────────────────────────────────────\n");
    // =========================================================================

    check("BOOLEAN FALSE encodes as 01 01 00",
          encodes_as(Boolean{false}, {0x01, 0x01, 0x00}));

    check("BOOLEAN TRUE encodes as 01 01 FF",
          encodes_as(Boolean{true}, {0x01, 0x01, 0xFF}));

    check("BOOLEAN FALSE round-trip", roundtrip(Boolean{false}));
    check("BOOLEAN TRUE round-trip",  roundtrip(Boolean{true}));

    // BER: any nonzero byte is TRUE when decoding
    {
        std::vector<uint8_t> ber = {0x01, 0x01, 0x42};  // non-canonical TRUE
        auto r = decode<BER, Boolean>(ber);
        check("BOOLEAN nonzero decodes as TRUE", r && r->value());
    }

    // =========================================================================
    printf("\n── NULL ────────────────────────────────────────────────────────\n");
    // =========================================================================

    check("NULL encodes as 05 00",
          encodes_as(Null{}, {0x05, 0x00}));

    check("NULL round-trip", roundtrip(Null{}));

    // =========================================================================
    printf("\n── OCTET STRING ────────────────────────────────────────────────\n");
    // =========================================================================

    OctetString os1{std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}};
    check("OCTET STRING encodes as 04 04 DE AD BE EF",
          encodes_as(os1, {0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}));

    check("OCTET STRING round-trip", roundtrip(os1));
    check("OCTET STRING empty round-trip", roundtrip(OctetString{}));

    // =========================================================================
    printf("\n── BIT STRING ──────────────────────────────────────────────────\n");
    // =========================================================================

    // BIT STRING with 3 unused bits, payload 0xA8 -> 03 02 03 A8
    BitString bs1{{0xA8}, 3};
    check("BIT STRING encodes as 03 02 03 A8",
          encodes_as(bs1, {0x03, 0x02, 0x03, 0xA8}));

    check("BIT STRING round-trip", roundtrip(bs1));
    check("BIT STRING 0 unused round-trip", roundtrip(BitString{{0xFF}, 0}));

    // =========================================================================
    printf("\n── OBJECT IDENTIFIER ───────────────────────────────────────────\n");
    // =========================================================================

    // OID 2.5.4.3 (commonName) = 06 03 55 04 03
    Oid oid1{{2, 5, 4, 3}};
    check("OID 2.5.4.3 encodes as 06 03 55 04 03",
          encodes_as(oid1, {0x06, 0x03, 0x55, 0x04, 0x03}));

    check("OID 2.5.4.3 round-trip", roundtrip(oid1));

    // OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    Oid oid2{{1, 2, 840, 113549, 1, 1, 11}};
    check("OID 1.2.840.113549.1.1.11 round-trip", roundtrip(oid2));

    // =========================================================================
    printf("\n── STRING TYPES ────────────────────────────────────────────────\n");
    // =========================================================================

    check("UTF8String round-trip", roundtrip(Utf8String{"Hello, World!"}));
    check("UTF8String empty round-trip", roundtrip(Utf8String{""}));
    check("IA5String round-trip",  roundtrip(Ia5String{"test@example.com"}));
    check("PrintableString round-trip", roundtrip(PrintableString{"Test 123"}));

    // UTF8String "AB" encodes as 0C 02 41 42
    check("UTF8String 'AB' encodes as 0C 02 41 42",
          encodes_as(Utf8String{"AB"}, {0x0C, 0x02, 0x41, 0x42}));

    // =========================================================================
    printf("\n── TIME TYPES ──────────────────────────────────────────────────\n");
    // =========================================================================

    check("UTCTime round-trip", roundtrip(UtcTime{"240115143000Z"}));
    check("GeneralizedTime round-trip", roundtrip(GeneralizedTime{"20240115143000.123Z"}));

    // =========================================================================
    printf("\n── REAL ────────────────────────────────────────────────────────\n");
    // =========================================================================

    check("REAL 0.0 encodes as 09 00 (zero-length)",
          encodes_as(Real{0.0}, {0x09, 0x00}));

    check("REAL 0.0 round-trip", roundtrip(Real{0.0}));
    check("REAL 1.0 round-trip", roundtrip(Real{1.0}));
    check("REAL -1.5 round-trip", roundtrip(Real{-1.5}));

    // =========================================================================
    printf("\n── INDEFINITE-LENGTH BER decode ────────────────────────────────\n");
    // =========================================================================

    // X.690 §8.1.3.2: indefinite-length is illegal on primitive types — must be rejected.
    {
        std::vector<uint8_t> ber_indef = {0x04, 0x80, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00};
        auto r = decode<BER, OctetString>(ber_indef);
        check("Indefinite-length primitive OCTET STRING rejected", !r);
    }

    // =========================================================================
    printf("\n");
    if (failures) {
        printf("  %d test(s) FAILED\n", failures);
        return 1;
    }
    printf("  All tests passed.\n");
    return 0;
}
