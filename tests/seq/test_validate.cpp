// Validation hook coverage test.
//
// Schema: tests/asn1/validate_test.asn1
// Built only when ASN1CPP_VALIDATE + ASN1CPP_VALIDATE_ON_ENCODE are enabled.
//
// For each range constraint, 4 boundary cases are exercised:
//   - just below lower → expect fail
//   - exactly at lower  → expect pass
//   - exactly at upper  → expect pass
//   - just above upper  → expect fail
// Plus extra cases for alphabet violations, enumerated out-of-map, and
// fixed-size SIZE(N) (3 cases: under, exact, over).
//
// FROM-custom-alphabet types (HexDigit / YesNo / Vowels) consult the
// per-type alphabet table (`PerConstraints::alphabet`, populated by codegen
// via `extract_from_alphabet`) when set, otherwise fall back to the type's
// built-in alphabet. Constraint validation is independent of any encoding
// rules — alphabet checks apply equally to BER / XER / PER paths. They appear as "FROM-NOT-YET-WIRED" no-fail expectations
// here so the test stays green until the codegen change lands.

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/Validation.hpp>
#include <asn1cpp/codec/Debug.hpp>

#include "HasPct.hpp"
#include "HasTariff.hpp"
#include "HasPos.hpp"
#include "HasSigned.hpp"
#include "HasNeg.hpp"
#include "HasWide.hpp"
#include "HasTiny.hpp"
#include "HasMid.hpp"
#include "HasFixed.hpp"
#include "HasFlagsByte.hpp"
#include "HasFlagsRange.hpp"
#include "HasCode.hpp"
#include "HasName.hpp"
#include "HasToken.hpp"
#include "HasVisi.hpp"
#include "HasColor.hpp"
#include "HasShortList.hpp"
#include "HasMidList.hpp"
#include "HasHex.hpp"
#include "HasYesNo.hpp"
#include "HasVowels.hpp"

using namespace asn1;
static int failures = 0;

template<typename T>
static void encode(const T& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf; BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
}

template<typename T>
static void expect_delta(const char* label, const T& v, const TypeDescriptor& def,
                         unsigned long long expected_delta) {
    reset_validate_fail_count();
    encode(v, def);
    auto got = validate_fail_count();
    if (got != expected_delta) {
        std::printf("  \033[31mFAIL\033[0m  %s — expected %llu fails, got %llu\n",
                    label, expected_delta, got);
        ++failures;
    } else {
        std::printf("  \033[32mPASS\033[0m  %s (%llu fail%s)\n",
                    label, got, got == 1 ? "" : "s");
    }
}

int main() {
    std::printf("\n=== Validation hook coverage ===\n\n");

    // --- INTEGER (4 boundary tests each) -------------------------------------
    // PercentInt (0..100)
    std::printf("PercentInt (0..100)\n");
    { HasPct h{}; h.v = -1;  expect_delta("just below 0  → fail",  h, asn_DEF_HasPct, 1); }
    { HasPct h{}; h.v = 0;   expect_delta("exactly 0     → pass",  h, asn_DEF_HasPct, 0); }
    { HasPct h{}; h.v = 100; expect_delta("exactly 100   → pass",  h, asn_DEF_HasPct, 0); }
    { HasPct h{}; h.v = 101; expect_delta("just above 100→ fail",  h, asn_DEF_HasPct, 1); }

    // Tariff (1000..2000)
    std::printf("Tariff (1000..2000)\n");
    { HasTariff h{}; h.v = 999;  expect_delta("just below 1000  → fail", h, asn_DEF_HasTariff, 1); }
    { HasTariff h{}; h.v = 1000; expect_delta("exactly 1000     → pass", h, asn_DEF_HasTariff, 0); }
    { HasTariff h{}; h.v = 2000; expect_delta("exactly 2000     → pass", h, asn_DEF_HasTariff, 0); }
    { HasTariff h{}; h.v = 2001; expect_delta("just above 2000  → fail", h, asn_DEF_HasTariff, 1); }

    // PositiveInt (10..MAX) — semi-constrained, no upper bound
    std::printf("PositiveInt (10..MAX)\n");
    { HasPos h{}; h.v = 9;        expect_delta("just below 10    → fail", h, asn_DEF_HasPos, 1); }
    { HasPos h{}; h.v = 10;       expect_delta("exactly 10       → pass", h, asn_DEF_HasPos, 0); }
    { HasPos h{}; h.v = 1000000;  expect_delta("large value      → pass", h, asn_DEF_HasPos, 0); }
    { HasPos h{}; h.v = -1;       expect_delta("negative         → fail", h, asn_DEF_HasPos, 1); }

    // SignedSmall (-50..50)
    std::printf("SignedSmall (-50..50)\n");
    { HasSigned h{}; h.v = -51; expect_delta("just below -50   → fail", h, asn_DEF_HasSigned, 1); }
    { HasSigned h{}; h.v = -50; expect_delta("exactly -50      → pass", h, asn_DEF_HasSigned, 0); }
    { HasSigned h{}; h.v = 50;  expect_delta("exactly 50       → pass", h, asn_DEF_HasSigned, 0); }
    { HasSigned h{}; h.v = 51;  expect_delta("just above 50    → fail", h, asn_DEF_HasSigned, 1); }

    // NegRange (-1000..-1)
    std::printf("NegRange (-1000..-1)\n");
    { HasNeg h{}; h.v = -1001; expect_delta("just below -1000 → fail", h, asn_DEF_HasNeg, 1); }
    { HasNeg h{}; h.v = -1000; expect_delta("exactly -1000    → pass", h, asn_DEF_HasNeg, 0); }
    { HasNeg h{}; h.v = -1;    expect_delta("exactly -1       → pass", h, asn_DEF_HasNeg, 0); }
    { HasNeg h{}; h.v = 0;     expect_delta("just above -1 (0)→ fail", h, asn_DEF_HasNeg, 1); }

    // WideUnsigned (5..1000000)
    std::printf("WideUnsigned (5..1000000)\n");
    { HasWide h{}; h.v = 4;       expect_delta("just below 5     → fail", h, asn_DEF_HasWide, 1); }
    { HasWide h{}; h.v = 5;       expect_delta("exactly 5        → pass", h, asn_DEF_HasWide, 0); }
    { HasWide h{}; h.v = 1000000; expect_delta("exactly 1000000  → pass", h, asn_DEF_HasWide, 0); }
    { HasWide h{}; h.v = 1000001; expect_delta("just above 1000000→ fail", h, asn_DEF_HasWide, 1); }

    // --- OCTET STRING SIZE -----------------------------------------------------
    // TinyBlob (SIZE 2..4)
    std::printf("\nTinyBlob OCTET STRING (SIZE 2..4)\n");
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(1,0)); expect_delta("size 1 (under)   → fail", h, asn_DEF_HasTiny, 1); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(2,0)); expect_delta("size 2 (boundary)→ pass", h, asn_DEF_HasTiny, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(4,0)); expect_delta("size 4 (boundary)→ pass", h, asn_DEF_HasTiny, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(5,0)); expect_delta("size 5 (over)    → fail", h, asn_DEF_HasTiny, 1); }

    // MidBlob (SIZE 5..12)
    std::printf("MidBlob OCTET STRING (SIZE 5..12)\n");
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(4,0));  expect_delta("size 4 (under)    → fail", h, asn_DEF_HasMid, 1); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(5,0));  expect_delta("size 5 (boundary) → pass", h, asn_DEF_HasMid, 0); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(12,0)); expect_delta("size 12 (boundary)→ pass", h, asn_DEF_HasMid, 0); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(13,0)); expect_delta("size 13 (over)    → fail", h, asn_DEF_HasMid, 1); }

    // FixedBlob (SIZE 8) — single boundary; 3 cases
    std::printf("FixedBlob OCTET STRING (SIZE 8)\n");
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(7,0)); expect_delta("size 7 (under)→ fail", h, asn_DEF_HasFixed, 1); }
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(8,0)); expect_delta("size 8 (exact)→ pass", h, asn_DEF_HasFixed, 0); }
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(9,0)); expect_delta("size 9 (over) → fail", h, asn_DEF_HasFixed, 1); }

    // --- BIT STRING SIZE ------------------------------------------------------
    // FlagsByte (SIZE 8) — 3 cases
    std::printf("\nFlagsByte BIT STRING (SIZE 8)\n");
    { HasFlagsByte h{}; h.v = BitString{{0xff}, 1};                  expect_delta("7 bits (under)→ fail", h, asn_DEF_HasFlagsByte, 1); }
    { HasFlagsByte h{}; h.v = BitString{{0xff}, 0};                  expect_delta("8 bits (exact)→ pass", h, asn_DEF_HasFlagsByte, 0); }
    { HasFlagsByte h{}; h.v = BitString{{0xff,0xff}, 0};             expect_delta("16 bits (over)→ fail", h, asn_DEF_HasFlagsByte, 1); }

    // FlagsRange (SIZE 16..24)
    std::printf("FlagsRange BIT STRING (SIZE 16..24)\n");
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff}, 1};             expect_delta("15 bits (under)   → fail", h, asn_DEF_HasFlagsRange, 1); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff}, 0};             expect_delta("16 bits (boundary)→ pass", h, asn_DEF_HasFlagsRange, 0); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff,0xff}, 0};        expect_delta("24 bits (boundary)→ pass", h, asn_DEF_HasFlagsRange, 0); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff,0xff,0xff}, 0};   expect_delta("32 bits (over)    → fail", h, asn_DEF_HasFlagsRange, 1); }

    // --- String SIZE + alphabet ----------------------------------------------
    // Code (NumericString SIZE 3..6)
    std::printf("\nCode NumericString (SIZE 3..6)\n");
    { HasCode h{}; h.v = NumericString{"12"};      expect_delta("size 2 (under)    → fail", h, asn_DEF_HasCode, 1); }
    { HasCode h{}; h.v = NumericString{"123"};     expect_delta("size 3 (boundary) → pass", h, asn_DEF_HasCode, 0); }
    { HasCode h{}; h.v = NumericString{"123456"};  expect_delta("size 6 (boundary) → pass", h, asn_DEF_HasCode, 0); }
    { HasCode h{}; h.v = NumericString{"1234567"}; expect_delta("size 7 (over)     → fail", h, asn_DEF_HasCode, 1); }
    { HasCode h{}; h.v = NumericString{"12X"};     expect_delta("alphabet ('X')    → fail", h, asn_DEF_HasCode, 1); }

    // Name (PrintableString SIZE 2..20)
    std::printf("Name PrintableString (SIZE 2..20)\n");
    { HasName h{}; h.v = PrintableString{"x"};                       expect_delta("size 1 (under)    → fail", h, asn_DEF_HasName, 1); }
    { HasName h{}; h.v = PrintableString{"hi"};                      expect_delta("size 2 (boundary) → pass", h, asn_DEF_HasName, 0); }
    { HasName h{}; h.v = PrintableString{std::string(20, 'a')};      expect_delta("size 20 (boundary)→ pass", h, asn_DEF_HasName, 0); }
    { HasName h{}; h.v = PrintableString{std::string(21, 'a')};      expect_delta("size 21 (over)    → fail", h, asn_DEF_HasName, 1); }
    { HasName h{}; h.v = PrintableString{"hi#bad"};                  expect_delta("alphabet ('#')    → fail", h, asn_DEF_HasName, 1); }

    // Token (IA5String SIZE 4..10)
    std::printf("Token IA5String (SIZE 4..10)\n");
    { HasToken h{}; h.v = Ia5String{"abc"};                          expect_delta("size 3 (under)    → fail", h, asn_DEF_HasToken, 1); }
    { HasToken h{}; h.v = Ia5String{"abcd"};                         expect_delta("size 4 (boundary) → pass", h, asn_DEF_HasToken, 0); }
    { HasToken h{}; h.v = Ia5String{std::string(10, 'a')};           expect_delta("size 10 (boundary)→ pass", h, asn_DEF_HasToken, 0); }
    { HasToken h{}; h.v = Ia5String{std::string(11, 'a')};           expect_delta("size 11 (over)    → fail", h, asn_DEF_HasToken, 1); }
    { HasToken h{}; std::string s = "ab\x80""x"; h.v = Ia5String{s}; expect_delta("alphabet (0x80)   → fail", h, asn_DEF_HasToken, 1); }

    // Visi (VisibleString SIZE 6..12)
    std::printf("Visi VisibleString (SIZE 6..12)\n");
    { HasVisi h{}; h.v = VisibleString{"hello"};                      expect_delta("size 5 (under)    → fail", h, asn_DEF_HasVisi, 1); }
    { HasVisi h{}; h.v = VisibleString{"hellos"};                     expect_delta("size 6 (boundary) → pass", h, asn_DEF_HasVisi, 0); }
    { HasVisi h{}; h.v = VisibleString{std::string(12, 'a')};         expect_delta("size 12 (boundary)→ pass", h, asn_DEF_HasVisi, 0); }
    { HasVisi h{}; h.v = VisibleString{std::string(13, 'a')};         expect_delta("size 13 (over)    → fail", h, asn_DEF_HasVisi, 1); }
    { HasVisi h{}; std::string s = "hellosx\x01"; h.v = VisibleString{s}; expect_delta("alphabet (0x01)   → fail", h, asn_DEF_HasVisi, 1); }

    // --- FROM custom alphabets ----------------------------------------------
    // HexDigit IA5String (FROM "0-9A-F") (SIZE 1..8)
    std::printf("\nHexDigit IA5String (FROM 0-9A-F, SIZE 1..8)\n");
    { HasHex h{}; h.v = Ia5String{"DEADBEEF"};         expect_delta("\"DEADBEEF\" valid    → pass", h, asn_DEF_HasHex, 0); }
    { HasHex h{}; h.v = Ia5String{"0"};                expect_delta("size 1 (boundary)   → pass", h, asn_DEF_HasHex, 0); }
    { HasHex h{}; h.v = Ia5String{""};                 expect_delta("empty (under)       → fail", h, asn_DEF_HasHex, 1); }
    { HasHex h{}; h.v = Ia5String{"0123456789"};       expect_delta("size 10 (over)      → fail", h, asn_DEF_HasHex, 1); }
    { HasHex h{}; h.v = Ia5String{"DEADbeef"};         expect_delta("lowercase (FROM)    → fail", h, asn_DEF_HasHex, 1); }
    { HasHex h{}; h.v = Ia5String{"DEADGOOD"};         expect_delta("'G','O' (FROM)      → fail", h, asn_DEF_HasHex, 1); }

    // YesNo IA5String (FROM "NY") (SIZE 1..3)
    std::printf("YesNo IA5String (FROM N|Y, SIZE 1..3)\n");
    { HasYesNo h{}; h.v = Ia5String{"Y"};              expect_delta("\"Y\" valid          → pass", h, asn_DEF_HasYesNo, 0); }
    { HasYesNo h{}; h.v = Ia5String{"NYN"};            expect_delta("size 3 (boundary)   → pass", h, asn_DEF_HasYesNo, 0); }
    { HasYesNo h{}; h.v = Ia5String{""};               expect_delta("empty (under)       → fail", h, asn_DEF_HasYesNo, 1); }
    { HasYesNo h{}; h.v = Ia5String{"NYNY"};           expect_delta("size 4 (over)       → fail", h, asn_DEF_HasYesNo, 1); }
    { HasYesNo h{}; h.v = Ia5String{"y"};              expect_delta("lowercase 'y' (FROM)→ fail", h, asn_DEF_HasYesNo, 1); }
    { HasYesNo h{}; h.v = Ia5String{"YX"};             expect_delta("'X' (FROM)          → fail", h, asn_DEF_HasYesNo, 1); }

    // Vowels PrintableString (FROM "aeiou") (SIZE 1..5)
    std::printf("Vowels PrintableString (FROM aeiou, SIZE 1..5)\n");
    { HasVowels h{}; h.v = PrintableString{"aeiou"};   expect_delta("\"aeiou\" valid      → pass", h, asn_DEF_HasVowels, 0); }
    { HasVowels h{}; h.v = PrintableString{"a"};       expect_delta("size 1 (boundary)   → pass", h, asn_DEF_HasVowels, 0); }
    { HasVowels h{}; h.v = PrintableString{""};        expect_delta("empty (under)       → fail", h, asn_DEF_HasVowels, 1); }
    { HasVowels h{}; h.v = PrintableString{"aeioua"};  expect_delta("size 6 (over)       → fail", h, asn_DEF_HasVowels, 1); }
    { HasVowels h{}; h.v = PrintableString{"hello"};   expect_delta("'h','l' (FROM)      → fail", h, asn_DEF_HasVowels, 1); }
    { HasVowels h{}; h.v = PrintableString{"AEIOU"};   expect_delta("uppercase (FROM)    → fail", h, asn_DEF_HasVowels, 1); }

    // --- ENUMERATED ---------------------------------------------------------
    std::printf("\nColor ENUMERATED\n");
    { HasColor h{}; h.v = Color::red;                expect_delta("red (in map)  → pass", h, asn_DEF_HasColor, 0); }
    { HasColor h{}; h.v = Color::blue;               expect_delta("blue (in map) → pass", h, asn_DEF_HasColor, 0); }
    { HasColor h{}; h.v = static_cast<Color>(3);     expect_delta("3 (just outside)→ fail", h, asn_DEF_HasColor, 1); }
    { HasColor h{}; h.v = static_cast<Color>(99);    expect_delta("99 (far outside)→ fail", h, asn_DEF_HasColor, 1); }

    // --- SEQUENCE OF SIZE --------------------------------------------------
    // ShortList (SIZE 1..3)
    std::printf("\nShortList SEQUENCE OF (SIZE 1..3)\n");
    { HasShortList h{}; h.v = {};            expect_delta("size 0 (under)    → fail", h, asn_DEF_HasShortList, 1); }
    { HasShortList h{}; h.v = {10};          expect_delta("size 1 (boundary) → pass", h, asn_DEF_HasShortList, 0); }
    { HasShortList h{}; h.v = {10,20,30};    expect_delta("size 3 (boundary) → pass", h, asn_DEF_HasShortList, 0); }
    { HasShortList h{}; h.v = {10,20,30,40}; expect_delta("size 4 (over)     → fail", h, asn_DEF_HasShortList, 1); }

    // MidList (SIZE 2..8)
    std::printf("MidList SEQUENCE OF (SIZE 2..8)\n");
    { HasMidList h{}; h.v = {1};                 expect_delta("size 1 (under)    → fail", h, asn_DEF_HasMidList, 1); }
    { HasMidList h{}; h.v = {1,2};               expect_delta("size 2 (boundary) → pass", h, asn_DEF_HasMidList, 0); }
    { HasMidList h{}; h.v = {1,2,3,4,5,6,7,8};   expect_delta("size 8 (boundary) → pass", h, asn_DEF_HasMidList, 0); }
    { HasMidList h{}; h.v = {1,2,3,4,5,6,7,8,9}; expect_delta("size 9 (over)     → fail", h, asn_DEF_HasMidList, 1); }

    std::printf("\n=== %d failure(s) ===\n", failures);
    return failures ? 1 : 0;
}
