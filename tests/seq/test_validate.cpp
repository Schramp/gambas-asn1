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
// per-type alphabet table (`Constraints::alphabet`, populated by codegen
// via `extract_from_alphabet`) when set, otherwise fall back to the type's
// built-in alphabet. Constraint validation is independent of encoding rules —
// alphabet checks apply equally to BER / XER / PER paths.

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
#include "HasByteCount.hpp"
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
    { HasPct h{}; h.v = -1;  expect_delta("just below 0  → fail",  h, HasPct::asn_DEF, 1); }
    { HasPct h{}; h.v = 0;   expect_delta("exactly 0     → pass",  h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 100; expect_delta("exactly 100   → pass",  h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 101; expect_delta("just above 100→ fail",  h, HasPct::asn_DEF, 1); }

    // Tariff (1000..2000)
    std::printf("Tariff (1000..2000)\n");
    { HasTariff h{}; h.v = 999;  expect_delta("just below 1000  → fail", h, HasTariff::asn_DEF, 1); }
    { HasTariff h{}; h.v = 1000; expect_delta("exactly 1000     → pass", h, HasTariff::asn_DEF, 0); }
    { HasTariff h{}; h.v = 2000; expect_delta("exactly 2000     → pass", h, HasTariff::asn_DEF, 0); }
    { HasTariff h{}; h.v = 2001; expect_delta("just above 2000  → fail", h, HasTariff::asn_DEF, 1); }

    // PositiveInt (10..MAX) — semi-constrained, no upper bound
    std::printf("PositiveInt (10..MAX)\n");
    { HasPos h{}; h.v = 9;        expect_delta("just below 10    → fail", h, HasPos::asn_DEF, 1); }
    { HasPos h{}; h.v = 10;       expect_delta("exactly 10       → pass", h, HasPos::asn_DEF, 0); }
    { HasPos h{}; h.v = 1000000;  expect_delta("large value      → pass", h, HasPos::asn_DEF, 0); }
    // PositiveInt is uint64_t; value 0 is below lower bound 10 → fail
    { HasPos h{}; h.v = 0;        expect_delta("zero (below lb)  → fail", h, HasPos::asn_DEF, 1); }

    // SignedSmall (-50..50)
    std::printf("SignedSmall (-50..50)\n");
    { HasSigned h{}; h.v = -51; expect_delta("just below -50   → fail", h, HasSigned::asn_DEF, 1); }
    { HasSigned h{}; h.v = -50; expect_delta("exactly -50      → pass", h, HasSigned::asn_DEF, 0); }
    { HasSigned h{}; h.v = 50;  expect_delta("exactly 50       → pass", h, HasSigned::asn_DEF, 0); }
    { HasSigned h{}; h.v = 51;  expect_delta("just above 50    → fail", h, HasSigned::asn_DEF, 1); }

    // NegRange (-1000..-1)
    std::printf("NegRange (-1000..-1)\n");
    { HasNeg h{}; h.v = -1001; expect_delta("just below -1000 → fail", h, HasNeg::asn_DEF, 1); }
    { HasNeg h{}; h.v = -1000; expect_delta("exactly -1000    → pass", h, HasNeg::asn_DEF, 0); }
    { HasNeg h{}; h.v = -1;    expect_delta("exactly -1       → pass", h, HasNeg::asn_DEF, 0); }
    { HasNeg h{}; h.v = 0;     expect_delta("just above -1 (0)→ fail", h, HasNeg::asn_DEF, 1); }

    // WideUnsigned (5..1000000)
    std::printf("WideUnsigned (5..1000000)\n");
    { HasWide h{}; h.v = 4;       expect_delta("just below 5     → fail", h, HasWide::asn_DEF, 1); }
    { HasWide h{}; h.v = 5;       expect_delta("exactly 5        → pass", h, HasWide::asn_DEF, 0); }
    { HasWide h{}; h.v = 1000000; expect_delta("exactly 1000000  → pass", h, HasWide::asn_DEF, 0); }
    { HasWide h{}; h.v = 1000001; expect_delta("just above 1000000→ fail", h, HasWide::asn_DEF, 1); }

    // --- OCTET STRING SIZE -----------------------------------------------------
    // TinyBlob (SIZE 2..4)
    std::printf("\nTinyBlob OCTET STRING (SIZE 2..4)\n");
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(1,0)); expect_delta("size 1 (under)   → fail", h, HasTiny::asn_DEF, 1); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(2,0)); expect_delta("size 2 (boundary)→ pass", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(4,0)); expect_delta("size 4 (boundary)→ pass", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(5,0)); expect_delta("size 5 (over)    → fail", h, HasTiny::asn_DEF, 1); }

    // MidBlob (SIZE 5..12)
    std::printf("MidBlob OCTET STRING (SIZE 5..12)\n");
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(4,0));  expect_delta("size 4 (under)    → fail", h, HasMid::asn_DEF, 1); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(5,0));  expect_delta("size 5 (boundary) → pass", h, HasMid::asn_DEF, 0); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(12,0)); expect_delta("size 12 (boundary)→ pass", h, HasMid::asn_DEF, 0); }
    { HasMid h{}; h.v = OctetString(std::vector<uint8_t>(13,0)); expect_delta("size 13 (over)    → fail", h, HasMid::asn_DEF, 1); }

    // FixedBlob (SIZE 8) — single boundary; 3 cases
    std::printf("FixedBlob OCTET STRING (SIZE 8)\n");
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(7,0)); expect_delta("size 7 (under)→ fail", h, HasFixed::asn_DEF, 1); }
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(8,0)); expect_delta("size 8 (exact)→ pass", h, HasFixed::asn_DEF, 0); }
    { HasFixed h{}; h.v = OctetString(std::vector<uint8_t>(9,0)); expect_delta("size 9 (over) → fail", h, HasFixed::asn_DEF, 1); }

    // --- BIT STRING SIZE ------------------------------------------------------
    // FlagsByte (SIZE 8) — 3 cases
    std::printf("\nFlagsByte BIT STRING (SIZE 8)\n");
    { HasFlagsByte h{}; h.v = BitString{{0xff}, 1};                  expect_delta("7 bits (under)→ fail", h, HasFlagsByte::asn_DEF, 1); }
    { HasFlagsByte h{}; h.v = BitString{{0xff}, 0};                  expect_delta("8 bits (exact)→ pass", h, HasFlagsByte::asn_DEF, 0); }
    { HasFlagsByte h{}; h.v = BitString{{0xff,0xff}, 0};             expect_delta("16 bits (over)→ fail", h, HasFlagsByte::asn_DEF, 1); }

    // FlagsRange (SIZE 16..24)
    std::printf("FlagsRange BIT STRING (SIZE 16..24)\n");
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff}, 1};             expect_delta("15 bits (under)   → fail", h, HasFlagsRange::asn_DEF, 1); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff}, 0};             expect_delta("16 bits (boundary)→ pass", h, HasFlagsRange::asn_DEF, 0); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff,0xff}, 0};        expect_delta("24 bits (boundary)→ pass", h, HasFlagsRange::asn_DEF, 0); }
    { HasFlagsRange h{}; h.v = BitString{{0xff,0xff,0xff,0xff}, 0};   expect_delta("32 bits (over)    → fail", h, HasFlagsRange::asn_DEF, 1); }

    // --- String SIZE + alphabet ----------------------------------------------
    // Code (NumericString SIZE 3..6)
    std::printf("\nCode NumericString (SIZE 3..6)\n");
    { HasCode h{}; h.v = NumericString{"12"};      expect_delta("size 2 (under)    → fail", h, HasCode::asn_DEF, 1); }
    { HasCode h{}; h.v = NumericString{"123"};     expect_delta("size 3 (boundary) → pass", h, HasCode::asn_DEF, 0); }
    { HasCode h{}; h.v = NumericString{"123456"};  expect_delta("size 6 (boundary) → pass", h, HasCode::asn_DEF, 0); }
    { HasCode h{}; h.v = NumericString{"1234567"}; expect_delta("size 7 (over)     → fail", h, HasCode::asn_DEF, 1); }
    { HasCode h{}; h.v = NumericString{"12X"};     expect_delta("alphabet ('X')    → fail", h, HasCode::asn_DEF, 1); }

    // Name (PrintableString SIZE 2..20)
    std::printf("Name PrintableString (SIZE 2..20)\n");
    { HasName h{}; h.v = PrintableString{"x"};                       expect_delta("size 1 (under)    → fail", h, HasName::asn_DEF, 1); }
    { HasName h{}; h.v = PrintableString{"hi"};                      expect_delta("size 2 (boundary) → pass", h, HasName::asn_DEF, 0); }
    { HasName h{}; h.v = PrintableString{std::string(20, 'a')};      expect_delta("size 20 (boundary)→ pass", h, HasName::asn_DEF, 0); }
    { HasName h{}; h.v = PrintableString{std::string(21, 'a')};      expect_delta("size 21 (over)    → fail", h, HasName::asn_DEF, 1); }
    { HasName h{}; h.v = PrintableString{"hi#bad"};                  expect_delta("alphabet ('#')    → fail", h, HasName::asn_DEF, 1); }

    // Token (IA5String SIZE 4..10)
    std::printf("Token IA5String (SIZE 4..10)\n");
    { HasToken h{}; h.v = Ia5String{"abc"};                          expect_delta("size 3 (under)    → fail", h, HasToken::asn_DEF, 1); }
    { HasToken h{}; h.v = Ia5String{"abcd"};                         expect_delta("size 4 (boundary) → pass", h, HasToken::asn_DEF, 0); }
    { HasToken h{}; h.v = Ia5String{std::string(10, 'a')};           expect_delta("size 10 (boundary)→ pass", h, HasToken::asn_DEF, 0); }
    { HasToken h{}; h.v = Ia5String{std::string(11, 'a')};           expect_delta("size 11 (over)    → fail", h, HasToken::asn_DEF, 1); }
    { HasToken h{}; std::string s = "ab\x80""x"; h.v = Ia5String{s}; expect_delta("alphabet (0x80)   → fail", h, HasToken::asn_DEF, 1); }

    // Visi (VisibleString SIZE 6..12)
    std::printf("Visi VisibleString (SIZE 6..12)\n");
    { HasVisi h{}; h.v = VisibleString{"hello"};                      expect_delta("size 5 (under)    → fail", h, HasVisi::asn_DEF, 1); }
    { HasVisi h{}; h.v = VisibleString{"hellos"};                     expect_delta("size 6 (boundary) → pass", h, HasVisi::asn_DEF, 0); }
    { HasVisi h{}; h.v = VisibleString{std::string(12, 'a')};         expect_delta("size 12 (boundary)→ pass", h, HasVisi::asn_DEF, 0); }
    { HasVisi h{}; h.v = VisibleString{std::string(13, 'a')};         expect_delta("size 13 (over)    → fail", h, HasVisi::asn_DEF, 1); }
    { HasVisi h{}; std::string s = "hellosx\x01"; h.v = VisibleString{s}; expect_delta("alphabet (0x01)   → fail", h, HasVisi::asn_DEF, 1); }

    // --- FROM custom alphabets ----------------------------------------------
    // HexDigit IA5String (FROM "0-9A-F") (SIZE 1..8)
    std::printf("\nHexDigit IA5String (FROM 0-9A-F, SIZE 1..8)\n");
    { HasHex h{}; h.v = Ia5String{"DEADBEEF"};         expect_delta("\"DEADBEEF\" valid    → pass", h, HasHex::asn_DEF, 0); }
    { HasHex h{}; h.v = Ia5String{"0"};                expect_delta("size 1 (boundary)   → pass", h, HasHex::asn_DEF, 0); }
    { HasHex h{}; h.v = Ia5String{""};                 expect_delta("empty (under)       → fail", h, HasHex::asn_DEF, 1); }
    { HasHex h{}; h.v = Ia5String{"0123456789"};       expect_delta("size 10 (over)      → fail", h, HasHex::asn_DEF, 1); }
    { HasHex h{}; h.v = Ia5String{"DEADbeef"};         expect_delta("lowercase (FROM)    → fail", h, HasHex::asn_DEF, 1); }
    { HasHex h{}; h.v = Ia5String{"DEADGOOD"};         expect_delta("'G','O' (FROM)      → fail", h, HasHex::asn_DEF, 1); }

    // YesNo IA5String (FROM "NY") (SIZE 1..3)
    std::printf("YesNo IA5String (FROM N|Y, SIZE 1..3)\n");
    { HasYesNo h{}; h.v = Ia5String{"Y"};              expect_delta("\"Y\" valid          → pass", h, HasYesNo::asn_DEF, 0); }
    { HasYesNo h{}; h.v = Ia5String{"NYN"};            expect_delta("size 3 (boundary)   → pass", h, HasYesNo::asn_DEF, 0); }
    { HasYesNo h{}; h.v = Ia5String{""};               expect_delta("empty (under)       → fail", h, HasYesNo::asn_DEF, 1); }
    { HasYesNo h{}; h.v = Ia5String{"NYNY"};           expect_delta("size 4 (over)       → fail", h, HasYesNo::asn_DEF, 1); }
    { HasYesNo h{}; h.v = Ia5String{"y"};              expect_delta("lowercase 'y' (FROM)→ fail", h, HasYesNo::asn_DEF, 1); }
    { HasYesNo h{}; h.v = Ia5String{"YX"};             expect_delta("'X' (FROM)          → fail", h, HasYesNo::asn_DEF, 1); }

    // Vowels PrintableString (FROM "aeiou") (SIZE 1..5)
    std::printf("Vowels PrintableString (FROM aeiou, SIZE 1..5)\n");
    { HasVowels h{}; h.v = PrintableString{"aeiou"};   expect_delta("\"aeiou\" valid      → pass", h, HasVowels::asn_DEF, 0); }
    { HasVowels h{}; h.v = PrintableString{"a"};       expect_delta("size 1 (boundary)   → pass", h, HasVowels::asn_DEF, 0); }
    { HasVowels h{}; h.v = PrintableString{""};        expect_delta("empty (under)       → fail", h, HasVowels::asn_DEF, 1); }
    { HasVowels h{}; h.v = PrintableString{"aeioua"};  expect_delta("size 6 (over)       → fail", h, HasVowels::asn_DEF, 1); }
    { HasVowels h{}; h.v = PrintableString{"hello"};   expect_delta("'h','l' (FROM)      → fail", h, HasVowels::asn_DEF, 1); }
    { HasVowels h{}; h.v = PrintableString{"AEIOU"};   expect_delta("uppercase (FROM)    → fail", h, HasVowels::asn_DEF, 1); }

    // --- ENUMERATED ---------------------------------------------------------
    std::printf("\nColor ENUMERATED\n");
    { HasColor h{}; h.v = Color::red;                expect_delta("red (in map)  → pass", h, HasColor::asn_DEF, 0); }
    { HasColor h{}; h.v = Color::blue;               expect_delta("blue (in map) → pass", h, HasColor::asn_DEF, 0); }
    { HasColor h{}; h.v = Color(static_cast<Color::Enm>(3));  expect_delta("3 (just outside)→ fail", h, HasColor::asn_DEF, 1); }
    { HasColor h{}; h.v = Color(static_cast<Color::Enm>(99)); expect_delta("99 (far outside)→ fail", h, HasColor::asn_DEF, 1); }

    // --- SEQUENCE OF SIZE --------------------------------------------------
    // ShortList (SIZE 1..3)
    std::printf("\nShortList SEQUENCE OF (SIZE 1..3)\n");
    { HasShortList h{}; h.v = {};            expect_delta("size 0 (under)    → fail", h, HasShortList::asn_DEF, 1); }
    { HasShortList h{}; h.v = {10};          expect_delta("size 1 (boundary) → pass", h, HasShortList::asn_DEF, 0); }
    { HasShortList h{}; h.v = {10,20,30};    expect_delta("size 3 (boundary) → pass", h, HasShortList::asn_DEF, 0); }
    { HasShortList h{}; h.v = {10,20,30,40}; expect_delta("size 4 (over)     → fail", h, HasShortList::asn_DEF, 1); }

    // MidList (SIZE 2..8)
    std::printf("MidList SEQUENCE OF (SIZE 2..8)\n");
    { HasMidList h{}; h.v = {1};                 expect_delta("size 1 (under)    → fail", h, HasMidList::asn_DEF, 1); }
    { HasMidList h{}; h.v = {1,2};               expect_delta("size 2 (boundary) → pass", h, HasMidList::asn_DEF, 0); }
    { HasMidList h{}; h.v = {1,2,3,4,5,6,7,8};   expect_delta("size 8 (boundary) → pass", h, HasMidList::asn_DEF, 0); }
    { HasMidList h{}; h.v = {1,2,3,4,5,6,7,8,9}; expect_delta("size 9 (over)     → fail", h, HasMidList::asn_DEF, 1); }

    // ByteCount (0..MAX) — uint64_t (UInteger), semi-constrained, lower=0
    std::printf("ByteCount (0..MAX) — uint64_t\n");
    { HasByteCount h{}; h.v = 0;          expect_delta("exactly 0        → pass", h, HasByteCount::asn_DEF, 0); }
    { HasByteCount h{}; h.v = 1000000;    expect_delta("large value      → pass", h, HasByteCount::asn_DEF, 0); }
    // BER round-trip of value > INT64_MAX (9-byte encoding with 0x00 pad)
    {
        constexpr uint64_t BIG = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
        HasByteCount enc{};
        enc.v = BIG;
        std::vector<uint8_t> buf;
        { BerWriter w{buf}; BerEncodeStream es{w};
          BerCodec::instance().encode(es, HasByteCount::asn_DEF, &enc); }
        HasByteCount dec{};
        { BerReader rd{std::span<const uint8_t>{buf.data(), buf.size()}};
          BerDecodeStream ds{rd};
          BerCodec::instance().decode(ds, HasByteCount::asn_DEF, &dec); }
        if (dec.v == BIG)
            std::printf("  \033[32mPASS\033[0m  ByteCount BER round-trip > INT64_MAX (9-byte)\n");
        else { std::printf("  \033[31mFAIL\033[0m  ByteCount BER round-trip: got %llu expected %llu\n",
                           (unsigned long long)dec.v.value(), (unsigned long long)BIG); ++failures; }
    }

    // --- Decode-side validation (encode + decode round-trip) ----------------
    // With ASN1CPP_VALIDATE_ON_DECODE enabled the decoder also runs validate()
    // on the populated object. Roundtripping invalid data therefore fires the
    // counter twice (once on encode, once on decode); valid data: zero.
#if defined(ASN1CPP_VALIDATE_ON_DECODE)
    std::printf("\n=== Decode-side validation ===\n");
    auto roundtrip_delta = [](const auto& v, const TypeDescriptor& def) -> unsigned long long {
        reset_validate_fail_count();
        std::vector<uint8_t> buf;
        { BerWriter w{buf}; BerEncodeStream es{w};
          BerCodec::instance().encode(es, def, &v); }
        std::remove_cvref_t<decltype(v)> out{};
        { BerReader rd{std::span<const uint8_t>{buf.data(), buf.size()}};
          BerDecodeStream ds{rd};
          (void)BerCodec::instance().decode(ds, def, &out); }
        return validate_fail_count();
    };
    auto expect_rt = [&](const char* label, const auto& v, const TypeDescriptor& def,
                         unsigned long long expect) {
        auto got = roundtrip_delta(v, def);
        if (got != expect) {
            std::printf("  \033[31mFAIL\033[0m  %s — expected %llu fails, got %llu\n",
                        label, expect, got);
            ++failures;
        } else {
            std::printf("  \033[32mPASS\033[0m  %s (%llu fail%s)\n",
                        label, got, got == 1 ? "" : "s");
        }
    };
    { HasPct h{}; h.v = 50;   expect_rt("PercentInt valid roundtrip   → 0",  h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 200;  expect_rt("PercentInt invalid roundtrip→ 2",  h, HasPct::asn_DEF, 2); }
    { HasTariff h{}; h.v = 1500; expect_rt("Tariff valid roundtrip      → 0", h, HasTariff::asn_DEF, 0); }
    { HasTariff h{}; h.v = 500;  expect_rt("Tariff invalid roundtrip    → 2", h, HasTariff::asn_DEF, 2); }
    { HasTiny h{}; h.v = OctetString{std::vector<uint8_t>{1,2,3}}; expect_rt("TinyBlob valid (size 3) → 0", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString{std::vector<uint8_t>{1}};     expect_rt("TinyBlob invalid (size 1)→ 2", h, HasTiny::asn_DEF, 2); }
#endif

    // --- ValidationPolicy + encode/decode_validated wrappers ----------------
    // Lenient (default) = current Postel behaviour; Strict = surface validate
    // failures as hard DecodeError on the decode path. encode_validated returns
    // bool indicating whether any failures fired during encode.
    std::printf("\n=== ValidationPolicy wrappers ===\n");
    {
        // Encode wrapper, valid value → returns true.
        HasPct h{}; h.v = 50;
        std::vector<uint8_t> buf; BerWriter w{buf}; BerEncodeStream es{w};
        reset_validate_fail_count();
        bool ok = encode_validated(BerCodec::instance(), es, HasPct::asn_DEF, &h);
        if (ok) std::printf("  \033[32mPASS\033[0m  encode_validated valid → true\n");
        else { std::printf("  \033[31mFAIL\033[0m  encode_validated valid → false\n"); ++failures; }
    }
    {
        // Encode wrapper, invalid value → returns false.
        HasPct h{}; h.v = 200;
        std::vector<uint8_t> buf; BerWriter w{buf}; BerEncodeStream es{w};
        reset_validate_fail_count();
        bool ok = encode_validated(BerCodec::instance(), es, HasPct::asn_DEF, &h);
        if (!ok) std::printf("  \033[32mPASS\033[0m  encode_validated invalid → false\n");
        else { std::printf("  \033[31mFAIL\033[0m  encode_validated invalid → true\n"); ++failures; }
    }
#if defined(ASN1CPP_VALIDATE_ON_DECODE)
    {
        // Strict decode of invalid bytes returns DecodeError.
        HasPct h{}; h.v = 200;
        std::vector<uint8_t> buf; { BerWriter w{buf}; BerEncodeStream es{w};
            BerCodec::instance().encode(es, HasPct::asn_DEF, &h); }
        HasPct out{};
        BerReader rd{std::span<const uint8_t>{buf.data(), buf.size()}};
        BerDecodeStream ds{rd};
        reset_validate_fail_count();
        auto res = decode_validated(BerCodec::instance(), ds, HasPct::asn_DEF, &out,
                                    ValidationPolicy::Strict);
        if (!res) std::printf("  \033[32mPASS\033[0m  Strict decode invalid → DecodeError\n");
        else { std::printf("  \033[31mFAIL\033[0m  Strict decode invalid → ok\n"); ++failures; }
    }
    {
        // Lenient decode of invalid bytes succeeds (counter still bumps).
        HasPct h{}; h.v = 200;
        std::vector<uint8_t> buf; { BerWriter w{buf}; BerEncodeStream es{w};
            BerCodec::instance().encode(es, HasPct::asn_DEF, &h); }
        HasPct out{};
        BerReader rd{std::span<const uint8_t>{buf.data(), buf.size()}};
        BerDecodeStream ds{rd};
        reset_validate_fail_count();
        auto res = decode_validated(BerCodec::instance(), ds, HasPct::asn_DEF, &out,
                                    ValidationPolicy::Lenient);
        if (res) std::printf("  \033[32mPASS\033[0m  Lenient decode invalid → ok (counter bumped)\n");
        else { std::printf("  \033[31mFAIL\033[0m  Lenient decode invalid → DecodeError\n"); ++failures; }
    }
#endif

#if defined(ASN1CPP_VALIDATE_REPORT)
    // --- ValidationReport: path tracking on encode --------------------------
    std::printf("\n=== ValidationReport (paths) ===\n");
    {
        // HasPct.v out of range — report should record path "v" (the SEQUENCE
        // member name pushed by encode_sequence) for type "INTEGER".
        HasPct h{}; h.v = 200;
        ValidationReport rpt;
        ValidationReportScope _scope{rpt};
        std::vector<uint8_t> buf; BerWriter w{buf}; BerEncodeStream es{w};
        BerCodec::instance().encode(es, HasPct::asn_DEF, &h);
        if (rpt.failures.size() == 1
            && rpt.failures[0].path == "v"
            && std::string(rpt.failures[0].type_name) == "PercentInt"
            && !rpt.failures[0].on_decode) {
            std::printf("  \033[32mPASS\033[0m  encode HasPct.v=200 → path='v' type='PercentInt'\n");
        } else {
            std::printf("  \033[31mFAIL\033[0m  encode HasPct.v=200 — got %zu failure(s)",
                        rpt.failures.size());
            if (!rpt.failures.empty())
                std::printf(", first path='%s' type='%s' on_decode=%d",
                            rpt.failures[0].path.c_str(),
                            rpt.failures[0].type_name ? rpt.failures[0].type_name : "?",
                            rpt.failures[0].on_decode);
            std::printf("\n");
            ++failures;
        }
    }
    {
        // Roundtrip — encode + decode, expect 2 failures (encode + decode side).
        HasPct h{}; h.v = 200;
        std::vector<uint8_t> buf;
        { BerWriter w{buf}; BerEncodeStream es{w};
          BerCodec::instance().encode(es, HasPct::asn_DEF, &h); }
        ValidationReport rpt;
        ValidationReportScope _scope{rpt};
        // Re-encode + decode under report scope.
        std::vector<uint8_t> buf2; { BerWriter w{buf2}; BerEncodeStream es{w};
            BerCodec::instance().encode(es, HasPct::asn_DEF, &h); }
        HasPct out{};
        BerReader rd{std::span<const uint8_t>{buf2.data(), buf2.size()}};
        BerDecodeStream ds{rd};
        (void)BerCodec::instance().decode(ds, HasPct::asn_DEF, &out);
        if (rpt.failures.size() == 2
            && rpt.failures[0].path == "v" && !rpt.failures[0].on_decode
            && rpt.failures[1].path == "v" &&  rpt.failures[1].on_decode) {
            std::printf("  \033[32mPASS\033[0m  roundtrip HasPct.v=200 → 2 entries (encode + decode)\n");
        } else {
            std::printf("  \033[31mFAIL\033[0m  roundtrip — got %zu entries\n", rpt.failures.size());
            ++failures;
        }
    }
#endif

#if defined(ASN1CPP_VALIDATE_ON_SET) && defined(ASN1CPP_VALIDATE)
    // --- set_<member> helpers (VALIDATE_ON_SET) ---------------------------------
    std::printf("\n=== set_<member> helpers (VALIDATE_ON_SET) ===\n");
    {
        // set_v on int64_t alias (PercentInt): valid value → no bump
        HasPct h{};
        reset_validate_fail_count();
        h.set_v(50);
        if (validate_fail_count() == 0)
            std::printf("  \033[32mPASS\033[0m  HasPct::set_v(50) valid → no fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasPct::set_v(50) valid → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
    {
        // set_v on int64_t alias: out-of-range → counter bumps once
        HasPct h{};
        reset_validate_fail_count();
        h.set_v(200);
        if (validate_fail_count() == 1)
            std::printf("  \033[32mPASS\033[0m  HasPct::set_v(200) invalid → 1 fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasPct::set_v(200) invalid → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
    {
        // set_v on PrintableString typedef (Name): valid size → no bump
        HasName h{};
        reset_validate_fail_count();
        h.set_v(Name{"hello"});   // 5 chars, within SIZE(2..20)
        if (validate_fail_count() == 0)
            std::printf("  \033[32mPASS\033[0m  HasName::set_v(\"hello\") valid → no fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasName::set_v(\"hello\") → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
    {
        // set_v on PrintableString typedef: too long → counter bumps
        HasName h{};
        reset_validate_fail_count();
        h.set_v(Name{std::string(25, 'x')});  // 25 chars, exceeds SIZE(2..20)
        if (validate_fail_count() == 1)
            std::printf("  \033[32mPASS\033[0m  HasName::set_v(25-char) invalid → 1 fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasName::set_v(25-char) → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
    {
        // set_v on OctetString typedef (TinyBlob SIZE 2..4): valid → no bump
        HasTiny h{};
        reset_validate_fail_count();
        h.set_v(TinyBlob{std::vector<uint8_t>(3, 0)});
        if (validate_fail_count() == 0)
            std::printf("  \033[32mPASS\033[0m  HasTiny::set_v(3 bytes) valid → no fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasTiny::set_v(3 bytes) → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
    {
        // set_v on OctetString typedef: too short → counter bumps
        HasTiny h{};
        reset_validate_fail_count();
        h.set_v(TinyBlob{std::vector<uint8_t>(1, 0)});
        if (validate_fail_count() == 1)
            std::printf("  \033[32mPASS\033[0m  HasTiny::set_v(1 byte) invalid → 1 fail\n");
        else { std::printf("  \033[31mFAIL\033[0m  HasTiny::set_v(1 byte) → %llu fail(s)\n",
                           validate_fail_count()); ++failures; }
    }
#endif

    std::printf("\n=== %d failure(s) ===\n", failures);
    return failures ? 1 : 0;
}
