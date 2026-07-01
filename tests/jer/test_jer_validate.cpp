// JER validation hook coverage test (#165).
//
// Verifies that JerCodec::encode() and JerCodec::decode() call validate()
// under ASN1CPP_VALIDATE guards, matching BerCodec behaviour.
//
// Schema: tests/asn1/validate_test.asn1 (same types used by test_validate.cpp).
// Built only when ASN1CPP_VALIDATE + ASN1CPP_VALIDATE_ON_ENCODE are enabled.

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/JerCodec.hpp>
#include <asn1cpp/codec/Validation.hpp>

#include "HasPct.hpp"
#include "HasTariff.hpp"
#include "HasTiny.hpp"
#include "HasCode.hpp"
#include "HasColor.hpp"
#include "HasShortList.hpp"

using namespace asn1;
static int failures = 0;

static void jer_encode(const TypeDescriptor& def, const Asn1Object* obj) {
    std::ostringstream oss;
    JerEncodeStream s{oss};
    JerCodec::instance().encode(s, def, obj);
}

template<typename T>
static void expect_delta(const char* label, const T& v, const TypeDescriptor& def,
                         unsigned long long expected_delta) {
    reset_validate_fail_count();
    jer_encode(def, &v);
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
    std::printf("\n=== JER Validation hook coverage ===\n\n");

    // --- INTEGER value-range (PercentInt 0..100) ----------------------------
    std::printf("PercentInt (0..100)\n");
    { HasPct h{}; h.v = -1;  expect_delta("just below 0   → fail", h, HasPct::asn_DEF, 1); }
    { HasPct h{}; h.v = 0;   expect_delta("exactly 0      → pass", h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 100; expect_delta("exactly 100    → pass", h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 101; expect_delta("just above 100 → fail", h, HasPct::asn_DEF, 1); }

    // --- INTEGER value-range (Tariff 1000..2000) ----------------------------
    std::printf("Tariff (1000..2000)\n");
    { HasTariff h{}; h.v = 999;  expect_delta("just below 1000  → fail", h, HasTariff::asn_DEF, 1); }
    { HasTariff h{}; h.v = 1000; expect_delta("exactly 1000     → pass", h, HasTariff::asn_DEF, 0); }
    { HasTariff h{}; h.v = 2000; expect_delta("exactly 2000     → pass", h, HasTariff::asn_DEF, 0); }
    { HasTariff h{}; h.v = 2001; expect_delta("just above 2000  → fail", h, HasTariff::asn_DEF, 1); }

    // --- OCTET STRING SIZE (TinyBlob SIZE 2..4) ----------------------------
    std::printf("\nTinyBlob OCTET STRING (SIZE 2..4)\n");
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(1,0)); expect_delta("size 1 (under)    → fail", h, HasTiny::asn_DEF, 1); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(2,0)); expect_delta("size 2 (boundary) → pass", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(4,0)); expect_delta("size 4 (boundary) → pass", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString(std::vector<uint8_t>(5,0)); expect_delta("size 5 (over)     → fail", h, HasTiny::asn_DEF, 1); }

    // --- String SIZE + alphabet (Code NumericString SIZE 3..6) -------------
    std::printf("\nCode NumericString (SIZE 3..6)\n");
    { HasCode h{}; h.v = NumericString{"12"};      expect_delta("size 2 (under)    → fail", h, HasCode::asn_DEF, 1); }
    { HasCode h{}; h.v = NumericString{"123"};     expect_delta("size 3 (boundary) → pass", h, HasCode::asn_DEF, 0); }
    { HasCode h{}; h.v = NumericString{"123456"};  expect_delta("size 6 (boundary) → pass", h, HasCode::asn_DEF, 0); }
    { HasCode h{}; h.v = NumericString{"1234567"}; expect_delta("size 7 (over)     → fail", h, HasCode::asn_DEF, 1); }
    { HasCode h{}; h.v = NumericString{"12X"};     expect_delta("alphabet ('X')    → fail", h, HasCode::asn_DEF, 1); }

    // --- ENUMERATED ---------------------------------------------------------
    std::printf("\nColor ENUMERATED\n");
    { HasColor h{}; h.v = Color::red;                              expect_delta("red (valid)     → pass", h, HasColor::asn_DEF, 0); }
    { HasColor h{}; h.v = Color(static_cast<Color::Enm>(99));     expect_delta("99 (invalid)    → fail", h, HasColor::asn_DEF, 1); }

    // --- SEQUENCE OF SIZE (ShortList SIZE 1..3) ----------------------------
    std::printf("\nShortList SEQUENCE OF (SIZE 1..3)\n");
    { HasShortList h{}; h.v = {};            expect_delta("size 0 (under)    → fail", h, HasShortList::asn_DEF, 1); }
    { HasShortList h{}; h.v = {10};          expect_delta("size 1 (boundary) → pass", h, HasShortList::asn_DEF, 0); }
    { HasShortList h{}; h.v = {10,20,30};    expect_delta("size 3 (boundary) → pass", h, HasShortList::asn_DEF, 0); }
    { HasShortList h{}; h.v = {10,20,30,40}; expect_delta("size 4 (over)     → fail", h, HasShortList::asn_DEF, 1); }

    // --- Decode-side validation ---------------------------------------------
#if defined(ASN1CPP_VALIDATE_ON_DECODE)
    std::printf("\n=== JER Decode-side validation ===\n");

    auto jer_roundtrip_delta = [](const auto& v, const TypeDescriptor& def) -> unsigned long long {
        reset_validate_fail_count();
        std::ostringstream oss;
        { JerEncodeStream es{oss}; JerCodec::instance().encode(es, def, &v); }
        std::string json = oss.str();
        std::remove_cvref_t<decltype(v)> out{};
        { JerDecodeStream ds{json}; (void)JerCodec::instance().decode(ds, def, &out); }
        return validate_fail_count();
    };

    auto expect_rt = [&](const char* label, const auto& v, const TypeDescriptor& def,
                         unsigned long long expect) {
        auto got = jer_roundtrip_delta(v, def);
        if (got != expect) {
            std::printf("  \033[31mFAIL\033[0m  %s — expected %llu fails, got %llu\n",
                        label, expect, got);
            ++failures;
        } else {
            std::printf("  \033[32mPASS\033[0m  %s (%llu fail%s)\n",
                        label, got, got == 1 ? "" : "s");
        }
    };

    { HasPct h{}; h.v = 50;  expect_rt("PercentInt valid roundtrip   → 0", h, HasPct::asn_DEF, 0); }
    { HasPct h{}; h.v = 200; expect_rt("PercentInt invalid roundtrip → 2", h, HasPct::asn_DEF, 2); }
    { HasTiny h{}; h.v = OctetString{std::vector<uint8_t>{1,2,3}}; expect_rt("TinyBlob valid (size 3)  → 0", h, HasTiny::asn_DEF, 0); }
    { HasTiny h{}; h.v = OctetString{std::vector<uint8_t>{1}};     expect_rt("TinyBlob invalid (size 1)→ 2", h, HasTiny::asn_DEF, 2); }
#endif

    std::printf("\n=== %d failure(s) ===\n", failures);
    return failures ? 1 : 0;
}
