// BER round-trip tests for SEQUENCE containing each new string type.
// Schema: tests/asn1/strings_test.asn1
#include <cstdio>
#include <vector>
#include <span>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "HasNumericString.hpp"
#include "HasPrintableString.hpp"
#include "HasT61String.hpp"
#include "HasVisibleString.hpp"
#include "HasGeneralString.hpp"
#include "HasGraphicString.hpp"
#include "HasUniversalString.hpp"
#include "HasBmpString.hpp"
#include "HasVideotexString.hpp"
#include "HasObjectDescriptor.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename HasT, typename StringT>
static bool roundtrip(const TypeDescriptor& def, const StringT& val) {
    HasT v{val};
    std::vector<uint8_t> buf;
    {
        BerWriter w{buf}; BerEncodeStream s{w};
        BerCodec::instance().encode(s, def, &v);
    }
    HasT out{};
    {
        BerReader r{std::span<const uint8_t>(buf)}; BerDecodeStream s{r};
        if (!BerCodec::instance().decode(s, def, &out).has_value()) return false;
    }
    return out.value.str() == val.str();
}

template<typename HasT, typename StringT>
static void check_wire(const char* label,
                       const TypeDescriptor& def,
                       const StringT& val,
                       uint8_t expected_tag,
                       std::vector<uint8_t> expected_bytes)
{
    HasT v{val};
    std::vector<uint8_t> buf;
    BerWriter w{buf}; BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    check(label, buf == expected_bytes);
}

int main() {
    // NumericString "123" tag=0x12, len=3
    // SEQUENCE: 30 05 12 03 "123"
    printf("\n── NumericString ────────────────────────────────────────────────\n");
    check_wire<HasNumericString>("HasNumericString{\"123\"} BER = 30 05 12 03 31 32 33",
        asn_DEF_HasNumericString, NumericString{"123"}, 0x12,
        {0x30,0x05,0x12,0x03,'1','2','3'});
    check("NumericString round-trip \"123\"",
        roundtrip<HasNumericString>(asn_DEF_HasNumericString, NumericString{"123"}));
    check("NumericString round-trip empty",
        roundtrip<HasNumericString>(asn_DEF_HasNumericString, NumericString{""}));

    // PrintableString "Hello" tag=0x13
    printf("\n── PrintableString ──────────────────────────────────────────────\n");
    check_wire<HasPrintableString>("HasPrintableString{\"Hi\"} BER = 30 04 13 02 48 69",
        asn_DEF_HasPrintableString, PrintableString{"Hi"}, 0x13,
        {0x30,0x04,0x13,0x02,'H','i'});
    check("PrintableString round-trip \"Hello, World!\"",
        roundtrip<HasPrintableString>(asn_DEF_HasPrintableString, PrintableString{"Hello, World!"}));

    // T61String tag=0x14
    printf("\n── T61String ────────────────────────────────────────────────────\n");
    check("T61String round-trip \"test\"",
        roundtrip<HasT61String>(asn_DEF_HasT61String, T61String{"test"}));

    // VisibleString tag=0x1A
    printf("\n── VisibleString ────────────────────────────────────────────────\n");
    check_wire<HasVisibleString>("HasVisibleString{\"AB\"} BER = 30 04 1A 02 41 42",
        asn_DEF_HasVisibleString, VisibleString{"AB"}, 0x1A,
        {0x30,0x04,0x1A,0x02,'A','B'});
    check("VisibleString round-trip \"ABC\"",
        roundtrip<HasVisibleString>(asn_DEF_HasVisibleString, VisibleString{"ABC"}));

    // GeneralString tag=0x1B
    printf("\n── GeneralString ────────────────────────────────────────────────\n");
    check("GeneralString round-trip \"test\"",
        roundtrip<HasGeneralString>(asn_DEF_HasGeneralString, GeneralString{"test"}));

    // GraphicString tag=0x19
    printf("\n── GraphicString ────────────────────────────────────────────────\n");
    check("GraphicString round-trip \"test\"",
        roundtrip<HasGraphicString>(asn_DEF_HasGraphicString, GraphicString{"test"}));

    // UniversalString tag=0x1C
    printf("\n── UniversalString ──────────────────────────────────────────────\n");
    check("UniversalString round-trip \"test\"",
        roundtrip<HasUniversalString>(asn_DEF_HasUniversalString, UniversalString{"test"}));

    // BmpString tag=0x1E
    printf("\n── BmpString ────────────────────────────────────────────────────\n");
    check("BmpString round-trip \"test\"",
        roundtrip<HasBmpString>(asn_DEF_HasBmpString, BmpString{"test"}));

    // VideotexString tag=0x15
    printf("\n── VideotexString ───────────────────────────────────────────────\n");
    check("VideotexString round-trip \"test\"",
        roundtrip<HasVideotexString>(asn_DEF_HasVideotexString, VideotexString{"test"}));

    // ObjectDescriptor tag=0x07
    printf("\n── ObjectDescriptor ─────────────────────────────────────────────\n");
    check("ObjectDescriptor round-trip \"test\"",
        roundtrip<HasObjectDescriptor>(asn_DEF_HasObjectDescriptor, ObjectDescriptor{"test"}));

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
