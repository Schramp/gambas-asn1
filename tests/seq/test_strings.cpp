// BER + XER + PER round-trip tests for SEQUENCE containing each string type.
// Schema: tests/asn1/strings_test.asn1
#include <cstdio>
#include <sstream>
#include <vector>
#include <span>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include <asn1cpp/codec/PerCodec.hpp>
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
#include "HasHexStr.hpp"
#include "HasYesNoStr.hpp"
#include "HasVowelStr.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

template<typename HasT, typename StringT>
static bool roundtrip(const TypeDescriptor& def, const StringT& val) {
    HasT v; v.value = val;
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
static bool xer_roundtrip(const TypeDescriptor& def, const StringT& val) {
    HasT v; v.value = val;
    std::ostringstream oss;
    { XerEncodeStream s{oss}; XerCodec::instance().encode(s, def, &v); }
    HasT out{};
    { XerDecodeStream s{oss.str()}; if (!XerCodec::instance().decode(s, def, &out).has_value()) return false; }
    return out.value.str() == val.str();
}

template<typename HasT, typename StringT>
static void check_wire(const char* label,
                       const TypeDescriptor& def,
                       const StringT& val,
                       uint8_t expected_tag,
                       std::vector<uint8_t> expected_bytes)
{
    HasT v; v.value = val;
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
        HasNumericString::asn_DEF, NumericString{"123"}, 0x12,
        {0x30,0x05,0x12,0x03,'1','2','3'});
    check("NumericString round-trip \"123\"",
        roundtrip<HasNumericString>(HasNumericString::asn_DEF, NumericString{"123"}));
    check("NumericString round-trip empty",
        roundtrip<HasNumericString>(HasNumericString::asn_DEF, NumericString{""}));

    // PrintableString "Hello" tag=0x13
    printf("\n── PrintableString ──────────────────────────────────────────────\n");
    check_wire<HasPrintableString>("HasPrintableString{\"Hi\"} BER = 30 04 13 02 48 69",
        HasPrintableString::asn_DEF, PrintableString{"Hi"}, 0x13,
        {0x30,0x04,0x13,0x02,'H','i'});
    check("PrintableString round-trip \"Hello, World!\"",
        roundtrip<HasPrintableString>(HasPrintableString::asn_DEF, PrintableString{"Hello, World!"}));

    // T61String tag=0x14
    printf("\n── T61String ────────────────────────────────────────────────────\n");
    check("T61String round-trip \"test\"",
        roundtrip<HasT61String>(HasT61String::asn_DEF, T61String{"test"}));

    // VisibleString tag=0x1A
    printf("\n── VisibleString ────────────────────────────────────────────────\n");
    check_wire<HasVisibleString>("HasVisibleString{\"AB\"} BER = 30 04 1A 02 41 42",
        HasVisibleString::asn_DEF, VisibleString{"AB"}, 0x1A,
        {0x30,0x04,0x1A,0x02,'A','B'});
    check("VisibleString round-trip \"ABC\"",
        roundtrip<HasVisibleString>(HasVisibleString::asn_DEF, VisibleString{"ABC"}));

    // GeneralString tag=0x1B
    printf("\n── GeneralString ────────────────────────────────────────────────\n");
    check("GeneralString round-trip \"test\"",
        roundtrip<HasGeneralString>(HasGeneralString::asn_DEF, GeneralString{"test"}));

    // GraphicString tag=0x19
    printf("\n── GraphicString ────────────────────────────────────────────────\n");
    check("GraphicString round-trip \"test\"",
        roundtrip<HasGraphicString>(HasGraphicString::asn_DEF, GraphicString{"test"}));

    // UniversalString tag=0x1C
    printf("\n── UniversalString ──────────────────────────────────────────────\n");
    check("UniversalString round-trip \"test\"",
        roundtrip<HasUniversalString>(HasUniversalString::asn_DEF, UniversalString{"test"}));

    // BmpString tag=0x1E
    printf("\n── BmpString ────────────────────────────────────────────────────\n");
    check("BmpString round-trip \"test\"",
        roundtrip<HasBmpString>(HasBmpString::asn_DEF, BmpString{"test"}));

    // VideotexString tag=0x15
    printf("\n── VideotexString ───────────────────────────────────────────────\n");
    check("VideotexString round-trip \"test\"",
        roundtrip<HasVideotexString>(HasVideotexString::asn_DEF, VideotexString{"test"}));

    // ObjectDescriptor tag=0x07
    printf("\n── ObjectDescriptor ─────────────────────────────────────────────\n");
    check("ObjectDescriptor round-trip \"test\"",
        roundtrip<HasObjectDescriptor>(HasObjectDescriptor::asn_DEF, ObjectDescriptor{"test"}));

    // XER: text-encoded strings (NumericString, PrintableString, VisibleString, ObjectDescriptor)
    printf("\n── XER text-encoded string round-trips ──────────────────────────\n");
    check("NumericString XER round-trip \"123\"",
        xer_roundtrip<HasNumericString>(HasNumericString::asn_DEF, NumericString{"123"}));
    check("PrintableString XER round-trip \"Hello\"",
        xer_roundtrip<HasPrintableString>(HasPrintableString::asn_DEF, PrintableString{"Hello"}));
    check("VisibleString XER round-trip \"ABC\"",
        xer_roundtrip<HasVisibleString>(HasVisibleString::asn_DEF, VisibleString{"ABC"}));
    check("ObjectDescriptor XER round-trip \"test\"",
        xer_roundtrip<HasObjectDescriptor>(HasObjectDescriptor::asn_DEF, ObjectDescriptor{"test"}));

    // XER: hex-encoded strings (HexStringXerHandler covers T61, Videotex, Graphic, General)
    printf("\n── XER hex-encoded string round-trips ───────────────────────────\n");
    check("T61String XER round-trip \"test\"",
        xer_roundtrip<HasT61String>(HasT61String::asn_DEF, T61String{"test"}));
    check("VideotexString XER round-trip \"test\"",
        xer_roundtrip<HasVideotexString>(HasVideotexString::asn_DEF, VideotexString{"test"}));
    check("GraphicString XER round-trip \"test\"",
        xer_roundtrip<HasGraphicString>(HasGraphicString::asn_DEF, GraphicString{"test"}));
    check("GeneralString XER round-trip \"test\"",
        xer_roundtrip<HasGeneralString>(HasGeneralString::asn_DEF, GeneralString{"test"}));

    {
        // Verify hex format in output
        HasT61String v; v.value = T61String{"hi"};
        std::ostringstream oss;
        XerEncodeStream s{oss};
        XerCodec::instance().encode(s, HasT61String::asn_DEF, &v);
        // "hi" = 0x68 0x69
        check("T61String XER output is hex-encoded",
              oss.str().find("68 69") != std::string::npos);
    }

    // XER: wide-char strings (BmpString = UCS-2BE, UniversalString = UCS-4BE)
    printf("\n── XER wide-char string round-trips ─────────────────────────────\n");
    {
        // "AB" in UCS-2BE = \x00\x41\x00\x42
        BmpString bmp{std::string("\x00\x41\x00\x42", 4)};
        check("BmpString XER round-trip (UCS-2BE \"AB\")",
            xer_roundtrip<HasBmpString>(HasBmpString::asn_DEF, bmp));
    }
    {
        // "AB" in UCS-4BE = \x00\x00\x00\x41\x00\x00\x00\x42
        UniversalString us{std::string("\x00\x00\x00\x41\x00\x00\x00\x42", 8)};
        check("UniversalString XER round-trip (UCS-4BE \"AB\")",
            xer_roundtrip<HasUniversalString>(HasUniversalString::asn_DEF, us));
    }
    {
        // Verify BmpString XER output is UTF-8 text, not hex
        BmpString bmp{std::string("\x00\x41\x00\x42", 4)};  // "AB" in UCS-2BE
        HasBmpString v; v.value = bmp;
        std::ostringstream oss;
        XerEncodeStream s{oss};
        XerCodec::instance().encode(s, HasBmpString::asn_DEF, &v);
        check("BmpString XER output contains UTF-8 text \"AB\"",
              oss.str().find("AB") != std::string::npos);
    }

    // ── PER FROM-constrained strings ──────────────────────────────────────────
    // Verifies that the alphabet table (TypeDescriptor::constraints.alphabet) is
    // used for UPER character indexing, not a hardcoded linear scan.
    printf("\n── PER FROM-constrained string round-trips ──────────────────────\n");

    auto per_rt_str = [](const char* label, const TypeDescriptor& def,
                         const auto& val, auto& wrapper) -> bool {
        wrapper.value = val;
        std::vector<uint8_t> buf;
        { PerEncodeStream s{buf}; PerCodec::instance().encode(s, def, &wrapper); s.flush(); }
        std::decay_t<decltype(wrapper)> out{};
        { PerDecodeStream s{std::span<const uint8_t>(buf)};
          if (!PerCodec::instance().decode(s, def, &out).has_value()) return false; }
        return out.value.str() == wrapper.value.str();
    };

    // HasHexStr: IA5String FROM "0-9A-F", 16-char alphabet → 4 bits/char
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"DEAD\"",    per_rt_str("", HasHexStr::asn_DEF, Ia5String{"DEAD"}, w)); }
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"0\"",       per_rt_str("", HasHexStr::asn_DEF, Ia5String{"0"}, w)); }
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"DEADBEEF\"",per_rt_str("", HasHexStr::asn_DEF, Ia5String{"DEADBEEF"}, w)); }

    // HasYesNoStr: IA5String FROM "NY", 2-char alphabet → 1 bit/char
    { HasYesNoStr w{};
      check("HasYesNoStr PER round-trip \"Y\"",     per_rt_str("", HasYesNoStr::asn_DEF, Ia5String{"Y"}, w)); }
    { HasYesNoStr w{};
      check("HasYesNoStr PER round-trip \"NYN\"",   per_rt_str("", HasYesNoStr::asn_DEF, Ia5String{"NYN"}, w)); }

    // HasVowelStr: PrintableString FROM "aeiou", 5-char alphabet → 3 bits/char
    { HasVowelStr w{};
      check("HasVowelStr PER round-trip \"aeiou\"", per_rt_str("", HasVowelStr::asn_DEF, PrintableString{"aeiou"}, w)); }
    { HasVowelStr w{};
      check("HasVowelStr PER round-trip \"a\"",     per_rt_str("", HasVowelStr::asn_DEF, PrintableString{"a"}, w)); }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
