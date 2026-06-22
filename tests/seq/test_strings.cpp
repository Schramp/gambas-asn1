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
#include "HexCharType.hpp"
#include "YesNoCharType.hpp"
#include "VowelType.hpp"
#include "OutOfOrderType.hpp"
#include "HasHexStr.hpp"
#include "HasYesNoStr.hpp"
#include "HasVowelStr.hpp"
#include "HasOutOfOrder.hpp"
#include "HasSizedIa5.hpp"
#include "HasSizedVis.hpp"
#include "HasSizedNum.hpp"
#include "HasSizedPrt.hpp"
#include "SizedIa5.hpp"
#include "SizedVis.hpp"
#include "SizedNum.hpp"
#include "SizedPrt.hpp"

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
    // Named intermediate types (HexCharType etc.) get dedicated TypeDescriptors
    // with constraints.alphabet populated. X.691 §26.5.7: canonical index =
    // position in numerically-sorted alphabet — std::lower_bound is valid.
    printf("\n── PER FROM-constrained string round-trips ──────────────────────\n");

    auto per_rt_str = [](const TypeDescriptor& def, const auto& val, auto& wrapper) -> bool {
        wrapper.value = val;
        std::vector<uint8_t> buf;
        { PerEncodeStream s{buf}; PerCodec::instance().encode(s, def, &wrapper); s.flush(); }
        std::decay_t<decltype(wrapper)> out{};
        { PerDecodeStream s{std::span<const uint8_t>(buf)};
          if (!PerCodec::instance().decode(s, def, &out).has_value()) return false; }
        return out.value.str() == wrapper.value.str();
    };

    // HexCharType: IA5String FROM "0-9A-F", 16-char alphabet → 4 bits/char
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"DEAD\"",    per_rt_str(HasHexStr::asn_DEF, Ia5String{"DEAD"}, w)); }
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"0\"",       per_rt_str(HasHexStr::asn_DEF, Ia5String{"0"}, w)); }
    { HasHexStr w{};
      check("HasHexStr PER round-trip \"DEADBEEF\"",per_rt_str(HasHexStr::asn_DEF, Ia5String{"DEADBEEF"}, w)); }

    // YesNoCharType: IA5String FROM "NY", 2-char alphabet → 1 bit/char
    { HasYesNoStr w{};
      check("HasYesNoStr PER round-trip \"Y\"",     per_rt_str(HasYesNoStr::asn_DEF, Ia5String{"Y"}, w)); }
    { HasYesNoStr w{};
      check("HasYesNoStr PER round-trip \"NYN\"",   per_rt_str(HasYesNoStr::asn_DEF, Ia5String{"NYN"}, w)); }

    // VowelType: PrintableString FROM "aeiou", 5-char alphabet → 3 bits/char
    { HasVowelStr w{};
      check("HasVowelStr PER round-trip \"aeiou\"", per_rt_str(HasVowelStr::asn_DEF, PrintableString{"aeiou"}, w)); }
    { HasVowelStr w{};
      check("HasVowelStr PER round-trip \"a\"",     per_rt_str(HasVowelStr::asn_DEF, PrintableString{"a"}, w)); }

    // OutOfOrderType: FROM ("F"|"A"|"9"|"0") — declared out of ASCII order.
    // Generator sorts to {0x30,0x39,0x41,0x46} before emitting; PerCodec encodes
    // by sorted index. Verifies sort is applied regardless of declaration order.
    { HasOutOfOrder w{};
      check("HasOutOfOrder PER round-trip \"0AF9\"", per_rt_str(HasOutOfOrder::asn_DEF, Ia5String{"0AF9"}, w)); }
    { HasOutOfOrder w{};
      check("HasOutOfOrder PER round-trip \"F\"",    per_rt_str(HasOutOfOrder::asn_DEF, Ia5String{"F"}, w)); }

    // ── PER builtin string type encoding (regression: IA5String table fix) ────
    // Expected bytes cross-validated against asn1c uper_encode_to_buffer().
    // See gen_builtin_tables.py — IA5String must use k_ia5_alpha[128] (0x00..0x7F),
    // NOT k_vis_alpha[95] (0x20..0x7E). Wrong tables → wrong encode_table indices.
    printf("\n── PER builtin string UPER encoding (asn1c-xval) ───────────────\n");

    // Direct table regression guards.
    check("asn_DEF_Ia5String alphabet_size=128",
        asn_DEF_Ia5String.constraints.alphabet_size == 128);
    check("asn_DEF_Ia5String enc[TAB=0x09]=9",
        asn_DEF_Ia5String.constraints.encode_table &&
        asn_DEF_Ia5String.constraints.encode_table[0x09] == 9);
    check("asn_DEF_Ia5String enc['B'=0x42]=66",
        asn_DEF_Ia5String.constraints.encode_table &&
        asn_DEF_Ia5String.constraints.encode_table[0x42] == 66);
    check("asn_DEF_Ia5String enc[0x80]=0xFFFF",
        asn_DEF_Ia5String.constraints.encode_table &&
        asn_DEF_Ia5String.constraints.encode_table[0x80] == 0xFFFFu);
    check("asn_DEF_VisibleString alphabet_size=95",
        asn_DEF_VisibleString.constraints.alphabet_size == 95);
    check("asn_DEF_VisibleString enc['B'=0x42]=34",
        asn_DEF_VisibleString.constraints.encode_table &&
        asn_DEF_VisibleString.constraints.encode_table[0x42] == 34);
    check("asn_DEF_VisibleString enc[TAB=0x09]=0xFFFF",
        asn_DEF_VisibleString.constraints.encode_table &&
        asn_DEF_VisibleString.constraints.encode_table[0x09] == 0xFFFFu);

    auto per_enc_bytes = [](const TypeDescriptor& def, const Asn1Object* obj) {
        std::vector<uint8_t> buf;
        PerEncodeStream s{buf};
        PerCodec::instance().encode(s, def, obj);
        s.flush();
        return buf;
    };
    auto per_dec_ok = [](const TypeDescriptor& def, Asn1Object* obj,
                         const std::vector<uint8_t>& buf) {
        PerDecodeStream s{std::span<const uint8_t>(buf)};
        return PerCodec::instance().decode(s, def, obj).has_value();
    };
    auto bytes_eq = [](const std::vector<uint8_t>& got,
                       std::initializer_list<uint8_t> exp) {
        return std::vector<uint8_t>(exp) == got;
    };

    // Unconstrained string types: length as 1-byte unconstrained determinant,
    // then characters at natural bit-width per string_params().
    // NumericString: 4 bits/char; "333" → {0x03, 0x44, 0x40}
    // PrintableString/IA5String/VisibleString: 7 bits/char; "BBB" → {0x03, 0x85, 0x0A, 0x10}
    printf("  unconstrained:\n");
    { HasNumericString w{}; w.value = NumericString{"333"};
      check("  HasNum{\"333\"} UPER={0x03,0x44,0x40}",
            bytes_eq(per_enc_bytes(HasNumericString::asn_DEF, &w), {0x03, 0x44, 0x40})); }
    { HasPrintableString w{}; w.value = PrintableString{"BBB"};
      check("  HasPrt{\"BBB\"} UPER={0x03,0x85,0x0A,0x10}",
            bytes_eq(per_enc_bytes(HasPrintableString::asn_DEF, &w), {0x03, 0x85, 0x0A, 0x10})); }
    { HasVisibleString w{}; w.value = VisibleString{"BBB"};
      check("  HasVis{\"BBB\"} UPER={0x03,0x85,0x0A,0x10}",
            bytes_eq(per_enc_bytes(HasVisibleString::asn_DEF, &w), {0x03, 0x85, 0x0A, 0x10})); }

    // SIZE(1..10) types: 4-bit size field (range=10, range_bits=4), then chars.
    // NumericString "333" → {0x24, 0x44}
    // PrintableString/IA5String/VisibleString "BBB" → {0x28, 0x50, 0xA1, 0x00}
    // IA5String "\t" (TAB=0x09): size_field=0000, char=0001001 → {0x01, 0x20}
    printf("  SIZE(1..10):\n");
    { HasSizedNum w{}; w.value = SizedNum{"333"};
      check("  HasSizedNum{\"333\"} UPER={0x24,0x44}",
            bytes_eq(per_enc_bytes(HasSizedNum::asn_DEF, &w), {0x24, 0x44})); }
    { HasSizedPrt w{}; w.value = SizedPrt{"BBB"};
      check("  HasSizedPrt{\"BBB\"} UPER={0x28,0x50,0xA1,0x00}",
            bytes_eq(per_enc_bytes(HasSizedPrt::asn_DEF, &w), {0x28, 0x50, 0xA1, 0x00})); }
    { HasSizedVis w{}; w.value = SizedVis{"BBB"};
      check("  HasSizedVis{\"BBB\"} UPER={0x28,0x50,0xA1,0x00}",
            bytes_eq(per_enc_bytes(HasSizedVis::asn_DEF, &w), {0x28, 0x50, 0xA1, 0x00})); }
    { HasSizedIa5 w{}; w.value = SizedIa5{"BBB"};
      check("  HasSizedIa5{\"BBB\"} UPER={0x28,0x50,0xA1,0x00}",
            bytes_eq(per_enc_bytes(HasSizedIa5::asn_DEF, &w), {0x28, 0x50, 0xA1, 0x00})); }
    // TAB is valid in IA5String (0x00..0x7F) but not in VisibleString (0x20..0x7E).
    { HasSizedIa5 w{}; w.value = SizedIa5{"\t"};
      auto b = per_enc_bytes(HasSizedIa5::asn_DEF, &w);
      check("  HasSizedIa5{TAB} UPER={0x01,0x20}",
            bytes_eq(b, {0x01, 0x20}));
      HasSizedIa5 dec{};
      check("  HasSizedIa5{TAB} round-trip",
            per_dec_ok(HasSizedIa5::asn_DEF, &dec, b) && dec.value.str() == "\t"); }

    // Round-trips for all SIZE-constrained types.
    printf("  round-trips:\n");
    auto per_rt = [&](const TypeDescriptor& def, auto& w, auto& out, const std::string& s) {
        w.value = decltype(w.value)(s);
        auto b = per_enc_bytes(def, &w);
        return per_dec_ok(def, &out, b) && out.value.str() == s;
    };
    { HasSizedNum w{}, o{}; check("  SizedNum \"12345\" round-trip",   per_rt(HasSizedNum::asn_DEF, w, o, "12345")); }
    { HasSizedPrt w{}, o{}; check("  SizedPrt \"Hello\" round-trip",   per_rt(HasSizedPrt::asn_DEF, w, o, "Hello")); }
    { HasSizedVis w{}, o{}; check("  SizedVis \"ABC\" round-trip",     per_rt(HasSizedVis::asn_DEF, w, o, "ABC")); }
    { HasSizedIa5 w{}, o{}; check("  SizedIa5 \"BBB\" round-trip",     per_rt(HasSizedIa5::asn_DEF, w, o, "BBB")); }
    { HasSizedIa5 w{}, o{}; check("  SizedIa5 \"\\tHello\" round-trip",per_rt(HasSizedIa5::asn_DEF, w, o, "\tHello")); }

    // Out-of-range alphabet index → DecodeError (was silent '?' substitution).
    // VowelType: PrintableString FROM("a"|"e"|"i"|"o"|"u"), alphabet_size=5, alphabet_bits=3.
    // Valid indices 0..4; index 5 (0b101) fits in 3 bits but is out of range.
    // Stream layout: unconstrained length byte (0x01 = 1 char), then 3-bit index padded.
    printf("  out-of-range alphabet index → DecodeError:\n");
    {
        // idx=5 (0b101): length=0x01, bits=10100000=0xA0 → out of range → error
        HasVowelStr out{};
        std::vector<uint8_t> corrupt{0x01, 0xA0};
        PerDecodeStream s{std::span<const uint8_t>(corrupt)};
        check("  VowelType idx=5 (out of range) → decode fails",
              !PerCodec::instance().decode(s, HasVowelStr::asn_DEF, &out).has_value());
    }
    {
        // idx=4 (0b100): length=0x01, bits=10000000=0x80 → 'u' (last valid entry)
        HasVowelStr out{};
        std::vector<uint8_t> valid{0x01, 0x80};
        PerDecodeStream s{std::span<const uint8_t>(valid)};
        check("  VowelType idx=4 ('u', in range) → decode succeeds",
              PerCodec::instance().decode(s, HasVowelStr::asn_DEF, &out).has_value()
              && out.value.str() == "u");
    }

    printf("\n");
    if (failures) { printf("  %d test(s) FAILED\n", failures); return 1; }
    printf("  All tests passed.\n");
    return 0;
}
