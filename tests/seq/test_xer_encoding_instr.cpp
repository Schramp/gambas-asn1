// XER encoding instruction tests (X.693 §21).
// Schema: tests/asn1/xer_encoding_instr_test.asn1
//
// Validates that [BASE64] on an OCTET STRING member switches XER serialisation
// from uppercase hex to Base64 (RFC 2045 §6.8), and that the default (no
// instruction) keeps hex.  Also exercises the named-typedef path.
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "InlineTest.hpp"
#include "Base64Payload.hpp"
#include "PayloadWrapper.hpp"
#include "LegacyBase64.hpp"
#include "StandardBase64.hpp"
#include "NoInstruction.hpp"
#include "Utf8Field.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else     { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

// ---------------------------------------------------------------------------
// Helpers

static std::string xer_encode_inline(const InlineTest& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, InlineTest::asn_DEF, &v);
    return oss.str();
}

static bool xer_decode_inline(const std::string& xml, InlineTest& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, InlineTest::asn_DEF, &out).has_value();
}

static std::string xer_encode_named(const Base64Payload& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, asn_DEF_Base64Payload, &v);
    return oss.str();
}

static bool xer_decode_named(const std::string& xml, Base64Payload& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, asn_DEF_Base64Payload, &out).has_value();
}

static std::string xer_encode_wrapper(const PayloadWrapper& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, PayloadWrapper::asn_DEF, &v);
    return oss.str();
}

// ---------------------------------------------------------------------------
// Test data: 0xDE 0xAD 0xBE 0xEF
// hex: DEADBEEF
// base64: 3q2+7w==

static const uint8_t kBytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };

// ---------------------------------------------------------------------------
// 1. Inline member: hexfield (default) vs b64field ([BASE64])

static void test_inline_encode() {
    printf("--- inline [BASE64] member encode ---\n");

    InlineTest v{};
    v.hexfield = OctetString{kBytes, sizeof(kBytes)};
    v.b64field = OctetString{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_inline(v);

    check("hexfield uses uppercase hex",
          xer.find("<hexfield>DEADBEEF</hexfield>") != std::string::npos);
    check("b64field uses base64",
          xer.find("<b64field>3q2+7w==</b64field>") != std::string::npos);
}

static void test_inline_decode() {
    printf("--- inline [BASE64] member decode ---\n");

    const std::string xml =
        "<InlineTest>"
        "<hexfield>DEADBEEF</hexfield>"
        "<b64field>3q2+7w==</b64field>"
        "</InlineTest>\n";

    InlineTest out{};
    check("XER decode succeeds", xer_decode_inline(xml, out));
    auto eq = [](auto sp, const uint8_t* p, std::size_t n) {
        return sp.size() == n && std::equal(sp.begin(), sp.end(), p);
    };
    check("hexfield bytes correct",  eq(out.hexfield.bytes(), kBytes, 4));
    check("b64field bytes correct",  eq(out.b64field.bytes(), kBytes, 4));
}

static void test_inline_roundtrip() {
    printf("--- inline [BASE64] member round-trip ---\n");

    InlineTest orig{};
    orig.hexfield = OctetString{kBytes, sizeof(kBytes)};
    orig.b64field = OctetString{kBytes, sizeof(kBytes)};

    std::string xer = xer_encode_inline(orig);
    InlineTest rt{};
    check("XER round-trip decode ok", xer_decode_inline(xer, rt));
    auto sp_eq = [](auto a, auto b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
    };
    check("hexfield round-trip bytes match", sp_eq(rt.hexfield.bytes(), orig.hexfield.bytes()));
    check("b64field round-trip bytes match",  sp_eq(rt.b64field.bytes(), orig.b64field.bytes()));
}

// ---------------------------------------------------------------------------
// 2. Named typedef: Base64Payload ::= [BASE64] OCTET STRING

static void test_named_typedef_encode() {
    printf("--- named [BASE64] typedef encode ---\n");

    Base64Payload v{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_named(v);
    check("named Base64Payload uses base64",
          xer.find("3q2+7w==") != std::string::npos);
}

static void test_named_typedef_decode() {
    printf("--- named [BASE64] typedef decode ---\n");

    const std::string xml = "<Base64Payload>3q2+7w==</Base64Payload>\n";
    Base64Payload out{};
    check("named decode succeeds", xer_decode_named(xml, out));
    auto sp_eq2 = [](auto sp, const uint8_t* p, std::size_t n) {
        return sp.size() == n && std::equal(sp.begin(), sp.end(), p);
    };
    check("named decoded bytes correct", sp_eq2(out.bytes(), kBytes, 4));
}

// ---------------------------------------------------------------------------
// 3. PayloadWrapper embeds Base64Payload via type-ref

static void test_wrapper_encode() {
    printf("--- PayloadWrapper (type-ref) encode ---\n");

    PayloadWrapper v{};
    v.data = Base64Payload{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_wrapper(v);
    check("wrapper data field uses base64",
          xer.find("<data>3q2+7w==</data>") != std::string::npos);
}

// ---------------------------------------------------------------------------
// 4. Empty OCTET STRING round-trip under both encodings

static void test_empty_roundtrip() {
    printf("--- empty OCTET STRING round-trip ---\n");

    InlineTest orig{};  // both fields empty

    std::string xer = xer_encode_inline(orig);
    check("hexfield empty encodes as empty element",
          xer.find("<hexfield></hexfield>") != std::string::npos);
    check("b64field empty encodes as empty element",
          xer.find("<b64field></b64field>") != std::string::npos);

    InlineTest rt{};
    check("empty round-trip decode ok", xer_decode_inline(xer, rt));
    check("hexfield empty after round-trip", rt.hexfield.bytes().empty());
    check("b64field empty after round-trip", rt.b64field.bytes().empty());
}

// ---------------------------------------------------------------------------
// 5. ENCODING-CONTROL XER block form (gambas-asn1#438) — separate grammar
//    path from the inline [BASE64] prefix tested above. Legacy per-type
//    (`T OCTET STRING ::= base64`) and standard (`BASE64 T`) forms both
//    target types with no `[BASE64]` written on the type itself.

template<typename T>
static std::string xer_encode_generic(const T& v, const TypeDescriptor& def) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, def, &v);
    return oss.str();
}

template<typename T>
static bool xer_decode_generic(const std::string& xml, const TypeDescriptor& def, T& out) {
    XerDecodeStream s{xml};
    return XerCodec::instance().decode(s, def, &out).has_value();
}

static void test_encoding_control_legacy() {
    printf("--- ENCODING-CONTROL XER legacy form (T OCTET STRING ::= base64) ---\n");

    LegacyBase64 v{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_generic(v, asn_DEF_LegacyBase64);
    check("legacy form uses base64", xer.find("3q2+7w==") != std::string::npos);

    LegacyBase64 out{};
    check("legacy form decode ok",
          xer_decode_generic("<LegacyBase64>3q2+7w==</LegacyBase64>\n", asn_DEF_LegacyBase64, out));
    check("legacy form decoded bytes correct",
          out.bytes().size() == 4 && std::equal(out.bytes().begin(), out.bytes().end(), kBytes));
}

static void test_encoding_control_standard() {
    printf("--- ENCODING-CONTROL XER standard form (BASE64 TypeName) ---\n");

    StandardBase64 v{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_generic(v, asn_DEF_StandardBase64);
    check("standard form uses base64", xer.find("3q2+7w==") != std::string::npos);

    StandardBase64 out{};
    check("standard form decode ok",
          xer_decode_generic("<StandardBase64>3q2+7w==</StandardBase64>\n", asn_DEF_StandardBase64, out));
    check("standard form decoded bytes correct",
          out.bytes().size() == 4 && std::equal(out.bytes().begin(), out.bytes().end(), kBytes));
}

static void test_encoding_control_no_instruction_stays_hex() {
    printf("--- type with no ENCODING-CONTROL instruction stays hex ---\n");

    NoInstruction v{kBytes, sizeof(kBytes)};
    std::string xer = xer_encode_generic(v, asn_DEF_NoInstruction);
    check("untouched type still uses hex", xer.find("DEADBEEF") != std::string::npos);
}

// ---------------------------------------------------------------------------
// 6. ENCODING-CONTROL XER ::= utf8 (gambas-asn1#443) — raw UTF-8 text, not
//    a hex/base64 variant. "Hi" + DC3 control char (0x13) + '&' + 'é'
//    (multi-byte UTF-8, 0xC3 0xA9) + '<' + '>'.
//    Expected XER: Hi<dc3/>&amp;\xC3\xA9&lt;&gt;

static const uint8_t kUtf8Bytes[] = {
    'H', 'i', 0x13, '&', 0xC3, 0xA9, '<', '>'
};

static void test_encoding_control_utf8_encode() {
    printf("--- ENCODING-CONTROL XER ::= utf8 encode ---\n");

    Utf8Field v{kUtf8Bytes, sizeof(kUtf8Bytes)};
    std::string xer = xer_encode_generic(v, asn_DEF_Utf8Field);
    check("utf8 form: ASCII text passes through", xer.find("Hi") != std::string::npos);
    check("utf8 form: control char becomes <dc3/>", xer.find("<dc3/>") != std::string::npos);
    check("utf8 form: & escaped", xer.find("&amp;") != std::string::npos);
    check("utf8 form: multi-byte UTF-8 passes through raw",
          xer.find("\xC3\xA9") != std::string::npos);
    check("utf8 form: < escaped", xer.find("&lt;") != std::string::npos);
    check("utf8 form: > escaped", xer.find("&gt;") != std::string::npos);
    // Not present as raw hex the way Default/Base64 would render these bytes.
    check("utf8 form: not hex-encoded", xer.find("4869") == std::string::npos);
}

static void test_encoding_control_utf8_roundtrip() {
    printf("--- ENCODING-CONTROL XER ::= utf8 round-trip ---\n");

    Utf8Field orig{kUtf8Bytes, sizeof(kUtf8Bytes)};
    std::string xer = xer_encode_generic(orig, asn_DEF_Utf8Field);

    Utf8Field out{};
    check("utf8 form round-trip decode ok", xer_decode_generic(xer, asn_DEF_Utf8Field, out));
    check("utf8 form round-trip bytes match",
          out.bytes().size() == sizeof(kUtf8Bytes)
              && std::equal(out.bytes().begin(), out.bytes().end(), kUtf8Bytes));
}

// ---------------------------------------------------------------------------

int main() {
    test_inline_encode();
    test_inline_decode();
    test_inline_roundtrip();
    test_named_typedef_encode();
    test_named_typedef_decode();
    test_wrapper_encode();
    test_empty_roundtrip();
    test_encoding_control_legacy();
    test_encoding_control_standard();
    test_encoding_control_no_instruction_stays_hex();
    test_encoding_control_utf8_encode();
    test_encoding_control_utf8_roundtrip();

    if (failures == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    }
    printf("\n%d test(s) FAILED.\n", failures);
    return 1;
}
