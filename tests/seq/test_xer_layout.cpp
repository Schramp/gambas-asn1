// XER text layout (xer_layout_test.asn1): the C++ XER encoder writes the
// same text as asn1c byte for byte, whitespace included. Each case decodes
// a DER record produced by asn1c's converter-example and compares the XER
// text with asn1c's own XER for that record. Rust leg: rust/xer_layout.
//
// A CHOICE as the document root is wrapped in its type name (X.693 §8.3.1),
// and its closing tag follows the alternative's line directly, for every
// kind of alternative. A SEQUENCE OF CHOICE writes each element as the
// chosen alternative's own element (X.680 §25.5 Table 5), in asn1c's layout.
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "XlRoot.hpp"
#include "XlSeq.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static bool decode(std::span<const uint8_t> bytes, const TypeDescriptor& def, Asn1Object& out) {
    BerReader r{bytes};
    BerDecodeStream s{r};
    return BerCodec::instance().decode(s, def, &out).has_value();
}

static std::string xer(const TypeDescriptor& def, const Asn1Object& v) {
    std::ostringstream oss;
    XerEncodeStream s{oss};
    XerCodec::instance().encode(s, def, &v);
    return oss.str();
}

static bool unxer(const std::string& text, const TypeDescriptor& def, Asn1Object& out) {
    XerDecodeStream s{text};
    return XerCodec::instance().decode(s, def, &out).has_value();
}

static bool same(const std::string& got, const std::string& want) {
    if (got != want) printf("        want:\n%s\n        got:\n%s\n", want.c_str(), got.c_str());
    return got == want;
}

struct Case {
    const char* label;
    std::vector<uint8_t> der;  // asn1c converter-example -oder
    const char* xer;           // asn1c converter-example -oxer
};

int main() {
    printf("\n── XER layout: root CHOICE ─────────────────────────────────────\n");

    const Case cases[] = {
        {"root CHOICE, INTEGER alternative", {0x80, 0x01, 0x05},
         "<XlRoot>\n    <num>5</num>\n</XlRoot>\n"},
        {"root CHOICE, SEQUENCE alternative", {0xa1, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0xff},
         "<XlRoot>\n    <rec>\n        <a>1</a>\n        <b><true/></b>\n    </rec>\n</XlRoot>\n"},
        {"root CHOICE, CHOICE alternative", {0xa2, 0x03, 0x81, 0x01, 0x00},
         "<XlRoot>\n    <sub>\n        <y><false/></y>\n    </sub>\n</XlRoot>\n"},
        {"root CHOICE, SEQUENCE OF alternative", {0xa3, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
         "<XlRoot>\n    <list>\n        <INTEGER>1</INTEGER>\n        <INTEGER>2</INTEGER>\n    </list>\n</XlRoot>\n"},
        {"root CHOICE, ENUMERATED alternative", {0x84, 0x01, 0x01},
         "<XlRoot>\n    <color><green/></color>\n</XlRoot>\n"},
        {"root CHOICE, UTF8String alternative", {0x85, 0x02, 0x68, 0x69},
         "<XlRoot>\n    <text>hi</text>\n</XlRoot>\n"},
    };
    for (const auto& c : cases) {
        XlRoot v;
        if (!decode(c.der, XlRoot::asn_DEF, v)) { check(c.label, false); continue; }
        std::string text = xer(XlRoot::asn_DEF, v);
        check(c.label, same(text, c.xer));
        XlRoot back;
        check("  XER round-trip", unxer(text, XlRoot::asn_DEF, back) && xer(XlRoot::asn_DEF, back) == text);
    }

    printf("\n── XER layout: SEQUENCE OF CHOICE ──────────────────────────────\n");
    {
        const std::vector<uint8_t> der = {0x30, 0x17, 0xa0, 0x12, 0xa0, 0x03, 0x80, 0x01, 0x01, 0xa1, 0x03, 0x80, 0x01, 0x02, 0x82, 0x01, 0x03, 0xa3, 0x03, 0x02, 0x01, 0x04, 0x81, 0x01, 0x09};
        const std::string want = "<XlSeq>\n    <items>\n            <rec>\n                <a>1</a>\n            </rec>\n\n            <sub>\n                <x>2</x>\n            </sub>\n\n            <num>3</num>\n\n            <list>\n                <INTEGER>4</INTEGER>\n            </list>\n    </items>\n    <tail>9</tail>\n</XlSeq>\n";
        XlSeq v;
        check("SEQUENCE OF CHOICE: BER decode", decode(der, XlSeq::asn_DEF, v));
        std::string text = xer(XlSeq::asn_DEF, v);
        check("SEQUENCE OF CHOICE, constructed and primitive alternatives", same(text, want));
        XlSeq back;
        check("  XER round-trip", unxer(text, XlSeq::asn_DEF, back) && xer(XlSeq::asn_DEF, back) == text);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
