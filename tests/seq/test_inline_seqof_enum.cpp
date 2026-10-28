// SEQUENCE OF / SET OF whose element is an ENUMERATED written inline
// (X.680 §20): codegen promotes the element to a named type in the
// collection's scope (IsRecEbEnum, IsRecEnItem, IsTopEnum), and the
// member field is declared with that same type.
// Schema: tests/asn1/inline_seqof_enum_test.asn1
//
// BER: each element is a universal ENUMERATED (X.690 §8.4); XER: the
// values form an XMLValueList (X.680 §25.5), asn1c's layout.
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>
#include <asn1cpp/asn1cpp.hpp>
#include "IsRec.hpp"
#include "IsTop.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
}

static std::vector<uint8_t> encode(const Asn1Object& v, const TypeDescriptor& def) {
    std::vector<uint8_t> buf;
    BerWriter w{buf};
    BerEncodeStream s{w};
    BerCodec::instance().encode(s, def, &v);
    return buf;
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

int main() {
    printf("\n── SEQUENCE OF inline ENUMERATED ───────────────────────────────\n");

    IsRec v;
    v.eb.push_back(IsRecEbEnum{IsRecEbEnum::b});
    v.eb.push_back(IsRecEbEnum{IsRecEbEnum::a});
    v.es.push_back(IsRecEsEnum{IsRecEsEnum::n});
    v.en.push_back(IsRecEnItem{IsRecEnItem::h});
    v.ec.set_present(IsRecEc::PR::x);
    v.ec.x() = IsRecEcX{IsRecEcX::q};

    auto enc = encode(v, IsRec::asn_DEF);
    const std::vector<uint8_t> want{
        0x30, 0x15,
        0x30, 0x06, 0x0A, 0x01, 0x01, 0x0A, 0x01, 0x00,  // eb
        0x31, 0x03, 0x0A, 0x01, 0x01,                    // es
        0xA0, 0x03, 0x0A, 0x01, 0x01,                    // en [0]
        0x0A, 0x01, 0x01,                                // ec.x
    };
    check("IsRec BER: elements are universal ENUMERATED", enc == want);
    IsRec back;
    check("IsRec BER round-trip", decode(enc, IsRec::asn_DEF, back) && back == v);

    auto text = xer(IsRec::asn_DEF, v);
    check("IsRec XER", same(text,
        "<IsRec>\n"
        "    <eb><b/><a/>    </eb>\n"
        "    <es>\n"
        "            <n/>    </es>\n"
        "    <en><h/>    </en>\n"
        "    <ec>\n"
        "        <x><q/></x>\n"
        "    </ec>\n"
        "</IsRec>\n"));
    IsRec xback;
    check("IsRec XER round-trip", unxer(text, IsRec::asn_DEF, xback) && xback == v);

    IsTop t;
    t.push_back(IsTopEnum{IsTopEnum::v});
    t.push_back(IsTopEnum{IsTopEnum::u});
    auto tenc = encode(t, asn_DEF_IsTop);
    check("IsTop BER", tenc == std::vector<uint8_t>{0x30, 0x06, 0x0A, 0x01, 0x01, 0x0A, 0x01, 0x00});
    IsTop tback;
    check("IsTop BER round-trip", decode(tenc, asn_DEF_IsTop, tback) && tback == t);
    check("IsTop XER", same(xer(asn_DEF_IsTop, t), "<IsTop><v/><u/></IsTop>\n"));

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
