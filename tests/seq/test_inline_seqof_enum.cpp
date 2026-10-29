// SEQUENCE OF / SET OF whose element is an ENUMERATED written inline
// (X.680 §20): codegen promotes the element to a named type in the
// collection's scope (IsRecEbEnum, IsRecEnItem, IsTopEnum), and the
// member field is declared with that same type. Each anonymous nested
// SEQUENCE OF / SET OF level is a collection type of its own
// (IsNestLlAnon), and the element below it is named in that level's scope
// (IsNestLlAnonEnum), at any depth. An element with its own identifier
// uses it as its XER tag (X.680 §25.10).
// Schemas: tests/asn1/inline_seqof_enum_test.asn1, inline_seqof_deep_test.asn1
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
#include "IsNest.hpp"
#include "IsTopNest.hpp"
#include "IsDeep.hpp"

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

    IsNest n;
    IsNestLlAnon ll;
    ll.push_back(IsNestLlAnonEnum{IsNestLlAnonEnum::b});
    n.ll.push_back(ll);
    IsNestNnRow row;
    row.push_back(IsNestNnRowCell{IsNestNnRowCell::f});
    row.push_back(IsNestNnRowCell{IsNestNnRowCell::e});
    n.nn.push_back(row);
    IsNestNiItem item;
    item.w = Boolean{true};
    n.ni.push_back(item);
    n.in.k.push_back(IsNestInKEnum{IsNestInKEnum::n});

    auto nenc = encode(n, IsNest::asn_DEF);
    IsNest nback;
    check("IsNest BER round-trip (nested levels)", decode(nenc, IsNest::asn_DEF, nback) && nback == n);
    auto ntext = xer(IsNest::asn_DEF, n);
    check("element identifier is the XER tag: SEQUENCE OF row SEQUENCE OF",
          ntext.find("    <nn>\n        <row><f/><e/>        </row>\n    </nn>\n") != std::string::npos);
    check("element identifier is the XER tag: SEQUENCE OF item SEQUENCE",
          ntext.find("    <ni>\n        <item>\n            <w><true/></w>\n        </item>\n    </ni>\n")
              != std::string::npos);
    IsNest nxback;
    check("IsNest XER round-trip (nested levels)", unxer(ntext, IsNest::asn_DEF, nxback) && nxback == n);

    IsDeep d;
    IsDeepCcAnonAnon cell;
    cell.v = Integer{6};
    IsDeepCcAnon cc;
    cc.push_back(cell);
    d.cc.push_back(cc);
    IsDeepL3AnonAnon l3set;
    l3set.push_back(IsDeepL3AnonAnonEnum{IsDeepL3AnonAnonEnum::d});
    IsDeepL3Anon l3;
    l3.push_back(l3set);
    d.l3.push_back(l3);
    IsDeepChLAnon chl;
    chl.push_back(IsDeepChLAnonEnum{IsDeepChLAnonEnum::h});
    d.ch.set_present(IsDeepCh::PR::l);
    d.ch.l().push_back(chl);
    auto denc = encode(d, IsDeep::asn_DEF);
    IsDeep dback;
    check("IsDeep BER round-trip (element types two levels down)", decode(denc, IsDeep::asn_DEF, dback) && dback == d);

    IsTopNest tn;
    IsTopNestAnon tset;
    tset.push_back(IsTopNestAnonEnum{IsTopNestAnonEnum::t});
    tn.push_back(tset);
    auto tnenc = encode(tn, asn_DEF_IsTopNest);
    check("IsTopNest BER", tnenc == std::vector<uint8_t>{0x30, 0x05, 0x31, 0x03, 0x0A, 0x01, 0x01});
    IsTopNest tnback;
    check("IsTopNest BER round-trip", decode(tnenc, asn_DEF_IsTopNest, tnback) && tnback == tn);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
