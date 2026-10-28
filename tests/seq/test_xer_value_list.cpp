// XER of a SEQUENCE OF / SET OF whose elements are BOOLEAN, ENUMERATED or
// NULL: the XMLValueList form (X.680 §25.5 Table 5) — each value bare, with
// no element tag, also through a type reference or a tag (§25.6, §25.9); a
// NULL value is the empty element of its type name (§25.4).
// Schema: tests/asn1/xer_value_list_test.asn1
//
// The expected text is asn1c's own layout (converter-example -iber -oxer):
// SEQUENCE OF values inline, SET OF values and NULL values each on a new
// line, the closing tag indented on the line of the last value.
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "VlRec.hpp"
#include "VlTopBool.hpp"
#include "VlTopNull.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* name, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", name);
    else { printf("  \033[31mFAIL\033[0m  %s\n", name); ++failures; }
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

static bool contains(const std::string& text, const std::string& part) {
    bool ok = text.find(part) != std::string::npos;
    if (!ok) printf("        missing:\n%s\n        in:\n%s\n", part.c_str(), text.c_str());
    return ok;
}

int main() {
    printf("\n── XMLValueList (X.680 §25.5) ──────────────────────────────────\n");

    VlRec v;
    v.ec.push_back(Color{Color::green});
    v.ec.push_back(Color{Color::green});
    v.et.push_back(TEnum{TEnum::red});
    v.bb.push_back(Boolean{true});
    v.bb.push_back(Boolean{false});
    v.ba.push_back(ABool{true});
    v.bt.push_back(TBool{false});
    v.bt.push_back(TBool{true});
    v.nb.push_back(Null{});
    v.nb.push_back(Null{});
    v.na.push_back(ANull{});
    v.nt.push_back(TNull{});
    v.st.push_back(ANull{});
    v.st.push_back(ANull{});
    VlRecLlAnon inner;
    inner.push_back(Boolean{true});
    inner.push_back(Boolean{true});
    v.ll.push_back(inner);
    VlPick pick;
    pick.set_present(VlPick::PR::b);
    pick.b() = Boolean{true};
    v.lc.push_back(pick);

    auto text = xer(VlRec::asn_DEF, v);
    check("SEQUENCE OF ENUMERATED: values inline",
          contains(text, "    <ec><green/><green/>    </ec>\n"));
    check("SEQUENCE OF tagged ENUMERATED type: values inline",
          contains(text, "    <et><red/>    </et>\n"));
    check("SEQUENCE OF BOOLEAN: bare <true/>/<false/>",
          contains(text, "    <bb><true/><false/>    </bb>\n"));
    check("SEQUENCE OF BOOLEAN type reference: bare value",
          contains(text, "    <ba><true/>    </ba>\n"));
    check("SET OF tagged BOOLEAN type: one bare value per line",
          contains(text, "    <bt>\n            <false/>\n            <true/>    </bt>\n"));
    check("SEQUENCE OF NULL: <NULL/> per line",
          contains(text, "    <nb>\n            <NULL/>\n            <NULL/>    </nb>\n"));
    check("SEQUENCE OF NULL type reference: <ANull/>",
          contains(text, "    <na>\n            <ANull/>    </na>\n"));
    check("SEQUENCE OF tagged NULL type: <TNull/>",
          contains(text, "    <nt>\n            <TNull/>    </nt>\n"));
    check("SET OF NULL type reference: <ANull/> per line",
          contains(text, "    <st>\n            <ANull/>\n            <ANull/>    </st>\n"));
    check("nested SEQUENCE OF BOOLEAN: values inline in <SEQUENCE_OF>",
          contains(text, "        <SEQUENCE_OF><true/><true/>        </SEQUENCE_OF>\n"));

    VlRec back;
    check("VlRec XER round-trip", unxer(text, VlRec::asn_DEF, back) && back == v);

    VlTopBool tb;
    tb.push_back(Boolean{false});
    tb.push_back(Boolean{true});
    auto tb_text = xer(asn_DEF_VlTopBool, tb);
    check("top-level SEQUENCE OF BOOLEAN", tb_text == "<VlTopBool><false/><true/></VlTopBool>\n");
    VlTopBool tb_back;
    check("top-level SEQUENCE OF BOOLEAN round-trip",
          unxer(tb_text, asn_DEF_VlTopBool, tb_back) && tb_back == tb);

    VlTopNull tn;
    tn.push_back(Null{});
    tn.push_back(Null{});
    auto tn_text = xer(asn_DEF_VlTopNull, tn);
    check("top-level SET OF NULL",
          tn_text == "<VlTopNull>\n        <NULL/>\n        <NULL/></VlTopNull>\n");
    VlTopNull tn_back;
    check("top-level SET OF NULL round-trip",
          unxer(tn_text, asn_DEF_VlTopNull, tn_back) && tn_back.count() == 2);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
