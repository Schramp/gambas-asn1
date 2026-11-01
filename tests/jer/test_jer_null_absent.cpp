// JER `null` for an absent OPTIONAL or DEFAULT member (jer_null_absent_test.asn1,
// X.697 §27.3.4); mirrors tests/rust/jer_null_absent/src/main.rs. A decoder
// takes `null` as "absent" for every OPTIONAL or DEFAULT member except one
// whose type can itself be `null` (NULL), where `null` is the value.
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "JnRec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static bool unjer(const std::string& json, JnRec& out) {
    JerDecodeStream s{json};
    return JerCodec::instance().decode(s, JnRec::asn_DEF, &out).has_value();
}

static std::string jer(const JnRec& v) {
    std::ostringstream o;
    JerEncodeStream s{o};
    JerCodec::instance().encode(s, JnRec::asn_DEF, &v);
    return o.str();
}

int main() {
    printf("=== JER null for absent members (X.697 §27.3.4) ===\n");

    JnRec r;
    bool ok = unjer(R"({"a":1,"b":null,"c":null,"o":null,"s":null})", r);
    check("null for OPTIONAL INTEGER/OCTET STRING/SEQUENCE and DEFAULT BOOLEAN decodes", ok);
    check("null OPTIONAL members are absent", ok && !r.b && !r.o && !r.s);
    check("null DEFAULT member is absent (takes its default)", ok && !r.c);
    check("absent members are left out on re-encode", ok && jer(r) == R"({"a":1})");

    JnRec w;
    ok = unjer(R"({ "a" : 2 , "b" : null , "n" : null })", w);
    check("null with surrounding whitespace decodes", ok && !w.b);
    check("null for NULL OPTIONAL is the NULL value, so present", ok && w.n);

    JnRec reuse;
    ok = unjer(R"({"a":3,"b":7})", reuse) && reuse.b;
    ok = ok && unjer(R"({"a":3,"b":null})", reuse);
    check("null resets a member decoded earlier into the same value", ok && !reuse.b);

    JnRec bad;
    check("null for a mandatory member is an error", !unjer(R"({"a":null})", bad));
    check("nullx is not null", !unjer(R"({"a":1,"b":nullx})", bad));

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
