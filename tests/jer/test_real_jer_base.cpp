// JER-visible base constraints on REAL (real_jer_base_test.asn1, X.697
// §23.1.3/§23.1.4); mirrors tests/rust/real_jer_base/src/main.rs.
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "Bases.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static std::string jer(const Bases& v) {
    std::ostringstream o;
    JerEncodeStream s{o};
    JerCodec::instance().encode(s, Bases::asn_DEF, &v);
    return o.str();
}

static bool unjer(const std::string& json, Bases& out) {
    JerDecodeStream s{json};
    return JerCodec::instance().decode(s, Bases::asn_DEF, &out).has_value();
}

static std::string strip_ws(std::string s) {
    std::erase_if(s, [](char c) { return c == ' ' || c == '\n' || c == '\t'; });
    return s;
}

int main() {
    printf("=== REAL JER base constraints ===\n");
    const Real d = Real::decimal(false, "1456", -2);
    Bases v;
    v.b10 = d; v.b2 = d; v.inline_ = d; v.x697 = d; v.both = d; v.plain = d;
    const std::string json = strip_ws(jer(v));
    printf("        %s\n", json.c_str());
    check("base (10): bare JSON number", json.find("\"b10\":1456E-2,") != std::string::npos);
    check("inline WITH COMPONENTS base (10): bare JSON number", json.find("\"inline\":1456E-2,") != std::string::npos);
    check("X.697 example (0 | WITH COMPONENTS {... base (10) ...}): bare JSON number",
          json.find("\"x697\":1456E-2,") != std::string::npos);
    check("base (2): base10Value object", json.find("\"b2\":{\"base10Value\":1456E-2}") != std::string::npos);
    check("base (2..10): base10Value object", json.find("\"both\":{\"base10Value\":1456E-2}") != std::string::npos);
    check("unconstrained: base10Value object", json.find("\"plain\":{\"base10Value\":1456E-2}") != std::string::npos);

    Bases back;
    check("every member decodes back to the same Decimal",
          unjer(json, back) && back.b10 == d && back.b2 == d && back.inline_ == d && back.x697 == d &&
          back.both == d && back.plain == d);

    Bases n;
    const std::string numbers = "{\"b10\":14.56,\"b2\":14.56,\"inline\":14.56,\"x697\":14.56,\"both\":14.56,\"plain\":14.56}";
    check("a JSON number is base 10 only where the base is constrained to 10",
          unjer(numbers, n) && n.b10 == d && n.inline_ == d && n.x697 == d &&
          n.b2.storage() == Real::Storage::Double && n.both.storage() == Real::Storage::Double &&
          n.plain.storage() == Real::Storage::Double);

    Bases b;
    b.b10 = Real{0.5};
    check("a base-2 value is a JSON number under base (10) too (§23.1.2)",
          strip_ws(jer(b)).find("\"b10\":0.5,") != std::string::npos);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
