// JSON string escapes in JER input (jer_escape_test.asn1, RFC 8259 §7,
// X.697 §23.4 NOTE); mirrors tests/rust/jer_escape/src/main.rs. Each vector
// is a JER document whose `text` value carries escapes; it must decode to
// the given UTF-8 bytes, or fail when the escape is malformed. Member names
// and CHOICE alternative names may be escaped too.
#include <cstdio>
#include <sstream>
#include <string>
#include <asn1cpp/asn1cpp.hpp>
#include "JeRec.hpp"

using namespace asn1;

static int failures = 0;

static void check(const char* label, bool cond) {
    if (cond) printf("  \033[32mPASS\033[0m  %s\n", label);
    else      { printf("  \033[31mFAIL\033[0m  %s\n", label); ++failures; }
}

static bool unjer(const std::string& json, JeRec& out) {
    JerDecodeStream s{json};
    return JerCodec::instance().decode(s, JeRec::asn_DEF, &out).has_value();
}

static std::string jer(const JeRec& v) {
    std::ostringstream o;
    JerEncodeStream s{o};
    JerCodec::instance().encode(s, JeRec::asn_DEF, &v);
    return o.str();
}

static std::string doc(const std::string& text) {
    return "{\"text\":\"" + text + "\",\"alt\":{\"n\":1}}";
}

struct Vec {
    const char* label;
    const char* escaped;  // JSON string content, without quotes
    const char* utf8;     // expected value; nullptr = decode error
};

int main() {
    printf("=== JER string escapes ===\n");
    const Vec vecs[] = {
        {"\\u0041 is A", "\\u0041", "A"},
        {"\\u00e9 is UTF-8 C3 A9", "\\u00e9", "\xC3\xA9"},
        {"\\u20AC (upper-case hex) is UTF-8 E2 82 AC", "\\u20AC", "\xE2\x82\xAC"},
        {"surrogate pair \\ud83d\\ude00 is UTF-8 F0 9F 98 80", "\\ud83d\\ude00", "\xF0\x9F\x98\x80"},
        {"\\b and \\f are U+0008 and U+000C", "\\b\\f", "\x08\x0C"},
        {"\\\" \\\\ \\/ \\n \\r \\t", "\\\"\\\\\\/\\n\\r\\t", "\"\\/\n\r\t"},
        {"lone high surrogate is an error", "\\ud83dx", nullptr},
        {"high surrogate followed by a non-surrogate escape is an error", "\\ud83d\\u0041", nullptr},
        {"lone low surrogate is an error", "\\ude00", nullptr},
        {"truncated \\u12 is an error", "\\u12", nullptr},
        {"non-hex digit in \\u is an error", "\\u00g1", nullptr},
        {"unknown escape \\x is an error", "\\x41", nullptr},
    };
    for (const auto& v : vecs) {
        JeRec r;
        bool ok = unjer(doc(v.escaped), r);
        check(v.label, v.utf8 ? ok && r.text.str() == v.utf8 : !ok);
    }

    JeRec r;
    check("escaped member and alternative names",
          unjer("{\"\\u0074ext\":\"hi\",\"al\\u0074\":{\"\\u006eame\":\"x\"}}", r) && r.text.str() == "hi"
              && r.alt.present() == JeRecAlt::PR::name && r.alt.name().str() == "x");

    JeRec c;
    c.text = Utf8String(std::string("a\x01\x08\x0C\x1F" "b\xC3\xA9"));
    c.alt.set_present(JeRecAlt::PR::n);
    JeRec back;
    check("control characters survive a JER round-trip", unjer(jer(c), back) && back.text.str() == c.text.str());

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
