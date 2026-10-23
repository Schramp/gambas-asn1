// ECMA-404 JSON reader used for compiler configuration files.
#include <cstdio>
#include <string>
#include "config/Json.hpp"

using asn1::config::JsonValue;
using asn1::config::parse_json;

static int failures = 0;

static void check(const char* name, bool cond) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static bool rejects(const char* text, const char* frag) {
    std::string err;
    auto v = parse_json(text, err);
    return !v && err.find(frag) != std::string::npos;
}

int main() {
    std::string err;
    auto v = parse_json(R"({ "a": [1, -2.5e3, true, false, null],
                             "s": "x\"\\\/\b\f\n\r\té😀", "o": {} })", err);
    check("parses a document", v && v->is_object());
    if (v) {
        const auto* a = v->find("a");
        check("array of 5", a && a->is_array() && std::get<JsonValue::Array>(a->v).size() == 5);
        check("number kept as text", a && std::get<JsonValue::Number>(std::get<JsonValue::Array>(a->v)[1].v).text == "-2.5e3");
        const auto* s = v->find("s");
        check("escapes and surrogate pair",
              s && std::get<std::string>(s->v) == "x\"\\/\b\f\n\r\t\xc3\xa9\xf0\x9f\x98\x80");
        check("missing member is null", v->find("zz") == nullptr);
        check("line numbers", a && a->line == 1);
    }
    auto multi = parse_json("{\n\n  \"k\": 1\n}", err);
    check("line of a later value", multi && multi->find("k")->line == 3);
    check("rejects trailing comma", rejects("[1,]", "unexpected character"));
    check("rejects duplicate member", rejects(R"({"a":1,"a":2})", "duplicate member"));
    check("rejects leading zero", rejects("[01]", "expected ','"));
    check("rejects trailing text", rejects("{} x", "trailing characters"));
    check("rejects unterminated string", rejects("\"abc", "unterminated string"));
    check("rejects control char", rejects("\"a\nb\"", "control character"));
    check("rejects lone surrogate", rejects(R"("\udc00")", "unpaired surrogate"));
    check("reports line", rejects("{\n\"a\":\n}", "line 3"));
    std::string deep(100, '[');
    check("rejects deep nesting", rejects(deep.c_str(), "nesting too deep"));
    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
