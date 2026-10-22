// X.682 §11.4/§11.6: classification of a contents constraint's ENCODED BY
// OBJECT IDENTIFIER into the encoding rules the codecs can apply.
#include <cstdio>
#include "sema/Contents.hpp"

using asn1::sema::ContentsEncoding;
using asn1::sema::classify_encoded_by;

static int failures = 0;

static void check(const char* text, ContentsEncoding want) {
    auto got = classify_encoded_by(text);
    if (got == want) {
        printf("  PASS  %s\n", text);
    } else {
        printf("  FAIL  %s: got %d, want %d\n", text, static_cast<int>(got), static_cast<int>(want));
        ++failures;
    }
}

int main() {
    check("", ContentsEncoding::Outer);
    check("{ joint-iso-itu-t asn1(1) basic-encoding(1) }", ContentsEncoding::Ber);
    check("{joint-iso-itu-t asn1 basic-encoding}", ContentsEncoding::Ber);
    check("{ 2 1 1 }", ContentsEncoding::Ber);
    check("{ 2 1 2 0 }", ContentsEncoding::Cer);
    check("{ joint-iso-itu-t asn1(1) ber-derived(2) distinguished-encoding(1) }", ContentsEncoding::Der);
    check("{ 2 1 3 0 0 }", ContentsEncoding::PerAligned);
    check("{ joint-iso-itu-t asn1(1) packed-encoding(3) basic(0) unaligned(1) }", ContentsEncoding::PerUnaligned);
    check("{ joint-iso-itu-t asn1(1) xml-encoding(5) basic(0) }", ContentsEncoding::Unknown);
    check("{ 2 1 }", ContentsEncoding::Unknown);
    check("{ 2 1 1 ", ContentsEncoding::Unknown);
    check("{ joint-iso-itu-t asn1( ) }", ContentsEncoding::Unknown);
    check("berOid", ContentsEncoding::Unknown);
    check("Module.berOid", ContentsEncoding::Unknown);
    printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
