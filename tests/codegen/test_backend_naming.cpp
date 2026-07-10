// Proves the Backend interface (gambas-asn1#216) is genuinely
// language-agnostic by exercising two real implementations — CppBackend and
// RustBackend (#217) — against the same ASN.1 names and checking that
// language-appropriate naming conventions diverge correctly. No emit_*
// methods exist on Backend yet (that's #225, added incrementally, pairwise
// with CppBackend) — this covers only the naming/identifier-escaping
// surface #216 actually delivered.
#include <cstdio>
#include <cstdlib>
#include "codegen/Backend.hpp"
#include "codegen/CppBackend.hpp"
#include "codegen/RustBackend.hpp"
#include "sema/Resolver.hpp"

using namespace asn1::codegen;

static int failures = 0;

static void check(const char* name, bool cond, const std::string& detail = "") {
    if (cond) {
        printf("  \033[32mPASS\033[0m  %s\n", name);
    } else {
        printf("  \033[31mFAIL\033[0m  %s%s%s\n", name,
               detail.empty() ? "" : ": ", detail.c_str());
        ++failures;
    }
}

int main() {
    CppBackend cpp;
    RustBackend rust;
    const Backend& c = cpp;
    const Backend& r = rust;

    // type_name: both replace hyphens with underscores (ASN.1 and Rust
    // struct/enum naming conventions coincide here) — same output, not a
    // divergence bug.
    check("type_name: C++ hyphens -> underscores",
          c.type_name("My-Type") == "My_Type",
          c.type_name("My-Type"));
    check("type_name: Rust matches C++ (coincidental overlap, not laziness)",
          r.type_name("My-Type") == "My_Type",
          r.type_name("My-Type"));

    // member_name: C++ wants lowerCamelCase, Rust wants snake_case — this is
    // the real divergence the interface exists to capture.
    check("member_name: C++ lowerCamelCase",
          c.member_name("MyMember") == "myMember",
          c.member_name("MyMember"));
    check("member_name: Rust snake_case",
          r.member_name("MyMember") == "my_member",
          r.member_name("MyMember"));
    check("member_name: Rust snake_case from hyphenated ASN.1 name",
          r.member_name("Network-Identifier") == "network_identifier",
          r.member_name("Network-Identifier"));

    // value_name: C++ preserves case (hyphens -> underscores only), Rust
    // constants want SCREAMING_SNAKE_CASE.
    check("value_name: C++ preserves case",
          c.value_name("someValue") == "someValue",
          c.value_name("someValue"));
    check("value_name: Rust SCREAMING_SNAKE_CASE",
          r.value_name("someValue") == "SOME_VALUE",
          r.value_name("someValue"));

    // escape: keyword collision handled by each language's own list, with
    // each language's own convention (C++: trailing underscore; Rust: raw
    // identifier r#...).
    check("escape: C++ 'class' -> 'class_'",
          c.escape("class") == "class_",
          c.escape("class"));
    check("escape: Rust 'match' -> 'r#match' (not a C++ keyword, so C++ leaves it alone)",
          r.escape("match") == "r#match" && c.escape("match") == "match",
          r.escape("match") + " / " + c.escape("match"));
    check("escape: C++ 'type' is not a C++ keyword (leaves alone); Rust escapes it",
          c.escape("type") == "type" && r.escape("type") == "r#type",
          c.escape("type") + " / " + r.escape("type"));

    // synthetic_name: same parent+CapitalizedMember strategy works for both
    // languages' PascalCase type-naming convention.
    check("synthetic_name: parent + capitalized member",
          c.synthetic_name("Parent", "member") == "ParentMember",
          c.synthetic_name("Parent", "member"));
    check("synthetic_name: Rust matches C++ (same PascalCase strategy)",
          r.synthetic_name("Parent", "member") == "ParentMember",
          r.synthetic_name("Parent", "member"));

    // Generator accepts an injected Backend (not just the default CppBackend)
    // — proves the seam #216 built is real, not just declared. Construction
    // only (no generate() call — that still hardcodes C++ text emission
    // until #225's pairwise migration lands; calling it with RustBackend
    // today would produce misleading non-Rust output).
    {
        asn1::sema::Resolver resolver;
        asn1::codegen::Generator gen("/tmp/rust_backend_stub_unused", resolver, rust);
        check("Generator constructs with an injected non-default Backend", true);
        (void)gen;
    }

    printf("\n%s\n", failures == 0 ? "All checks passed." : "Some checks FAILED.");
    return failures == 0 ? 0 : 1;
}
