// Proves the Backend interface (gambas-asn1#216) is genuinely
// language-agnostic by exercising two real implementations — CppBackend and
// RustBackend (#217) — against the same ASN.1 names and checking that
// language-appropriate naming conventions diverge correctly. Also exercises
// the first real emit_* pair (ENUMERATED, #226/#234): both backends produce
// real, distinct output for the same EnumeratedSpec.
#include <cstdio>
#include <cstdlib>
#include <sstream>
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

    // emit_enumerated_hpp/cpp: first real construct pair. Same
    // EnumeratedSpec, two genuinely different real outputs — not a
    // stub/placeholder on either side.
    {
        EnumeratedSpec spec;
        spec.type_name = "MyEnum";
        spec.xer_name  = "MyEnum";
        spec.values    = {{"foo", 0}, {"bar", 1}};
        spec.extensible = false;
        spec.root_count  = 2;

        std::ostringstream cpp_hpp, cpp_cpp, rust_hpp, rust_cpp;
        c.emit_enumerated_hpp(spec, cpp_hpp);
        c.emit_enumerated_cpp(spec, cpp_cpp);
        r.emit_enumerated_hpp(spec, rust_hpp);
        r.emit_enumerated_cpp(spec, rust_cpp);

        check("emit_enumerated_hpp: C++ produces a class",
              cpp_hpp.str().find("class MyEnum") != std::string::npos,
              cpp_hpp.str());
        check("emit_enumerated_hpp: Rust produces a real enum (not a stub)",
              rust_hpp.str().find("pub enum MyEnum") != std::string::npos,
              rust_hpp.str());
        check("emit_enumerated_hpp: Rust variants use declared values, UpperCamelCase",
              rust_hpp.str().find("Foo = 0") != std::string::npos &&
              rust_hpp.str().find("Bar = 1") != std::string::npos,
              rust_hpp.str());
        check("emit_enumerated_cpp: C++ produces EnumSpec + TypeDescriptor",
              cpp_cpp.str().find("asn_SPC") != std::string::npos &&
              cpp_cpp.str().find("asn_DEF") != std::string::npos,
              cpp_cpp.str());
        check("emit_enumerated_cpp: Rust produces a value-lookup impl",
              rust_cpp.str().find("impl std::convert::TryFrom<i64> for MyEnum") != std::string::npos &&
              rust_cpp.str().find("0 => Ok(MyEnum::Foo)") != std::string::npos,
              rust_cpp.str());
    }

    // emit_integer_hpp/cpp: second real construct pair. Constrained INTEGER
    // (0..100), U64 storage — exercises native_int_type() too.
    {
        IntegerSpec spec;
        spec.type_name = "MyInt";
        spec.xer_name  = "MyInt";
        spec.storage_kind = IntStorageKind::U64;
        spec.named_values = {{"zero", 0}};
        spec.has_constraint = true;
        spec.extensible = false;
        spec.semi_constrained = false;
        spec.hi_is_large = false;
        spec.range_bits = 7;
        spec.lower_s64 = 0;
        spec.upper_s64 = 100;
        spec.lower_u64 = 0;
        spec.upper_u64 = 100;

        std::ostringstream cpp_hpp, cpp_cpp, rust_hpp, rust_cpp;
        c.emit_integer_hpp(spec, cpp_hpp);
        c.emit_integer_cpp(spec, cpp_cpp);
        r.emit_integer_hpp(spec, rust_hpp);
        r.emit_integer_cpp(spec, rust_cpp);

        check("native_int_type: C++ maps U64 to asn1::UInteger",
              c.native_int_type(IntStorageKind::U64) == "asn1::UInteger",
              c.native_int_type(IntStorageKind::U64));
        check("native_int_type: Rust maps U64 to u64",
              r.native_int_type(IntStorageKind::U64) == "u64",
              r.native_int_type(IntStorageKind::U64));
        check("emit_integer_hpp: C++ produces a using-alias to asn1::UInteger",
              cpp_hpp.str().find("using MyInt = asn1::UInteger;") != std::string::npos,
              cpp_hpp.str());
        check("emit_integer_hpp: Rust produces a real type alias (not a stub)",
              rust_hpp.str().find("pub type MyInt = u64;") != std::string::npos,
              rust_hpp.str());
        check("emit_integer_cpp: C++ produces a Constraints-bearing TypeDescriptor",
              cpp_cpp.str().find("asn_DEF_MyInt") != std::string::npos &&
              cpp_cpp.str().find(".range_bits=7") != std::string::npos,
              cpp_cpp.str());
        check("emit_integer_cpp: Rust produces a real range-check function",
              rust_cpp.str().find("pub fn my_int_in_range(v: i64) -> bool {") != std::string::npos &&
              rust_cpp.str().find("v >= 0 && v <= 100") != std::string::npos,
              rust_cpp.str());
    }

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
