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

// TypeOutputSession::buffer() returns std::ostream&; every internal buffer
// is actually an ostringstream, so this is safe.
static std::string buf_str(TypeOutputSession& s, const std::string& ext) {
    return static_cast<std::ostringstream&>(s.buffer(ext)).str();
}

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

    // type_name: C++ replaces hyphens with underscores; Rust (gambas-asn1#306)
    // wants a real word-split PascalCase instead — no underscore at all
    // (rustc's non_camel_case_types lint flags the literal underscore, not
    // acronym-style internal casing) — this is a real divergence, not the
    // coincidental overlap it used to be before #306.
    check("type_name: C++ hyphens -> underscores",
          c.type_name("My-Type") == "My_Type",
          c.type_name("My-Type"));
    check("type_name: Rust real PascalCase, no underscore (gambas-asn1#306)",
          r.type_name("My-Type") == "MyType",
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

    // emit_enumerated_declaration/cpp: first real construct pair. Same
    // EnumeratedSpec, two genuinely different real outputs — not a
    // stub/placeholder on either side.
    {
        EnumeratedSpec spec;
        spec.type_name = "MyEnum";
        spec.xer_name  = "MyEnum";
        spec.values    = {{"foo", 0}, {"bar", 1}};
        spec.extensible = false;
        spec.root_count  = 2;

        TypeOutputSession cpp_session, rust_session;
        c.emit_enumerated(spec, cpp_session);
        r.emit_enumerated(spec, rust_session);
        std::string cpp_hpp = buf_str(cpp_session, c.declaration_extension());
        std::string cpp_cpp = buf_str(cpp_session, c.definition_extension());
        std::string rust_hpp = buf_str(rust_session, r.declaration_extension());
        std::string rust_cpp = buf_str(rust_session, r.definition_extension());

        check("emit_enumerated: C++ produces a class",
              cpp_hpp.find("class MyEnum") != std::string::npos,
              cpp_hpp);
        check("emit_enumerated: Rust produces a real enum (not a stub)",
              rust_hpp.find("pub enum MyEnum") != std::string::npos,
              rust_hpp);
        check("emit_enumerated: Rust variants use declared values, UpperCamelCase",
              rust_hpp.find("Foo = 0") != std::string::npos &&
              rust_hpp.find("Bar = 1") != std::string::npos,
              rust_hpp);
        check("emit_enumerated: C++ produces EnumSpec + TypeDescriptor",
              cpp_cpp.find("asn_SPC") != std::string::npos &&
              cpp_cpp.find("asn_DEF") != std::string::npos,
              cpp_cpp);
        check("emit_enumerated: Rust produces a value-lookup impl",
              rust_cpp.find("impl std::convert::TryFrom<i64> for MyEnum") != std::string::npos &&
              rust_cpp.find("0 => Ok(MyEnum::Foo)") != std::string::npos,
              rust_cpp);
    }

    // emit_integer_declaration/cpp: second real construct pair. Constrained INTEGER
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

        TypeOutputSession cpp_session, rust_session;
        c.emit_integer(spec, cpp_session);
        r.emit_integer(spec, rust_session);
        std::string cpp_hpp = buf_str(cpp_session, c.declaration_extension());
        std::string cpp_cpp = buf_str(cpp_session, c.definition_extension());
        std::string rust_hpp = buf_str(rust_session, r.declaration_extension());
        std::string rust_cpp = buf_str(rust_session, r.definition_extension());

        check("native_int_type: C++ maps U64 to asn1::UInteger",
              c.native_int_type(IntStorageKind::U64) == "asn1::UInteger",
              c.native_int_type(IntStorageKind::U64));
        check("native_int_type: Rust maps U64 to u64",
              r.native_int_type(IntStorageKind::U64) == "u64",
              r.native_int_type(IntStorageKind::U64));
        check("emit_integer: C++ produces a using-alias to asn1::UInteger",
              cpp_hpp.find("using MyInt = asn1::UInteger;") != std::string::npos,
              cpp_hpp);
        check("emit_integer: Rust produces a real type alias (not a stub)",
              rust_hpp.find("pub type MyInt = u64;") != std::string::npos,
              rust_hpp);
        check("emit_integer: C++ produces a Constraints-bearing TypeDescriptor",
              cpp_cpp.find("asn_DEF_MyInt") != std::string::npos &&
              cpp_cpp.find(".range_bits=7") != std::string::npos,
              cpp_cpp);
        check("emit_integer: Rust produces a real range-check function",
              rust_cpp.find("pub fn my_int_in_range(v: i64) -> bool {") != std::string::npos &&
              rust_cpp.find("v >= 0 && v <= 100") != std::string::npos,
              rust_cpp);
    }

    // Regression: BuiltinAliasSpec must distinguish "has a SIZE constraint at
    // all" (has_size_constraint) from "has a finite upper bound"
    // (size_bounded) — SIZE(5..MAX) is semi-constrained, has_size_constraint
    // but not size_bounded. A prior version conflated the two and always set
    // SIZE_CONSTRAINED whenever a SIZE clause was present at all, even
    // semi-constrained ones (caught while designing the Rust builtin-alias
    // pairing, before it was exercised by any real schema).
    {
        BuiltinAliasSpec bounded;
        bounded.type_name = "Bounded";
        bounded.xer_name  = "Bounded";
        bounded.builtin_type = asn1::ast::BuiltinType::OctetString;
        bounded.has_size_constraint = true;
        bounded.size_bounded = true;
        bounded.size_range_bits = 4;
        bounded.size_lower = 1;
        bounded.size_upper = 10;
        bounded.extensible = false;

        BuiltinAliasSpec semi = bounded;
        semi.type_name = "Semi";
        semi.xer_name  = "Semi";
        semi.size_bounded = false;
        // size_upper deliberately left at the bounded value (10) here to
        // prove the fix checks size_bounded, not size_upper's value.

        TypeOutputSession bounded_session, semi_session;
        c.emit_builtin_alias(bounded, bounded_session);
        c.emit_builtin_alias(semi, semi_session);
        std::string bounded_os = buf_str(bounded_session, c.definition_extension());
        std::string semi_os = buf_str(semi_session, c.definition_extension());

        // Extract the ".flags=N" integer from each TypeDescriptor's constraints line.
        auto extract_flags = [](const std::string& s) -> std::string {
            auto pos = s.find(".flags=");
            if (pos == std::string::npos) return "";
            pos += 7;
            auto end = s.find_first_of(",}", pos);
            return s.substr(pos, end - pos);
        };
        std::string bounded_flags = extract_flags(bounded_os);
        std::string semi_flags    = extract_flags(semi_os);
        check("BuiltinAliasSpec: bounded vs semi-constrained SIZE produce different flags",
              !bounded_flags.empty() && !semi_flags.empty() && bounded_flags != semi_flags,
              "bounded=" + bounded_flags + " semi=" + semi_flags);
    }

    // emit_builtin_alias_definition: fourth real construct pair (builtin-alias).
    // Bounded SIZE constraint on an OCTET STRING.
    {
        BuiltinAliasSpec spec;
        spec.type_name = "MyBytes";
        spec.xer_name  = "MyBytes";
        spec.builtin_type = asn1::ast::BuiltinType::OctetString;
        spec.has_size_constraint = true;
        spec.size_bounded = true;
        spec.size_range_bits = 4;
        spec.size_lower = 1;
        spec.size_upper = 10;
        spec.extensible = false;

        TypeOutputSession cpp_session, rust_session;
        c.emit_builtin_alias(spec, cpp_session);
        r.emit_builtin_alias(spec, rust_session);
        std::string cpp_os = buf_str(cpp_session, c.definition_extension());
        std::string rust_os = buf_str(rust_session, r.definition_extension());

        check("native_int_type is unrelated; emit_builtin_alias: C++ produces a TypeDescriptor",
              cpp_os.find("asn_DEF_MyBytes") != std::string::npos,
              cpp_os);
        check("emit_builtin_alias: Rust produces a real newtype wrapper (not a plain alias)",
              rust_os.find("pub struct MyBytes(pub asn1cpp_ber::octet_string::OctetString);") != std::string::npos,
              rust_os);
        check("emit_builtin_alias: Rust newtype's own Asn1Value impl reports its own XER element name",
              rust_os.find("impl asn1cpp_ber::value::Asn1Value for MyBytes {") != std::string::npos &&
              rust_os.find("\"MyBytes\"") != std::string::npos,
              rust_os);
        check("emit_builtin_alias: Rust produces a real size-check function",
              rust_os.find("pub fn my_bytes_size_ok(v: &asn1cpp_ber::octet_string::OctetString) -> bool {") != std::string::npos &&
              rust_os.find("(v.len() as i64) >= 1 && (v.len() as i64) <= 10") != std::string::npos,
              rust_os);
    }

    // emit_default_setter / emit_member_type_descriptor: fifth real
    // construct pair (shared member-emission helpers, #229/#237).
    {
        DefaultValueSpec spec;
        spec.kind = DefaultValueSpec::Kind::Int;
        spec.int_val = 42;

        TypeOutputSession cpp_session, rust_session;
        c.emit_default_setter(spec, "int64_t", "MySeq", "myField", cpp_session);
        r.emit_default_setter(spec, "i64", "MySeq", "myField", rust_session);
        std::string cpp_os = buf_str(cpp_session, c.definition_extension());
        std::string rust_os = buf_str(rust_session, r.definition_extension());

        check("emit_default_setter: C++ produces a setter/checker pair",
              cpp_os.find("_setdef_MySeq_myField") != std::string::npos &&
              cpp_os.find("_isdef_MySeq_myField") != std::string::npos,
              cpp_os);
        check("emit_default_setter: Rust produces a real accessor function (not a stub)",
              rust_os.find("pub fn my_seq_myField_default() -> i64 {") != std::string::npos &&
              rust_os.find("42") != std::string::npos,
              rust_os);
    }
    {
        MemberTypeDescriptorSpec spec;
        spec.kind = MemberTypeDescriptorSpec::Kind::Integer;
        spec.tname = "asn_TYP_MySeq_myField";
        spec.storage_kind = IntStorageKind::S64;
        spec.extensible = false;
        spec.semi_constrained = false;
        spec.hi_is_large = false;
        spec.range_bits = 7;
        spec.lower_s64 = 0;
        spec.upper_s64 = 100;
        spec.lower_u64 = 0;
        spec.upper_u64 = 100;
        spec.xer_type_name = "INTEGER";
        spec.universal_tag = 2;

        TypeOutputSession cpp_session, rust_session;
        c.emit_member_type_descriptor(spec, cpp_session);
        r.emit_member_type_descriptor(spec, rust_session);
        std::string cpp_os = buf_str(cpp_session, c.definition_extension());
        std::string rust_os = buf_str(rust_session, r.definition_extension());

        check("emit_member_type_descriptor: C++ produces a TypeDescriptor",
              cpp_os.find("asn_TYP_MySeq_myField") != std::string::npos,
              cpp_os);
        check("emit_member_type_descriptor: Rust produces a real range-check function",
              rust_os.find("pub fn asn_typ_my_seq_my_field_range_delta(v: i64) -> i64 { "
                            "asn1cpp_ber::integer::range_delta_i64(v, false, false, 0, 100) }") != std::string::npos,
              rust_os);
    }

    // emit_seq_of_definition: sixth real construct pair (SEQUENCE OF, #230/#238).
    // Bounded SIZE(1..10) collection.
    {
        SeqOfSpec spec;
        spec.type_name = "MyList";
        spec.xer_name  = "MyList";
        spec.elem_type = "Elem";
        spec.elem_ref  = "&asn_DEF_Elem";
        spec.range_bits = 4;
        spec.size_lower = 1;
        spec.size_upper = 10;
        spec.is_set_of = false;

        TypeOutputSession cpp_session, rust_session;
        c.emit_seq_of(spec, cpp_session);
        r.emit_seq_of(spec, rust_session);
        std::string cpp_os = buf_str(cpp_session, c.definition_extension());
        std::string rust_os = buf_str(rust_session, r.definition_extension());

        check("emit_seq_of: C++ produces a SeqOfSpec + TypeDescriptor",
              cpp_os.find("asn_SPC_MyList") != std::string::npos &&
              cpp_os.find("asn_DEF_MyList") != std::string::npos,
              cpp_os);
        check("emit_seq_of: Rust produces a real generic size-check function",
              rust_os.find("pub fn my_list_size_ok<T>(v: &Vec<T>) -> bool {") != std::string::npos &&
              rust_os.find("(v.len() as i64) >= 1 && (v.len() as i64) <= 10") != std::string::npos,
              rust_os);
    }

    // emit_sequence_declaration/cpp: seventh real construct pair (SEQUENCE, #231/#239).
    // One required INTEGER member, one optional String member.
    {
        SequenceSpec spec;
        spec.type_name = "MySeq";
        spec.xer_name  = "MySeq";
        spec.has_optional_members = true;
        spec.mcount = 2;
        spec.ext_at = -1;
        spec.roms_count = 1;
        spec.is_set = false;

        SequenceMemberSpec req;
        req.asn1_name = "count";
        req.mtype = "int64_t";
        req.mname = "count";
        req.resolved_tag = MemberTagSpec{ TypeTagSpec{asn1::ast::TagClass::Universal, 2, false}, false };
        req.optional = false;
        req.tdref = "&asn_DEF_MyInt";
        req.def_setter = "nullptr";
        spec.members.push_back(req);

        SequenceMemberSpec opt;
        opt.asn1_name = "label";
        opt.mtype = "String";
        opt.mname = "label";
        opt.resolved_tag = MemberTagSpec{ TypeTagSpec{asn1::ast::TagClass::Universal, 12, false}, false };
        opt.optional = true;
        opt.tdref = "&asn_DEF_Utf8String";
        opt.def_setter = "nullptr";
        spec.members.push_back(opt);

        TypeOutputSession cpp_session, rust_session;
        c.emit_sequence(spec, cpp_session);
        r.emit_sequence(spec, rust_session);
        std::string cpp_hpp = buf_str(cpp_session, c.declaration_extension());
        std::string cpp_cpp = buf_str(cpp_session, c.definition_extension());
        std::string rust_hpp = buf_str(rust_session, r.declaration_extension());
        std::string rust_cpp = buf_str(rust_session, r.definition_extension());

        check("emit_sequence: C++ produces a class with a unique_ptr optional member",
              cpp_hpp.find("class MySeq : public asn1::SequenceBase<MySeq>") != std::string::npos &&
              cpp_hpp.find("std::unique_ptr<String> label;") != std::string::npos,
              cpp_hpp);
        check("emit_sequence: C++ produces a member descriptor table",
              cpp_cpp.find("const asn1::MemberDescriptor MySeq::s_members[]") != std::string::npos,
              cpp_cpp);
        check("emit_sequence: Rust produces a real struct with Option<T> for the optional member",
              rust_hpp.find("pub struct MySeq {") != std::string::npos &&
              rust_hpp.find("pub count: int64_t,") != std::string::npos &&
              rust_hpp.find("pub label: Option<String>,") != std::string::npos,
              rust_hpp);
        check("emit_sequence: Rust produces a real impl block with new()",
              rust_cpp.find("impl MySeq {") != std::string::npos &&
              rust_cpp.find("Self::default()") != std::string::npos,
              rust_cpp);
    }

    // emit_choice_declaration/cpp: eighth real construct pair (CHOICE, #232/#240).
    // Two alternatives: an INTEGER and a String.
    {
        ChoiceSpec spec;
        spec.type_name = "MyChoice";
        spec.xer_name  = "MyChoice";
        spec.count = 2;
        spec.ext_at = -1;

        ChoiceAlternativeSpec num;
        num.mtype = "int64_t";
        num.accessor_name = "num";
        num.pr_name = "Num";
        num.asn1_name = "num";
        num.resolved_tag = MemberTagSpec{ TypeTagSpec{asn1::ast::TagClass::Universal, 2, false}, false };
        num.tdref = "&asn_DEF_MyInt";
        spec.alternatives.push_back(num);

        ChoiceAlternativeSpec label;
        label.mtype = "String";
        label.accessor_name = "label";
        label.pr_name = "Label";
        label.asn1_name = "label";
        label.resolved_tag = MemberTagSpec{ TypeTagSpec{asn1::ast::TagClass::Universal, 12, false}, false };
        label.tdref = "&asn_DEF_Utf8String";
        spec.alternatives.push_back(label);

        TypeOutputSession cpp_session, rust_session;
        c.emit_choice(spec, cpp_session);
        r.emit_choice(spec, rust_session);
        std::string cpp_hpp = buf_str(cpp_session, c.declaration_extension());
        std::string cpp_cpp = buf_str(cpp_session, c.definition_extension());
        std::string rust_hpp = buf_str(rust_session, r.declaration_extension());
        std::string rust_cpp = buf_str(rust_session, r.definition_extension());

        check("emit_choice: C++ produces a ChoiceInterface-derived class",
              cpp_hpp.find("class MyChoice : public asn1::ChoiceInterface") != std::string::npos &&
              cpp_hpp.find("enum class PR : int { NOTHING = 0, Num = 1, Label = 2 };") != std::string::npos,
              cpp_hpp);
        check("emit_choice: C++ produces an alternatives table",
              cpp_cpp.find("const asn1::MemberDescriptor MyChoice::s_alternatives[]") != std::string::npos,
              cpp_cpp);
        check("emit_choice: Rust produces a real enum with variant payloads (not a stub)",
              rust_hpp.find("pub enum MyChoice {") != std::string::npos &&
              rust_hpp.find("Num(int64_t),") != std::string::npos &&
              rust_hpp.find("Label(String),") != std::string::npos,
              rust_hpp);
        check("emit_choice: Rust produces real exhaustive-match accessor functions",
              rust_cpp.find("pub fn my_choice_get_num(x: &mut MyChoice) -> &mut int64_t {") != std::string::npos &&
              rust_cpp.find("match x { MyChoice::Num(v) => v, _ => panic!(\"wrong variant\") }") != std::string::npos &&
              rust_cpp.find("pub fn my_choice_get_label(x: &mut MyChoice) -> &mut String {") != std::string::npos,
              rust_cpp);
    }

    // emit_declaration_preamble/emit_definition_preamble/emit_namespace_open/close +
    // emit_builtin_alias_declaration/emit_seq_of_declaration/emit_typeref_alias_declaration: ninth
    // real construct pair (top-level dispatch, #233/#241) — closes out the
    // Rust side of #225.
    {
        TypeOutputSession cpp_pre, rust_pre;
        c.emit_declaration_preamble("MyModule { 1 2 3 }", cpp_pre);
        c.emit_definition_preamble("MyType", cpp_pre);
        r.emit_declaration_preamble("MyModule { 1 2 3 }", rust_pre);
        r.emit_definition_preamble("MyType", rust_pre);
        std::string cpp_hpp_pre = buf_str(cpp_pre, c.declaration_extension());
        std::string cpp_cpp_pre = buf_str(cpp_pre, c.definition_extension());
        std::string rust_hpp_pre = buf_str(rust_pre, r.declaration_extension());

        check("emit_declaration_preamble: C++ produces a module comment + pragma once",
              cpp_hpp_pre.find("// Module: MyModule { 1 2 3 }") != std::string::npos &&
              cpp_hpp_pre.find("#pragma once") != std::string::npos,
              cpp_hpp_pre);
        check("emit_declaration_preamble: Rust produces a real doc comment (not a stub)",
              rust_hpp_pre.find("//! Module: MyModule { 1 2 3 }") != std::string::npos,
              rust_hpp_pre);
        check("emit_definition_preamble: C++ produces an #include for the paired header",
              cpp_cpp_pre.find("#include \"MyType.hpp\"") != std::string::npos,
              cpp_cpp_pre);

        TypeOutputSession cpp_ns, rust_ns;
        c.emit_namespace_open("myns", cpp_ns);
        c.emit_namespace_close("myns", cpp_ns);
        r.emit_namespace_open("myns", rust_ns);
        r.emit_namespace_close("myns", rust_ns);
        std::string cpp_ns_hpp = buf_str(cpp_ns, c.declaration_extension());
        std::string rust_ns_hpp = buf_str(rust_ns, r.declaration_extension());

        check("emit_namespace_open/close: C++ produces a namespace block",
              cpp_ns_hpp.find("namespace myns {") != std::string::npos &&
              cpp_ns_hpp.find("} // namespace myns") != std::string::npos,
              cpp_ns_hpp);
        check("emit_namespace_open/close: Rust produces a real mod block (not a stub)",
              rust_ns_hpp.find("pub mod myns {") != std::string::npos,
              rust_ns_hpp);

        BuiltinAliasSpec alias_spec;
        alias_spec.type_name = "MyBytes2";
        alias_spec.builtin_type = asn1::ast::BuiltinType::OctetString;
        TypeOutputSession cpp_alias, rust_alias;
        c.emit_builtin_alias(alias_spec, cpp_alias);
        r.emit_builtin_alias(alias_spec, rust_alias);
        std::string cpp_alias_hpp = buf_str(cpp_alias, c.declaration_extension());
        check("emit_builtin_alias: C++ declaration half produces a using-alias + extern descriptor",
              cpp_alias_hpp.find("using MyBytes2 = asn1::OctetString;") != std::string::npos &&
              cpp_alias_hpp.find("extern const asn1::TypeDescriptor asn_DEF_MyBytes2;") != std::string::npos,
              cpp_alias_hpp);

        SeqOfSpec seqof_spec;
        seqof_spec.type_name = "MyList2";
        seqof_spec.elem_type = "i64";
        TypeOutputSession cpp_seqof, rust_seqof;
        c.emit_seq_of(seqof_spec, cpp_seqof);
        r.emit_seq_of(seqof_spec, rust_seqof);
        std::string cpp_seqof_hpp = buf_str(cpp_seqof, c.declaration_extension());
        std::string rust_seqof_hpp = buf_str(rust_seqof, r.declaration_extension());
        check("emit_seq_of: C++ declaration half produces a VectorSeqOf using-alias",
              cpp_seqof_hpp.find("using MyList2 = asn1::VectorSeqOf<i64>;") != std::string::npos,
              cpp_seqof_hpp);
        check("emit_seq_of: Rust declaration half produces a real newtype wrapping Vec<T> (not a stub)",
              rust_seqof_hpp.find("pub struct MyList2(pub Vec<i64>);") != std::string::npos,
              rust_seqof_hpp);

        TypeOutputSession cpp_tr, rust_tr;
        c.emit_typeref_alias_declaration("MyAlias", "OtherType", cpp_tr);
        r.emit_typeref_alias_declaration("MyAlias", "OtherType", rust_tr);
        std::string cpp_tr_hpp = buf_str(cpp_tr, c.declaration_extension());
        std::string rust_tr_hpp = buf_str(rust_tr, r.declaration_extension());
        check("emit_typeref_alias_declaration: C++ produces a using-alias",
              cpp_tr_hpp == "using MyAlias = OtherType;\n",
              cpp_tr_hpp);
        check("emit_typeref_alias_declaration: Rust produces a real pub type alias (not a stub)",
              rust_tr_hpp == "pub type MyAlias = OtherType;\n",
              rust_tr_hpp);
    }

    // declaration_extension/definition_extension (#262): Backend decides
    // file identity — CppBackend keeps the two-file hpp/cpp split;
    // RustBackend returns the same extension for both, which merges them
    // into one file via TypeOutputSession (no separate merge flag).
    {
        check("declaration_extension/definition_extension: C++ requests a two-file hpp/cpp split",
              c.declaration_extension() == "hpp" && c.definition_extension() == "cpp",
              c.declaration_extension() + " / " + c.definition_extension());
        check("declaration_extension/definition_extension: Rust requests the same extension for both (merges)",
              r.declaration_extension() == "rs" && r.definition_extension() == "rs",
              r.declaration_extension() + " / " + r.definition_extension());

        TypeOutputSession session;
        session.buffer("rs") << "decl content ";
        session.buffer("rs") << "def content";
        auto merged = session.finish();
        check("TypeOutputSession: same extension merges into one buffer",
              merged.size() == 1 && merged[0].first == "rs" &&
              merged[0].second == "decl content def content",
              merged.empty() ? "" : merged[0].second);

        TypeOutputSession session2;
        session2.buffer("hpp") << "decl";
        session2.buffer("cpp") << "def";
        auto split = session2.finish();
        check("TypeOutputSession: different extensions stay separate",
              split.size() == 2 && split[0].first == "hpp" && split[0].second == "decl" &&
              split[1].first == "cpp" && split[1].second == "def",
              std::to_string(split.size()));
    }

    // gambas-asn1#290: format_tag_literal used to be a CppBackend-only free
    // function Generator called unconditionally — RustBackend must produce
    // real Rust syntax here, not throw, or every SEQUENCE/CHOICE member's
    // eff_tag computation breaks under --target=rust.
    {
        TypeTagSpec universal{asn1::ast::TagClass::Universal, 2, false};
        check("format_tag_literal: CppBackend universal tag",
              c.format_tag_literal(universal) == "asn1::Tag{asn1::TagClass::Universal, 2, false}",
              c.format_tag_literal(universal));
        check("format_tag_literal: RustBackend universal tag",
              r.format_tag_literal(universal) ==
                  "asn1cpp_ber::tag::Tag { class: asn1cpp_ber::tag::TagClass::Universal, number: 2, constructed: false }",
              r.format_tag_literal(universal));

        TypeTagSpec context_explicit{asn1::ast::TagClass::Context, 1, true};
        check("format_tag_literal: CppBackend context/constructed tag",
              c.format_tag_literal(context_explicit) == "asn1::Tag{asn1::TagClass::Context, 1, true}",
              c.format_tag_literal(context_explicit));
        check("format_tag_literal: RustBackend context/constructed tag",
              r.format_tag_literal(context_explicit) ==
                  "asn1cpp_ber::tag::Tag { class: asn1cpp_ber::tag::TagClass::Context, number: 1, constructed: true }",
              r.format_tag_literal(context_explicit));

        TypeTagSpec application{asn1::ast::TagClass::Application, 5, false};
        check("format_tag_literal: CppBackend and RustBackend diverge (different syntax, same info)",
              c.format_tag_literal(application) != r.format_tag_literal(application) &&
              c.format_tag_literal(application).find("Application") != std::string::npos &&
              r.format_tag_literal(application).find("Application") != std::string::npos);
    }

    // Generator accepts an injected Backend (not just the default CppBackend)
    // — proves the seam #216 built is real, not just declared. Construction
    // only (no generate() call — that still hardcodes C++ text emission
    // until #245's CLI backend-selection flag lands; calling it with
    // RustBackend today would produce misleading non-Rust output).
    {
        asn1::sema::Resolver resolver;
        asn1::codegen::Generator gen("/tmp/rust_backend_stub_unused", resolver, rust);
        check("Generator constructs with an injected non-default Backend", true);
        (void)gen;
    }

    printf("\n%s\n", failures == 0 ? "All checks passed." : "Some checks FAILED.");
    return failures == 0 ? 0 : 1;
}
