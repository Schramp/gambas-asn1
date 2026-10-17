// Rust leg of the unknown CHOICE extension alternative test
// (per_choice_unknown_ext_test.asn1, X.691 §23.8); mirrors
// tests/seq/test_choice_unknown_ext.cpp. A MsgV2 extension alternative
// decodes as MsgV1 into its UnknownExtension variant (open-type contents
// kept); a root alternative encodes identically in both versions.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::spec::object::Asn1Choice;
use MsgV1::MsgV1 as V1;
use MsgV2::MsgV2 as V2;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    let mut failures = 0;
    let ext_bytes = asn1cpp_wire::per::object::encode_pdu(&V2::b(asn1cpp_wire::boolean::Boolean(true))).unwrap();
    let v1 = asn1cpp_wire::per::object::decode_pdu::<V1>(&ext_bytes);
    check("MsgV2 extension alternative decodes as MsgV1", v1.is_ok(), &mut failures);
    if let Ok(v) = &v1 {
        check("the unknown alternative is kept as UnknownExtension",
              matches!(v, V1::UnknownExtension(..)) && v.extract_unknown_extension().is_some(),
              &mut failures);
    }

    let root2 = asn1cpp_wire::per::object::encode_pdu(&V2::a(asn1cpp_wire::integer::Integer(5))).unwrap();
    let root1 = asn1cpp_wire::per::object::encode_pdu(&V1::a(asn1cpp_wire::integer::Integer(5))).unwrap();
    check("a root alternative encodes identically in both versions", root1 == root2, &mut failures);
    check("MsgV2 root alternative decodes as MsgV1",
          matches!(asn1cpp_wire::per::object::decode_pdu::<V1>(&root2), Ok(V1::a(asn1cpp_wire::integer::Integer(5)))),
          &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
