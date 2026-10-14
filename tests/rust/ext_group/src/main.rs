// Rust leg of the extension addition group test (per_ext_group_test.asn1,
// X.691 §18.9); mirrors tests/seq/test_ext_group.cpp with asn1c's UPER
// bytes for each value.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::boolean::Boolean;
use asn1cpp_wire::integer::Integer;
use Rec::Rec as RecT;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn make(before: Option<bool>, g1: Option<i64>, g2: Option<bool>, after: Option<i64>) -> RecT {
    RecT {
        id: Integer(39),
        before: before.map(Boolean),
        g1: g1.map(Integer),
        g2: g2.map(Boolean),
        after: after.map(Integer),
        ..Default::default()
    }
}

fn main() {
    let mut failures = 0;
    let cases: [(&str, Vec<u8>, RecT); 4] = [
        ("no extensions", vec![0x13, 0x80], make(None, None, None, None)),
        ("before, group {g1}, after", vec![0x93, 0x82, 0xe0, 0x30, 0x00, 0x27, 0x00, 0x30, 0x00],
         make(Some(true), Some(7), None, Some(2))),
        ("group {g1, g2} only", vec![0x93, 0x82, 0x40, 0x37, 0x80], make(None, Some(7), Some(true), None)),
        ("after only", vec![0x93, 0x82, 0x20, 0x28, 0x00], make(None, None, None, Some(1))),
    ];
    for (label, bytes, value) in &cases {
        check(&format!("encode: {label}"), asn1cpp_wire::per::object::encode_pdu(value) == *bytes, &mut failures);
        let back = asn1cpp_wire::per::object::decode_pdu::<RecT>(bytes);
        check(&format!("decode: {label}"), back.as_ref().is_ok_and(|b| b == value), &mut failures);
    }
    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
