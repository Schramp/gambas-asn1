// Rust leg of the SET component order test (per_set_order_test.asn1,
// IMPLICIT TAGS, components declared out of tag order); mirrors
// tests/seq/test_set_order.cpp.
//
//   - BER decode accepts the components in any order (X.690 §8.11.2).
//   - BER encode writes canonical tag order (X.680 §8.6; DER, X.690 §10.3).
//   - PER encodes the root components in canonical tag order (X.691 §20).
//
// Expected bytes are asn1c's DER / UPER output for the same value
// (third = 2, first = FALSE, zeroth = 199, second absent).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use Rec::Rec as RecT;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn is_expected(v: &RecT) -> bool {
    v.third.0 == 2 && !v.first.0 && v.zeroth.0 == 199 && v.second.is_none()
}

fn main() {
    let declaration_order = [0x31, 0x0a, 0x83, 0x01, 0x02, 0x81, 0x01, 0x00, 0x80, 0x02, 0x00, 0xc7];
    let canonical_order = [0x31, 0x0a, 0x80, 0x02, 0x00, 0xc7, 0x81, 0x01, 0x00, 0x83, 0x01, 0x02];
    let mut failures = 0;

    let a = asn1cpp_wire::ber::object::decode_pdu::<RecT>(&declaration_order);
    check("BER decode, declaration order", a.as_ref().is_ok_and(is_expected), &mut failures);
    let b = asn1cpp_wire::ber::object::decode_pdu::<RecT>(&canonical_order);
    check("BER decode, canonical order", b.as_ref().is_ok_and(is_expected), &mut failures);
    if let Ok(v) = &a {
        check("BER encode writes canonical order (asn1c DER)",
              asn1cpp_wire::ber::object::encode_pdu(v) == canonical_order, &mut failures);
        check("PER encodes root components in canonical order (asn1c UPER 63 90)",
              asn1cpp_wire::per::object::encode_pdu(v) == vec![0x63, 0x90], &mut failures);
    }

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
