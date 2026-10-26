// Rust leg of the REAL DEFAULT test (real_default_test.asn1); mirrors
// tests/seq/test_real_default.cpp. Defaults has five DEFAULT REAL members
// and a mandatory `tag` INTEGER.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::real::Real;
use Defaults::Defaults as Rec;

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
    println!("=== REAL DEFAULT ===");

    // SEQUENCE { tag [5] 7 }: every DEFAULT member absent.
    let only_tag = [0x30u8, 0x03, 0x85, 0x01, 0x07];
    let d = asn1cpp_wire::ber::object::decode_pdu::<Rec>(&only_tag);
    check("decode with every DEFAULT absent", d.is_ok(), &mut failures);
    let d = d.unwrap_or_default();
    check("kilo reads as 1.5E3", d.kilo == Some(Real::new(1500.0)), &mut failures);
    check("two reads as 2", d.two.as_ref().is_some_and(|t| t.0 == Real::new(2.0)), &mut failures);
    check("inf reads as PLUS-INFINITY", d.inf == Some(Real::new(f64::INFINITY)), &mut failures);
    check("negInf reads as MINUS-INFINITY", d.negInf == Some(Real::new(f64::NEG_INFINITY)), &mut failures);
    check("zero reads as +0", d.zero == Some(Real::new(0.0)), &mut failures);

    check(
        "members equal to their defaults are not encoded",
        asn1cpp_wire::ber::object::encode_pdu(&d).is_ok_and(|b| b == only_tag),
        &mut failures,
    );

    let m = Rec { tag: Integer(7), zero: Some(Real::new(-0.0)), ..Default::default() };
    let bytes = asn1cpp_wire::ber::object::encode_pdu(&m).unwrap_or_default();
    check(
        "minus zero differs from the zero default and is encoded",
        bytes == [0x30, 0x06, 0x84, 0x01, 0x43, 0x85, 0x01, 0x07],
        &mut failures,
    );
    let back = asn1cpp_wire::ber::object::decode_pdu::<Rec>(&bytes);
    check(
        "minus zero round-trips",
        back.is_ok_and(|b| b.zero.is_some_and(|z| z.value() == 0.0 && z.value().is_sign_negative())),
        &mut failures,
    );

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
