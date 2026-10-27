// Rust leg of the PER SIZE-violation test (per_size_violation_test.asn1,
// X.691 §10.9.4.1); mirrors tests/per/test_per_size_violation.cpp.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::bit_string::BitString;
use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::per::object::{decode_pdu, encode_pdu};
use Probe::Probe as Rec;
use ProbeLElem::ProbeLElem as Elem;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn valid() -> Rec {
    let mut p = Rec::default();
    p.s = Sized::Sized(OctetString(vec![1, 2].into()));
    p.b = Bits::Bits(BitString { bytes: vec![0xA5], unused_bits: 0 });
    p.l.push(Elem(Integer(1)));
    p.l.push(Elem(Integer(2)));
    p.tail = Integer(99);
    p
}

fn main() {
    let mut failures = 0;
    println!("=== PER: length outside a non-extensible SIZE ===");
    let ok = encode_pdu(&valid());
    check(
        "in-range value encodes and round-trips",
        ok.as_ref().is_ok_and(|b| decode_pdu::<Rec>(b).is_ok_and(|r| r == valid())),
        &mut failures,
    );

    let mut p = valid();
    p.s = Sized::Sized(OctetString(vec![0x78; 15].into()));
    check("OCTET STRING (SIZE(1..4)) with 15 octets fails", encode_pdu(&p).is_err(), &mut failures);
    p.s = Sized::Sized(OctetString(Vec::new().into()));
    check("OCTET STRING (SIZE(1..4)) with 0 octets fails", encode_pdu(&p).is_err(), &mut failures);

    let mut p = valid();
    p.b = Bits::Bits(BitString { bytes: vec![0xA5, 0x5A], unused_bits: 0 });
    check("BIT STRING (SIZE(8..12)) with 16 bits fails", encode_pdu(&p).is_err(), &mut failures);

    let mut p = valid();
    p.l.push(Elem(Integer(3)));
    p.l.push(Elem(Integer(4)));
    check("SEQUENCE (SIZE(2..3)) OF with 4 elements fails", encode_pdu(&p).is_err(), &mut failures);
    let mut q = valid();
    q.l.truncate(1);
    check("SEQUENCE (SIZE(2..3)) OF with 1 element fails", encode_pdu(&q).is_err(), &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
