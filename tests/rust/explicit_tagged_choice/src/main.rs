// Rust leg of the EXPLICIT-tagged CHOICE test (explicit_tagged_choice_test.asn1,
// EXPLICIT TAGS). `Own ::= [5] CHOICE`, so `tagged [4] Own` wraps the
// CHOICE's whole encoding, its own [5] included (X.680 §30.6,
// X.690 §8.14.3): A4 05 A5 03 01 01 FF.
//
// Expected bytes are asn1c's DER for
// { own i:300, tagged b:TRUE, n NULL }.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use HoldsOwn::HoldsOwn as HoldsOwnT;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    let der = [
        0x30, 0x0f, 0xa5, 0x04, 0x02, 0x02, 0x01, 0x2c, 0xa4, 0x05, 0xa5, 0x03, 0x01, 0x01, 0xff, 0x05, 0x00,
    ];
    let mut failures = 0;

    let v = asn1cpp_wire::ber::object::decode_pdu::<HoldsOwnT>(&der);
    check("BER decode keeps the CHOICE's own tag under the EXPLICIT tag", v.is_ok(), &mut failures);
    if let Ok(v) = &v {
        check("BER encode matches asn1c DER",
              asn1cpp_wire::ber::object::encode_pdu(v).unwrap() == der, &mut failures);
    }

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
