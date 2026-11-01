// Rust leg of the PER SIZE-on-non-known-multiplier-strings test
// (per_nkm_size_test.asn1, X.691 §10.3.18, §30.6); mirrors
// tests/per/test_per_nkm_size.cpp. NKM_MODE (strict / visible / mixed) names
// the --per-nkm-size setting the generated code was built with; the expected
// bytes are the C++ leg's (Erlang/OTP for strict, asn1c otherwise).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::constraints::validate_string;
use asn1cpp_wire::per::object::{decode_pdu, encode_pdu};
use asn1cpp_wire::strings::{GeneralString, Ia5String, Utf8String};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn value() -> Rec::Rec {
    let mut r = Rec::Rec::default();
    r.s = Utf8String("ab".to_string());
    r.ext = Utf8String("abc".to_string());
    r.named = Name::Name(Utf8String("xyz".to_string()));
    r.g = GeneralString("AB".to_string());
    r.ia5 = Ia5String("hi".to_string());
    r
}

fn main() {
    let mode = std::env::var("NKM_MODE").expect("NKM_MODE must be strict, visible or mixed");
    let expected = match mode.as_str() {
        "strict" => "026162036162630378797a0241420b4690",
        "visible" => "09858804c2c4c60278797a505082d1a4",
        "mixed" => "02616203616263013c3cbd28284168d2",
        m => panic!("unknown NKM_MODE {m}"),
    };
    let mut failures = 0;
    println!("=== PER SIZE on non-known-multiplier strings: {mode} ===");
    let enc = encode_pdu(&value());
    check("encodes", enc.is_ok(), &mut failures);
    let bytes = enc.unwrap_or_default();
    check(&format!("bytes {} == {expected}", hex(&bytes)), hex(&bytes) == expected, &mut failures);
    check("round-trips", decode_pdu::<Rec::Rec>(&bytes).is_ok_and(|r| r == value()), &mut failures);

    // 40 characters exceed SIZE(0..32): carried by an unconstrained length
    // when the SIZE is not PER-visible, rejected when it is.
    let mut big = value();
    big.s = Utf8String("x".repeat(40));
    let big_enc = encode_pdu(&big);
    if mode == "visible" {
        check("40-char s rejected by the visible SIZE(0..32)", big_enc.is_err(), &mut failures);
    } else {
        check(
            "40-char s carried with an unconstrained length",
            big_enc.as_ref().is_ok_and(|b| b.len() > 40 && b[0] == 40),
            &mut failures,
        );
    }
    check(
        "validate_string still applies SIZE(0..32)",
        validate_string(&big.s.0, &Rec::REC_S_CONSTRAINTS) != 0
            && validate_string("ab", &Rec::REC_S_CONSTRAINTS) == 0,
        &mut failures,
    );

    println!("{}", if failures == 0 { "all passed" } else { "FAILED" });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
