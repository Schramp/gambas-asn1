// Rust leg of the JER null-for-absent-member test (jer_null_absent_test.asn1,
// X.697 §27.3.4); mirrors tests/jer/test_jer_null_absent.cpp.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::jer::object::{decode_pdu, encode_pdu};
use JnRec::JnRec as Rec;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    let mut f = 0;
    println!("=== JER null for absent members (X.697 §27.3.4) ===");

    let r = decode_pdu::<Rec>(r#"{"a":1,"b":null,"c":null,"o":null,"s":null}"#);
    check("null for OPTIONAL INTEGER/OCTET STRING/SEQUENCE and DEFAULT BOOLEAN decodes", r.is_ok(), &mut f);
    let r = r.ok();
    check(
        "null OPTIONAL members are absent",
        r.as_ref().is_some_and(|r| r.b.is_none() && r.o.is_none() && r.s.is_none()),
        &mut f,
    );
    check(
        "null DEFAULT member takes its default",
        r.as_ref().is_some_and(|r| r.c.as_ref().is_some_and(|c| c.0)),
        &mut f,
    );
    // An absent DEFAULT member decodes to its default value, as in BER and
    // PER, so only the OPTIONAL members are certain to be left out.
    check(
        "absent OPTIONAL members are left out on re-encode",
        r.as_ref().is_some_and(|r| {
            encode_pdu(r).is_ok_and(|t| !t.contains("\"b\"") && !t.contains("\"o\"") && !t.contains("\"s\"") && !t.contains("null"))
        }),
        &mut f,
    );

    let w = decode_pdu::<Rec>(r#"{ "a" : 2 , "b" : null , "n" : null }"#);
    check("null with surrounding whitespace decodes", w.as_ref().is_ok_and(|w| w.b.is_none()), &mut f);
    check("null for NULL OPTIONAL is the NULL value, so present", w.as_ref().is_ok_and(|w| w.n.is_some()), &mut f);

    check("null for a mandatory member is an error", decode_pdu::<Rec>(r#"{"a":null}"#).is_err(), &mut f);
    check("nullx is not null", decode_pdu::<Rec>(r#"{"a":1,"b":nullx}"#).is_err(), &mut f);

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
