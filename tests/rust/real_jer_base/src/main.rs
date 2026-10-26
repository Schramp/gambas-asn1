// Rust leg of the REAL JER base-constraint test (real_jer_base_test.asn1,
// X.697 §23.1.3/§23.1.4); mirrors tests/jer/test_real_jer_base.cpp.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::real::{Real, Storage};
use Bases::Bases as Rec;

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
    println!("=== REAL JER base constraints ===");
    let d = Real::decimal(false, "1456", -2);
    let v = Rec {
        b10: Base10::Base10(d.clone()),
        b2: Base2::Base2(d.clone()),
        inline: d.clone(),
        x697: d.clone(),
        both: d.clone(),
        plain: d.clone(),
    };
    let json: String = asn1cpp_wire::jer::object::encode_pdu(&v).unwrap_or_default().chars().filter(|c| !c.is_whitespace()).collect();
    println!("        {json}");
    check("base (10): bare JSON number", json.contains("\"b10\":1456E-2,"), &mut failures);
    check("inline WITH COMPONENTS base (10): bare JSON number", json.contains("\"inline\":1456E-2,"), &mut failures);
    check("X.697 example (0 | WITH COMPONENTS {... base (10) ...}): bare JSON number", json.contains("\"x697\":1456E-2,"), &mut failures);
    check("base (2): base10Value object", json.contains("\"b2\":{\"base10Value\":1456E-2}"), &mut failures);
    check("base (2..10): base10Value object", json.contains("\"both\":{\"base10Value\":1456E-2}"), &mut failures);
    check("unconstrained: base10Value object", json.contains("\"plain\":{\"base10Value\":1456E-2}"), &mut failures);

    let back = asn1cpp_wire::jer::object::decode_pdu::<Rec>(&json);
    check("every member decodes back to the same Decimal", back.is_ok_and(|b| b == v), &mut failures);

    let numbers = "{\"b10\":14.56,\"b2\":14.56,\"inline\":14.56,\"x697\":14.56,\"both\":14.56,\"plain\":14.56}";
    let n = asn1cpp_wire::jer::object::decode_pdu::<Rec>(numbers);
    check(
        "a JSON number is base 10 only where the base is constrained to 10",
        n.is_ok_and(|n| {
            n.b10.0 == d && n.inline == d && n.x697 == d && n.b2.0.storage() == Storage::Double
                && n.both.storage() == Storage::Double && n.plain.storage() == Storage::Double
        }),
        &mut failures,
    );

    let b = Rec { b10: Base10::Base10(Real::new(0.5)), ..Default::default() };
    let bj: String = asn1cpp_wire::jer::object::encode_pdu(&b).unwrap_or_default().chars().filter(|c| !c.is_whitespace()).collect();
    check("a base-2 value is a JSON number under base (10) too (§23.1.2)", bj.contains("\"b10\":0.5,"), &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
