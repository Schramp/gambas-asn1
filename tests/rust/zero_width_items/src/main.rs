// Rust leg of the PER zero-width SEQUENCE OF items test
// (zero_width_items_test.asn1); mirrors tests/per/test_zero_width_items.cpp,
// with the same UPER vectors. A list counting more than
// nesting::MAX_ZERO_WIDTH_ITEMS items is refused once an element takes no
// input (X.691 §18, §11.9.3.8); elements that take input, and many short
// lists, are not limited.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::nesting::MAX_ZERO_WIDTH_ITEMS;
use asn1cpp_wire::per::object::decode_pdu;
use asn1cpp_wire::spec::object::Asn1Pdu;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn accepts<T: Asn1Pdu + std::ops::Deref<Target = Vec<E>>, E>(label: &str, h: &str, count: usize, failures: &mut i32) {
    let r = decode_pdu::<T>(&unhex(h));
    check(&format!("{label} decodes to {count} items"), r.is_ok_and(|v| v.len() == count), failures);
}

fn refuses<T: Asn1Pdu>(label: &str, h: &str, failures: &mut i32) {
    let r = decode_pdu::<T>(&unhex(h));
    check(
        &format!("{label} is refused as zero-width items"),
        r.is_err_and(|e| e.message.contains("items encoded in zero bits")),
        failures,
    );
}

fn main() {
    let mut failures = 0;
    println!("=== PER zero-width SEQUENCE OF items (limit {MAX_ZERO_WIDTH_ITEMS}) ===");
    accepts::<Nulls::Nulls, _>("Nulls, 200 NULLs", "80c8", 200, &mut failures);
    refuses::<Nulls::Nulls>("Nulls, 201 NULLs", "80c9", &mut failures);
    refuses::<Nulls::Nulls>("Nulls, 100 fragments of 64K NULLs", &format!("{}00", "c4".repeat(100)), &mut failures);
    accepts::<Fives::Fives, _>("Fives, 200 single-value INTEGERs", "00c8", 200, &mut failures);
    refuses::<Fives::Fives>("Fives, 60000 single-value INTEGERs", "ea60", &mut failures);
    accepts::<Flags::Flags, _>("Flags, 1000 one-bit BOOLEANs", &format!("83e8{}", "ff".repeat(125)), 1000, &mut failures);
    accepts::<Rows::Rows, _>("Rows, 300 lists of 200 NULLs", &format!("812c{}", "80c8".repeat(300)), 300, &mut failures);
    accepts::<Rows::Rows, _>("Rows, 201 empty lists", &format!("80c9{}", "00".repeat(201)), 201, &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
