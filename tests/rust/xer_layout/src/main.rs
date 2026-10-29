// Rust leg of the XER layout test (xer_layout_test.asn1); mirrors
// tests/seq/test_xer_layout.cpp. Each case decodes a DER record produced by
// asn1c's converter-example and compares the XER text, whitespace included,
// with asn1c's own XER for that record.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::{ber, xer};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn same(got: &str, want: &str) -> bool {
    if got != want {
        println!("        want:\n{want}\n        got:\n{got}");
    }
    got == want
}

fn main() {
    let mut f = 0;
    println!("=== XER layout: root CHOICE ===");

    let cases: &[(&str, &[u8], &str)] = &[
        ("root CHOICE, INTEGER alternative", &[0x80, 0x01, 0x05], "<XlRoot>\n    <num>5</num>\n</XlRoot>\n"),
        (
            "root CHOICE, SEQUENCE alternative",
            &[0xa1, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0xff],
            "<XlRoot>\n    <rec>\n        <a>1</a>\n        <b><true/></b>\n    </rec>\n</XlRoot>\n",
        ),
        (
            "root CHOICE, CHOICE alternative",
            &[0xa2, 0x03, 0x81, 0x01, 0x00],
            "<XlRoot>\n    <sub>\n        <y><false/></y>\n    </sub>\n</XlRoot>\n",
        ),
        (
            "root CHOICE, SEQUENCE OF alternative",
            &[0xa3, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            "<XlRoot>\n    <list>\n        <INTEGER>1</INTEGER>\n        <INTEGER>2</INTEGER>\n    </list>\n</XlRoot>\n",
        ),
        ("root CHOICE, ENUMERATED alternative", &[0x84, 0x01, 0x01], "<XlRoot>\n    <color><green/></color>\n</XlRoot>\n"),
        ("root CHOICE, UTF8String alternative", &[0x85, 0x02, 0x68, 0x69], "<XlRoot>\n    <text>hi</text>\n</XlRoot>\n"),
    ];
    for (label, der, want) in cases {
        let Ok(v) = ber::object::decode_pdu::<XlRoot::XlRoot>(der) else {
            check(label, false, &mut f);
            continue;
        };
        let text = xer::object::encode_pdu(&v).unwrap_or_default();
        check(label, same(&text, want), &mut f);
        check("  XER round-trip", xer::object::decode_pdu::<XlRoot::XlRoot>(&text).is_ok_and(|b| b == v), &mut f);
    }

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
