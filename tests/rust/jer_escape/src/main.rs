// Rust leg of the JER string-escape test (jer_escape_test.asn1, RFC 8259
// §7, X.697 §23.4 NOTE); mirrors tests/jer/test_jer_escape.cpp.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::jer::object::{decode_pdu, encode_pdu};
use asn1cpp_wire::strings::Utf8String;
use JeRec::JeRec as Rec;
use JeRecAlt::JeRecAlt as Alt;

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
    println!("=== JER string escapes ===");
    let vecs: &[(&str, &str, Option<&[u8]>)] = &[
        ("\\u0041 is A", r"A", Some(b"A")),
        ("\\u00e9 is UTF-8 C3 A9", r"é", Some(b"\xC3\xA9")),
        ("\\u20AC (upper-case hex) is UTF-8 E2 82 AC", r"€", Some(b"\xE2\x82\xAC")),
        ("surrogate pair \\ud83d\\ude00 is UTF-8 F0 9F 98 80", r"😀", Some(b"\xF0\x9F\x98\x80")),
        ("\\b and \\f are U+0008 and U+000C", r"\b\f", Some(b"\x08\x0C")),
        ("\\\" \\\\ \\/ \\n \\r \\t", r#"\"\\\/\n\r\t"#, Some(b"\"\\/\n\r\t")),
        ("lone high surrogate is an error", r"\ud83dx", None),
        ("high surrogate followed by a non-surrogate escape is an error", r"\ud83dA", None),
        ("lone low surrogate is an error", r"\ude00", None),
        ("truncated \\u12 is an error", r"\u12", None),
        ("non-hex digit in \\u is an error", r"\u00g1", None),
        ("unknown escape \\x is an error", r"\x41", None),
    ];
    for (label, escaped, want) in vecs {
        let r = decode_pdu::<Rec>(&format!("{{\"text\":\"{escaped}\",\"alt\":{{\"n\":1}}}}"));
        let ok = match want {
            Some(w) => r.is_ok_and(|r| r.text.as_bytes() == *w),
            None => r.is_err(),
        };
        check(label, ok, &mut f);
    }

    let r = decode_pdu::<Rec>(r#"{"text":"hi","alt":{"name":"x"}}"#);
    check(
        "escaped member and alternative names",
        r.is_ok_and(|r| r.text.as_str() == "hi" && matches!(&r.alt, Alt::name(n) if n.as_str() == "x")),
        &mut f,
    );

    let c = Rec { text: Utf8String("a\x01\x08\x0C\x1Fb\u{e9}".to_string()), alt: Alt::name(Utf8String("y".to_string())) };
    let back = encode_pdu(&c).map(|t| decode_pdu::<Rec>(&t));
    check("control characters survive a JER round-trip", back.is_ok_and(|b| b.is_ok_and(|b| b == c)), &mut f);

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
