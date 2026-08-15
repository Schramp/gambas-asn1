// Regression test for gambas-asn1#437: a deeply nested anonymous
// CHOICE-in-CHOICE (201-nested-choice-name-collision-OK.asn1) promotes a
// synthetic 0-member SEQUENCE {} type (the innermost `criticalExtensions`
// alternative, X.680 §24 permits a SEQUENCE with no components — an
// extension-marker placeholder). RustBackend used to withhold the whole
// Asn1Value impl for any 0-member SEQUENCE, so the moment this promoted
// type was used as a CHOICE alternative elsewhere, the crate failed to
// compile (E0277: Asn1Value not satisfied) — even though the equivalent
// C++ output built fine. Getting this far (the crate compiles at all) is
// most of what this test regresses; the standalone round-trip below
// exercises the actual fixed code path.
//
// Note: this schema also exposes a separate, pre-existing, cross-language
// bug — two sibling CHOICE alternatives at the middle nesting level ("r11"
// and "criticalExtensions") both resolve to the same natural tag
// (SEQUENCE, universal 16) instead of getting distinct AUTOMATIC TAGS,
// making them wire-ambiguous. Confirmed present in unmodified C++ output
// too (same schema, same tag table) — unrelated to the Asn1Value gap this
// test regresses, so this test deliberately does not round-trip through
// that ambiguous alternative selection.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use handover_command_critical_extensions_critical_extensions_critical_extensions::HandoverCommandCriticalExtensionsCriticalExtensionsCriticalExtensions as Leaf;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    println!("\n\u{2500}\u{2500} nested_choice_201: promoted 0-member SEQUENCE Asn1Value \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut failures = 0;

    let leaf = Leaf {};

    let bytes = leaf.encode();
    check("leaf BER encode non-empty length ok", bytes.len() == 2, &mut failures);

    let back = Leaf::decode(&bytes);
    check("leaf BER decode ok", back.is_ok(), &mut failures);
    check("leaf BER round-trip", back == Ok(leaf.clone()), &mut failures);

    let xml = leaf.encode_xer();
    check("leaf XER encode non-empty", !xml.is_empty(), &mut failures);

    let back_xml = Leaf::decode_xer(&xml);
    check("leaf XER decode ok", back_xml.is_ok(), &mut failures);
    check("leaf XER round-trip", back_xml == Ok(leaf), &mut failures);

    println!("\n{}  {failures} failure(s)", if failures != 0 { "\x1b[31mFAIL\x1b[0m" } else { "\x1b[32mPASS\x1b[0m" });
    if failures != 0 {
        std::process::exit(1);
    }
}
