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
// Also covers gambas-asn1#450: this same schema's middle-level CHOICE
// (two sibling alternatives "r11"/"criticalExtensions", both plain
// references to a SEQUENCE with no `[n]` of their own) used to collide on
// the same natural tag instead of getting distinct AUTOMATIC TAGS — the
// module's own tag default was lost while generating a promoted/inline
// type (Generator::generate_inline_types ran before
// current_tag_default_ was set for this module). Fixed at the Generator
// level (shared by both backends); the full nested round-trip below
// exercises exactly the alternative that used to collide, and the
// expected BER bytes are confirmed byte-exact against real asn1c output
// (`asn1c -fcompound-names` + `converter-example -ixer -oder`).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use handover_command::HandoverCommand;
use handover_command_critical_extensions::HandoverCommandCriticalExtensions;
use handover_command_critical_extensions_critical_extensions::HandoverCommandCriticalExtensionsCriticalExtensions;
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

    // Full nested round-trip through the previously-ambiguous middle-level
    // "criticalExtensions" alternative (gambas-asn1#450).
    let hc = HandoverCommand {
        rrc_trans_id: 7,
        critical_extensions: HandoverCommandCriticalExtensions::CriticalExtensions(
            HandoverCommandCriticalExtensionsCriticalExtensions::CriticalExtensions(Leaf {}),
        ),
    };

    let bytes = hc.encode();
    let expected: &[u8] = &[0x30, 0x09, 0x80, 0x01, 0x07, 0xa1, 0x04, 0xa1, 0x02, 0xa1, 0x00];
    check("nested BER matches asn1c ground truth", bytes == expected, &mut failures);

    let back = HandoverCommand::decode(&bytes);
    check("nested BER decode ok", back.is_ok(), &mut failures);
    check("nested BER round-trip", back == Ok(hc.clone()), &mut failures);

    let xml = hc.encode_xer();
    let back_xml = HandoverCommand::decode_xer(&xml);
    check("nested XER decode ok", back_xml.is_ok(), &mut failures);
    check("nested XER round-trip", back_xml == Ok(hc), &mut failures);

    println!("\n{}  {failures} failure(s)", if failures != 0 { "\x1b[31mFAIL\x1b[0m" } else { "\x1b[32mPASS\x1b[0m" });
    if failures != 0 {
        std::process::exit(1);
    }
}
