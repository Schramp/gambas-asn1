// Rust leg of the XMLValueList test (xer_value_list_test.asn1); mirrors
// tests/seq/test_xer_value_list.cpp. A SEQUENCE OF / SET OF whose elements
// are BOOLEAN, ENUMERATED or NULL uses the XMLValueList form (X.680 §25.5
// Table 5): each value bare, with no element tag, also through a type
// reference or a tag (§25.6, §25.9); a NULL value is the empty element of
// its type name (§25.4). The expected text is asn1c's own layout.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::sequence::{SeqOf, SetOf};
use asn1cpp_wire::boolean::Boolean;
use asn1cpp_wire::null::Null;
use asn1cpp_wire::xer::object::{decode_pdu, encode_pdu};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn contains(text: &str, part: &str) -> bool {
    let ok = text.contains(part);
    if !ok {
        println!("        missing:\n{part}\n        in:\n{text}");
    }
    ok
}

fn same(text: &str, want: &str) -> bool {
    let ok = text == want;
    if !ok {
        println!("        want:\n{want}\n        got:\n{text}");
    }
    ok
}

fn main() {
    let mut f = 0;
    println!("=== XMLValueList (X.680 §25.5) ===");

    let v = VlRec::VlRec {
        ec: SeqOf(vec![Color::Color::green, Color::Color::green]),
        et: SeqOf(vec![TEnum::TEnum::red]),
        bb: SeqOf(vec![Boolean(true), Boolean(false)]),
        ba: SeqOf(vec![ABool::ABool(Boolean(true))]),
        bt: SetOf(vec![TBool::TBool(Boolean(false)), TBool::TBool(Boolean(true))]),
        nb: SeqOf(vec![Null, Null]),
        na: SeqOf(vec![ANull::ANull(Null)]),
        nt: SeqOf(vec![TNull::TNull(Null)]),
        st: SetOf(vec![ANull::ANull(Null), ANull::ANull(Null)]),
        ll: SeqOf(vec![SeqOf(vec![Boolean(true), Boolean(true)])]),
        lc: SeqOf(vec![VlPick::VlPick::b(Boolean(true))]),
    };

    let text = encode_pdu(&v).unwrap_or_default();
    check("SEQUENCE OF ENUMERATED: values inline", contains(&text, "    <ec><green/><green/>    </ec>\n"), &mut f);
    check("SEQUENCE OF tagged ENUMERATED type: values inline", contains(&text, "    <et><red/>    </et>\n"), &mut f);
    check("SEQUENCE OF BOOLEAN: bare <true/>/<false/>", contains(&text, "    <bb><true/><false/>    </bb>\n"), &mut f);
    check("SEQUENCE OF BOOLEAN type reference: bare value", contains(&text, "    <ba><true/>    </ba>\n"), &mut f);
    check(
        "SET OF tagged BOOLEAN type: one bare value per line",
        contains(&text, "    <bt>\n            <false/>\n            <true/>    </bt>\n"),
        &mut f,
    );
    check(
        "SEQUENCE OF NULL: <NULL/> per line",
        contains(&text, "    <nb>\n            <NULL/>\n            <NULL/>    </nb>\n"),
        &mut f,
    );
    check("SEQUENCE OF NULL type reference: <ANull/>", contains(&text, "    <na>\n            <ANull/>    </na>\n"), &mut f);
    check("SEQUENCE OF tagged NULL type: <TNull/>", contains(&text, "    <nt>\n            <TNull/>    </nt>\n"), &mut f);
    check(
        "SET OF NULL type reference: <ANull/> per line",
        contains(&text, "    <st>\n            <ANull/>\n            <ANull/>    </st>\n"),
        &mut f,
    );
    check(
        "nested SEQUENCE OF BOOLEAN: values inline in <SEQUENCE_OF>",
        contains(&text, "        <SEQUENCE_OF><true/><true/>        </SEQUENCE_OF>\n"),
        &mut f,
    );
    check("VlRec XER round-trip", decode_pdu::<VlRec::VlRec>(&text).is_ok_and(|b| b == v), &mut f);

    let tb = VlTopBool::VlTopBool(vec![Boolean(false), Boolean(true)]);
    let tb_text = encode_pdu(&tb).unwrap_or_default();
    check("top-level SEQUENCE OF BOOLEAN", same(&tb_text, "<VlTopBool><false/><true/></VlTopBool>\n"), &mut f);
    check(
        "top-level SEQUENCE OF BOOLEAN round-trip",
        decode_pdu::<VlTopBool::VlTopBool>(&tb_text).is_ok_and(|b| b == tb),
        &mut f,
    );

    let tn = VlTopNull::VlTopNull(vec![Null, Null]);
    let tn_text = encode_pdu(&tn).unwrap_or_default();
    check("top-level SET OF NULL", same(&tn_text, "<VlTopNull>\n        <NULL/>\n        <NULL/></VlTopNull>\n"), &mut f);
    check(
        "top-level SET OF NULL round-trip",
        decode_pdu::<VlTopNull::VlTopNull>(&tn_text).is_ok_and(|b| b == tn),
        &mut f,
    );

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
