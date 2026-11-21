// Rust leg of the items of a newer schema version (X.680 §52.1); mirrors
// tests/seq/test_enum_unknown.cpp and tests/seq/test_choice_unknown.cpp.
// A version-2 value decoded with the version-1 type is kept, re-encodes
// unchanged in the codec it came from, and fails to encode elsewhere with
// the same message as the C++ runtime.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::spec::choice::UnknownOrigin;
use asn1cpp_wire::spec::enumerated::EnumUnknown;
use asn1cpp_wire::spec::object::Asn1Choice;
use asn1cpp_wire::{ber, jer, per, xer};
use ColorV1::ColorV1 as C1;
use ColorV2::ColorV2 as C2;
use MsgV1::MsgV1 as M1;
use MsgV2::MsgV2 as M2;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

/// Message of a failed encode, or "" when it succeeded.
fn err<T, E: std::fmt::Display>(r: Result<T, E>) -> String {
    r.err().map(|e| e.to_string()).unwrap_or_default()
}

// The ENUMERATED values travel as elements of a SEQUENCE OF (a PDU).
type P1 = PaletteV1::PaletteV1;
fn palette(items: Vec<C1>) -> P1 {
    PaletteV1::PaletteV1(items)
}
fn palette_v2(c: C2) -> PaletteV2::PaletteV2 {
    PaletteV2::PaletteV2(vec![c])
}

fn test_enum(f: &mut i32) {
    println!("\n── ENUMERATED: PER unknown extension ordinal ─────────────────────");
    let wire = per::object::encode_pdu(&palette_v2(C2::yellow)).unwrap();
    let p = per::object::decode_pdu::<P1>(&wire);
    check("v1 decodes v2 yellow", p.is_ok(), f);
    let p = p.unwrap_or_else(|_| palette(vec![]));
    let item = p.0.first().copied();
    check("  ...as unknown ordinal 2", item == Some(C1::Unknown(EnumUnknown::Ordinal(2))), f);
    check("  ...re-encodes to the same bits", per::object::encode_pdu(&p).ok() == Some(wire.clone()), f);
    check("  ...BER encode fails",
          err(ber::object::encode_pdu(&p)) == "ENUMERATED ColorV1: extension item #2 of a newer schema version has no BER encoding", f);
    check("  ...XER encode fails", xer::object::encode_pdu(&p).is_err(), f);
    check("  ...JER encode fails", jer::object::encode_pdu(&p).is_err(), f);

    println!("\n── ENUMERATED: BER unknown value ─────────────────────────────────");
    let wire = ber::object::encode_pdu(&palette_v2(C2::magenta)).unwrap();
    let p = ber::object::decode_pdu::<P1>(&wire).unwrap_or_else(|_| palette(vec![]));
    check("v1 decodes v2 magenta as unknown value 10", p.0.first() == Some(&C1::Unknown(EnumUnknown::Value(10))), f);
    check("  ...re-encodes to the same octets", ber::object::encode_pdu(&p).ok() == Some(wire.clone()), f);
    check("  ...PER encode fails",
          err(per::object::encode_pdu(&p)) == "ENUMERATED ColorV1: value 10 of a newer schema version has no PER encoding", f);
    check("non-extensible BER still rejects 10",
          ber::object::decode_pdu::<FixedPalette::FixedPalette>(&fixed_wire(10)).is_err(), f);

    println!("\n── ENUMERATED: XER / JER unknown identifier ──────────────────────");
    let p = xer::object::decode_pdu::<P1>("<PaletteV1><red/><yellow/></PaletteV1>");
    check("XER list with an unknown identifier accepted",
          p.as_ref().is_ok_and(|p| p.0.len() == 2 && p.0[1] == C1::Unknown(EnumUnknown::Identifier)), f);
    if let Ok(p) = &p {
        check("  ...XER re-encode fails",
              err(xer::object::encode_pdu(p)) == "ENUMERATED ColorV1: an unknown identifier of a newer schema version has no XER encoding", f);
    }
    check("JER unknown identifier accepted",
          jer::object::decode_pdu::<P1>("[\"yellow\"]")
              .is_ok_and(|p| p.0 == vec![C1::Unknown(EnumUnknown::Identifier)]), f);
}

/// BER of a FixedPalette with one element of value `n`.
fn fixed_wire(n: u8) -> Vec<u8> {
    vec![0x30, 0x03, 0x0A, 0x01, n]
}

fn v2_d() -> M2 {
    M2::d(MsgV2D::MsgV2D { x: asn1cpp_wire::integer::Integer(300), y: asn1cpp_wire::boolean::Boolean(true) })
}

fn test_choice(f: &mut i32) {
    println!("\n── CHOICE: BER unknown extension alternative ─────────────────────");
    let wire = ber::object::encode_pdu(&v2_d()).unwrap();
    let m = ber::object::decode_pdu::<M1>(&wire);
    check("v1 decodes v2 alternative d",
          m.as_ref().is_ok_and(|m| m.extract_unknown_extension().is_some_and(|e| e.origin == UnknownOrigin::Ber)), f);
    if let Ok(m) = &m {
        check("  ...re-encodes to the same octets", ber::object::encode_pdu(m).ok() == Some(wire.clone()), f);
        check("  ...PER encode fails",
              err(per::object::encode_pdu(m)) == "CHOICE MsgV1: extension alternative of a newer schema version, read from BER, has no PER encoding", f);
    }

    println!("\n── CHOICE: PER unknown extension alternative ─────────────────────");
    let wire = per::object::encode_pdu(&v2_d()).unwrap();
    let m = per::object::decode_pdu::<M1>(&wire);
    check("v1 decodes v2 alternative d as extension index 1",
          m.as_ref().is_ok_and(|m| m.extract_unknown_extension().is_some_and(|e| e.origin == UnknownOrigin::Per && e.index == 1)), f);
    if let Ok(m) = &m {
        check("  ...re-encodes to the same bits", per::object::encode_pdu(m).ok() == Some(wire.clone()), f);
        check("  ...BER encode fails",
              err(ber::object::encode_pdu(m)) == "CHOICE MsgV1: extension alternative of a newer schema version, read from PER, has no BER encoding", f);
    }
}

fn main() {
    let mut failures = 0;
    test_enum(&mut failures);
    test_choice(&mut failures);
    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
