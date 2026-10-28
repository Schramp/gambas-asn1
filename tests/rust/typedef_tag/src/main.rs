// Rust leg of the type-assignment tag test (typedef_tag_test.asn1); mirrors
// tests/seq/test_typedef_tag.cpp. A reference to `TBool::TBool ::= [APPLICATION 1]
// BOOLEAN` and friends carries the type assignment's tag (X.680 §31.2):
// IMPLICIT replaces the universal tag (X.690 §8.14.3), EXPLICIT wraps it
// (§8.14.2). Compiling this crate also covers SEQUENCE OF a BOOLEAN, NULL
// or OBJECT IDENTIFIER type assignment (`lb`, `ln`, `lo`).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::reader::Reader;
use asn1cpp_wire::ber::tag::{Tag, TagClass};
use asn1cpp_wire::ber::{object, sequence::SeqOf, sequence::SetOf};
use asn1cpp_wire::bit_string::BitString;
use asn1cpp_wire::boolean::Boolean;
use asn1cpp_wire::integer::{Integer, UInteger};
use asn1cpp_wire::null::Null;
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::oid::ObjectIdentifier;
use asn1cpp_wire::real::Real;
use asn1cpp_wire::relative_oid::RelativeOid;
use asn1cpp_wire::strings::Ia5String;
use Pick::Pick as P;
use Tagged::Tagged as Rec;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn is_app(t: Tag, n: u32) -> bool {
    t.class == TagClass::Application && t.number == n
}

fn tlvs(content: &[u8]) -> Vec<(Tag, &[u8])> {
    let mut r = Reader::new(content);
    let mut out = Vec::new();
    while !r.at_end() {
        match r.read_tlv() {
            Ok(t) => out.push((t.tag, t.value)),
            Err(_) => break,
        }
    }
    out
}

fn elems_are(content: &[u8], n: u32) -> bool {
    let e = tlvs(content);
    !e.is_empty() && e.iter().all(|(t, _)| is_app(*t, n))
}

fn oid(arcs: &[u64]) -> TOid::TOid {
    TOid::TOid(ObjectIdentifier(arcs.to_vec()))
}

fn tagged(pick: P) -> Rec {
    Rec {
        b: TBool::TBool(Boolean(true)),
        o: oid(&[1, 2, 840]),
        s: TOct::TOct(OctetString(vec![0xAB])),
        t: TBit::TBit(BitString { bytes: vec![0xA0], unused_bits: 4 }),
        r: TReal::TReal(Real::new(2.5)),
        l: TRel::TRel(RelativeOid(vec![3, 4])),
        u: TUInt::TUInt(UInteger(9)),
        i: TInt::TInt(Integer(-3)),
        x: TStr::TStr(Ia5String("abc".into())),
        z: TNull::TNull(Null),
        e: TEnum::TEnum::green,
        q: TSeq::TSeq { v: Integer(1) },
        w: TExp::TExp(Integer(5)),
        c: pick,
        lst: SeqOf(vec![TOct::TOct(OctetString(vec![1])), TOct::TOct(OctetString(vec![]))]),
        lq: SeqOf(vec![TSeq::TSeq { v: Integer(2) }]),
        lw: SeqOf(vec![TExp::TExp(Integer(6)), TExp::TExp(Integer(7))]),
        le: SeqOf(vec![TEnum::TEnum::red, TEnum::TEnum::green]),
        lb: SetOf(vec![TBool::TBool(Boolean(false)), TBool::TBool(Boolean(true))]),
        ln: SeqOf(vec![TNull::TNull(Null), TNull::TNull(Null)]),
        lo: SeqOf(vec![oid(&[2, 5]), oid(&[1, 3, 6, 1])]),
        ob: Some(TBool::TBool(Boolean(false))),
        os: Some(TOct::TOct(OctetString(vec![0xCD]))),
    }
}

fn main() {
    let mut f = 0;
    println!("=== Type-assignment tag on a builtin type ===");

    let pb = object::encode_pdu(&P::pb(TBool::TBool(Boolean(true)))).unwrap_or_default();
    check("TBool as a CHOICE alternative: [APPLICATION 1] primitive (41 01 FF)", pb == [0x41, 0x01, 0xFF], &mut f);
    check("TBool alternative decodes its own tag", object::decode_pdu::<P>(&pb).is_ok_and(|p| p == P::pb(TBool::TBool(Boolean(true)))), &mut f);
    check("TBool alternative rejects the universal BOOLEAN tag", object::decode_pdu::<P>(&[0x01, 0x01, 0xFF]).is_err(), &mut f);

    let q = object::encode_pdu(&TSeq::TSeq { v: Integer(1) }).unwrap_or_default();
    check("TSeq standalone: [APPLICATION 12] constructed (6C)", q.first() == Some(&0x6C), &mut f);

    for (name, pick, pick_tag) in [
        ("pb", P::pb(TBool::TBool(Boolean(false))), 1),
        ("po", P::po(TOct::TOct(OctetString(vec![7]))), 3),
        ("pi", P::pi(TInt::TInt(Integer(8))), 8),
    ] {
        let v = tagged(pick);
        let enc = match object::encode_pdu(&v) {
            Ok(e) => e,
            Err(e) => {
                check(&format!("Tagged (c = {name}) encodes: {e:?}"), false, &mut f);
                continue;
            }
        };
        let outer = tlvs(&enc);
        let m = outer.first().map(|(_, c)| tlvs(c)).unwrap_or_default();
        // b o s t r l u i x z e q w → APPLICATION 1..13, then c, lst, lq, lw,
        // le, lb, ln, lo, ob, os.
        check(&format!("Tagged (c = {name}) has 23 members"), m.len() == 23, &mut f);
        if m.len() != 23 {
            continue;
        }
        check(
            &format!("Tagged (c = {name}): b..w carry APPLICATION 1..13"),
            (1..=13).all(|n| is_app(m[n as usize - 1].0, n)),
            &mut f,
        );
        check(&format!("Tagged (c = {name}): CHOICE alternative tag"), is_app(m[13].0, pick_tag), &mut f);
        check(
            &format!("Tagged (c = {name}): SEQUENCE OF / SET OF elements carry their type's tag"),
            elems_are(m[14].1, 3)
                && elems_are(m[15].1, 12)
                && elems_are(m[16].1, 13)
                && elems_are(m[17].1, 11)
                && elems_are(m[18].1, 1)
                && elems_are(m[19].1, 10)
                && elems_are(m[20].1, 2),
            &mut f,
        );
        check(&format!("Tagged (c = {name}): optional members"), is_app(m[21].0, 1) && is_app(m[22].0, 3), &mut f);
        let w = tlvs(m[12].1);
        check(
            &format!("Tagged (c = {name}): TExp is EXPLICIT around a universal INTEGER"),
            w.len() == 1 && w[0].0.class == TagClass::Universal && w[0].0.number == 2,
            &mut f,
        );
        let back = object::decode_pdu::<Rec>(&enc);
        check(&format!("Tagged (c = {name}) BER round-trip"), back.is_ok_and(|b| b == v), &mut f);
    }

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
