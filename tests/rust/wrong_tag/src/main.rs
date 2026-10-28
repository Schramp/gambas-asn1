// Rust leg of the wrong-tag test (wrong_tag_test.asn1); mirrors
// tests/seq/test_wrong_tag.cpp. BER decode must reject a TLV whose
// identifier octets are not the type's own tag (X.690 §8.1.2) for the PDU,
// each SEQUENCE member and each SEQUENCE OF element. A reference to a
// tagged CONTAINING type assignment (`t TCont`, `e TContE`) carries that
// assignment's tag (X.680 §31.2), IMPLICIT or EXPLICIT, as a SEQUENCE
// member and as a CHOICE alternative.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::object::{decode_pdu, encode_pdu};
use asn1cpp_wire::ber::reader::Reader;
use asn1cpp_wire::ber::sequence::SeqOf;
use asn1cpp_wire::containing::Containing;
use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::spec::object::Asn1Pdu;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn inner(x: i64) -> Inner::Inner {
    Inner::Inner { x: Integer(x) }
}

fn contained(x: i64) -> Containing<Inner::Inner> {
    let mut c = Containing::default();
    c.set_value(inner(x));
    c
}

fn x_of(c: &Containing<Inner::Inner>) -> Option<i64> {
    c.value().map(|v| v.x.0)
}

// Offsets of the identifier octet of the outer TLV and of each TLV directly
// inside it.
fn tag_offsets(enc: &[u8]) -> Vec<usize> {
    let mut out = vec![0];
    let Ok(outer) = Reader::new(enc).read_tlv() else { return out };
    let content_start = enc.len() - outer.value.len();
    let mut r = Reader::new(outer.value);
    while !r.at_end() {
        let at = r.pos();
        if r.read_tlv().is_err() {
            break;
        }
        out.push(content_start + at);
    }
    out
}

// Change the tag class of each TLV in turn (universal ↔ context,
// application ↔ private) and expect decode to fail.
fn expect_each_rejected<T: Asn1Pdu>(what: &str, enc: &[u8], f: &mut i32) {
    for off in tag_offsets(enc) {
        let mut bad = enc.to_vec();
        bad[off] ^= 0x80;
        check(
            &format!("{what}: tag {:02X} -> {:02X} at offset {off} rejected", enc[off], bad[off]),
            decode_pdu::<T>(&bad).is_err(),
            f,
        );
    }
}

fn main() {
    let mut f = 0;
    println!("=== Wrong tag on a value decoded through its own type ===");

    let v = WtSeq::WtSeq {
        a: inner(5),
        o: OctetString(vec![0x61]),
        l: SeqOf(vec![Integer(1)]),
        c: contained(7),
        t: contained(8),
        e: contained(9),
        p: WtPick::WtPick::n(Integer(4)),
    };
    let enc = encode_pdu(&v).unwrap_or_default();
    let offs = tag_offsets(&enc);
    check("WtSeq has 7 members", offs.len() == 8, &mut f);
    if offs.len() == 8 {
        check("t carries [APPLICATION 5] IMPLICIT (45)", enc[offs[5]] == 0x45, &mut f);
        check("e carries [APPLICATION 6] EXPLICIT (66) around 04", enc[offs[6]] == 0x66 && enc[offs[6] + 2] == 0x04, &mut f);
    }
    let back = decode_pdu::<WtSeq::WtSeq>(&enc);
    check(
        "WtSeq round-trips",
        back.is_ok_and(|b| x_of(&b.t) == Some(8) && x_of(&b.e) == Some(9) && encode_pdu(&b).is_ok_and(|e| e == enc)),
        &mut f,
    );
    expect_each_rejected::<WtSeq::WtSeq>("WtSeq", &enc, &mut f);

    let enc = encode_pdu(&WtPick::WtPick::t(contained(2))).unwrap_or_default();
    check("CHOICE alternative t carries [APPLICATION 5] (45)", enc.first() == Some(&0x45), &mut f);
    check(
        "CHOICE alternative t round-trips",
        decode_pdu::<WtPick::WtPick>(&enc).is_ok_and(|p| matches!(&p, WtPick::WtPick::t(c) if x_of(c) == Some(2))),
        &mut f,
    );
    let enc = encode_pdu(&WtPick::WtPick::e(contained(3))).unwrap_or_default();
    check(
        "CHOICE alternative e carries [APPLICATION 6] EXPLICIT around 04",
        enc.len() > 2 && enc[0] == 0x66 && enc[2] == 0x04,
        &mut f,
    );
    check(
        "CHOICE alternative e round-trips",
        decode_pdu::<WtPick::WtPick>(&enc).is_ok_and(|p| matches!(&p, WtPick::WtPick::e(c) if x_of(c) == Some(3))),
        &mut f,
    );

    let enc = encode_pdu(&WtListSeq::WtListSeq(vec![inner(1)])).unwrap_or_default();
    expect_each_rejected::<WtListSeq::WtListSeq>("SEQUENCE OF Inner", &enc, &mut f);

    let enc = encode_pdu(&WtListOct::WtListOct(vec![OctetString(vec![])])).unwrap_or_default();
    expect_each_rejected::<WtListOct::WtListOct>("SEQUENCE OF OCTET STRING", &enc, &mut f);
    let mut as_int = enc.clone();
    as_int[2] = 0x02;
    check(
        "SEQUENCE OF OCTET STRING: INTEGER element rejected",
        decode_pdu::<WtListOct::WtListOct>(&as_int).is_err(),
        &mut f,
    );

    let enc = encode_pdu(&WtListList::WtListList(vec![WtListListAnon::WtListListAnon(vec![Integer(3)])])).unwrap_or_default();
    expect_each_rejected::<WtListList::WtListList>("SEQUENCE OF SEQUENCE OF", &enc, &mut f);

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
