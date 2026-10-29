// Rust leg of the ENUMERATED item names test (enum_item_names_test.asn1).
// Items named like generated locals (x, v, f, i, s, value) keep their ASN.1
// spelling as Rust variants; compiling this crate checks that no generated
// binding shadows them (E0170). `self` cannot be a Rust raw identifier, so
// its variant is `self_`, while every codec still uses the ASN.1 name.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::sequence::SeqOf;
use asn1cpp_wire::{ber, xer};
use EinEnum::EinEnum as E;

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
    println!("=== ENUMERATED item names ===");

    let rec = |item: E| EinRec::EinRec {
        req: item,
        opt: Some(E::v),
        dflt: Some(E::self_),
        inl: Some(EinRecInl::EinRecInl::x),
        list: SeqOf(vec![E::value, E::self_]),
        alt: EinRecAlt::EinRecAlt::e(E::x),
    };
    let names = ["x", "v", "f", "i", "s", "value", "self"];
    let all = [E::x, E::v, E::f, E::i, E::s, E::value, E::self_];
    for (n, item) in all.iter().enumerate() {
        let enc = ber::object::encode_pdu(&rec(*item)).unwrap_or_default();
        check(&format!("item {} BER value {n}", names[n]), enc.get(2..5) == Some(&[0x80, 0x01, n as u8][..]), &mut f);
        let text = xer::object::encode_pdu(&rec(*item)).unwrap_or_default();
        check(
            &format!("item {} XER uses the ASN.1 name", names[n]),
            text.contains(&format!("<req><{}/></req>", names[n])),
            &mut f,
        );
    }

    let r = rec(E::self_);
    let enc = ber::object::encode_pdu(&r).unwrap_or_default();
    check("EinRec BER round-trip", ber::object::decode_pdu::<EinRec::EinRec>(&enc).is_ok_and(|b| b == r), &mut f);
    let rtext = xer::object::encode_pdu(&r).unwrap_or_default();
    check("EinRec XER round-trip", xer::object::decode_pdu::<EinRec::EinRec>(&rtext).is_ok_and(|b| b == r), &mut f);

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
