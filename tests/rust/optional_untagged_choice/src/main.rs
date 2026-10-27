// OPTIONAL SEQUENCE member whose type is an untagged CHOICE (fuzz_test.asn1
// Bag.pick): presence is decided by the peeked tag matching one of the
// CHOICE's alternative tags (X.690 §8.13), in every codec.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::bit_string::BitString;
use asn1cpp_wire::boolean::Boolean;
use asn1cpp_wire::integer::{Integer, UInteger};
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::strings::PrintableString;
use asn1cpp_wire::{ber, per, xer};
use Bag::Bag as Rec;
use Inner::Inner as Item;
use Pick::Pick as Alt;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn bag(pick: Option<Alt>, color: Option<Color::Color>) -> Rec {
    let mut b = Rec::default();
    b.label = PrintableString("bag".into());
    let mut i = Item::default();
    i.n = Integer(7);
    i.counter = UInteger(244);
    i.s = OctetString(vec![1, 2, 3].into());
    i.flag = Boolean(true);
    b.items.push(i);
    b.pick = pick.map(Box::new);
    b.flags = BitString { bytes: vec![0xA5], unused_bits: 0 };
    b.color = color;
    b
}

fn round_trips(label: &str, v: &Rec, failures: &mut i32) {
    let ber_ok = ber::object::encode_pdu(v).is_ok_and(|b| ber::object::decode_pdu::<Rec>(&b).is_ok_and(|r| &r == v));
    check(&format!("BER {label}"), ber_ok, failures);
    let per_ok = per::object::encode_pdu(v).is_ok_and(|b| per::object::decode_pdu::<Rec>(&b).is_ok_and(|r| &r == v));
    check(&format!("PER {label}"), per_ok, failures);
    let xer_ok = xer::object::encode_pdu(v).is_ok_and(|s| xer::object::decode_pdu::<Rec>(&s).is_ok_and(|r| &r == v));
    check(&format!("XER {label}"), xer_ok, failures);
}

fn main() {
    let mut failures = 0;
    println!("=== OPTIONAL untagged CHOICE member ===");
    round_trips("pick absent", &bag(None, None), &mut failures);
    round_trips("pick absent, next OPTIONAL present", &bag(None, Some(Color::Color::blue)), &mut failures);
    round_trips("pick = a [0]", &bag(Some(Alt::a(Integer(9))), None), &mut failures);
    round_trips("pick = d [3]", &bag(Some(Alt::d(PrintableString("hi".into()))), Some(Color::Color::red)), &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
