// Rust leg of the inline SEQUENCE OF ENUMERATED test
// (inline_seqof_enum_test.asn1); mirrors tests/seq/test_inline_seqof_enum.cpp.
// The element of a SEQUENCE OF / SET OF written as an inline ENUMERATED
// (X.680 §20) is promoted to a named type in the collection's scope
// (IsRecEbEnum, IsRecEnItem, IsTopEnum); compiling this crate checks that
// the member fields use those names.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::sequence::{SeqOf, SetOf};
use asn1cpp_wire::{ber, xer};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn same<T: PartialEq + std::fmt::Debug>(got: &T, want: &T) -> bool {
    if got != want {
        println!("        want:\n{want:?}\n        got:\n{got:?}");
    }
    got == want
}

fn main() {
    let mut f = 0;
    println!("=== SEQUENCE OF inline ENUMERATED ===");

    let v = IsRec::IsRec {
        eb: SeqOf(vec![IsRecEbEnum::IsRecEbEnum::b, IsRecEbEnum::IsRecEbEnum::a]),
        es: SetOf(vec![IsRecEsEnum::IsRecEsEnum::n]),
        en: SeqOf(vec![IsRecEnItem::IsRecEnItem::h]),
        ec: IsRecEc::IsRecEc::x(IsRecEcX::IsRecEcX::q),
    };
    let enc = ber::object::encode_pdu(&v).unwrap_or_default();
    let want: Vec<u8> = vec![
        0x30, 0x15, //
        0x30, 0x06, 0x0A, 0x01, 0x01, 0x0A, 0x01, 0x00, // eb
        0x31, 0x03, 0x0A, 0x01, 0x01, // es
        0xA0, 0x03, 0x0A, 0x01, 0x01, // en [0]
        0x0A, 0x01, 0x01, // ec.x
    ];
    check("IsRec BER: elements are universal ENUMERATED", same(&enc, &want), &mut f);
    check("IsRec BER round-trip", ber::object::decode_pdu::<IsRec::IsRec>(&enc).is_ok_and(|b| b == v), &mut f);

    let text = xer::object::encode_pdu(&v).unwrap_or_default();
    let want_text = "<IsRec>\n\
                     \x20   <eb><b/><a/>    </eb>\n\
                     \x20   <es>\n\
                     \x20           <n/>    </es>\n\
                     \x20   <en><h/>    </en>\n\
                     \x20   <ec>\n\
                     \x20       <x><q/></x>\n\
                     \x20   </ec>\n\
                     </IsRec>\n";
    check("IsRec XER", same(&text.as_str(), &want_text), &mut f);
    check("IsRec XER round-trip", xer::object::decode_pdu::<IsRec::IsRec>(&text).is_ok_and(|b| b == v), &mut f);

    let t = IsTop::IsTop(vec![IsTopEnum::IsTopEnum::v, IsTopEnum::IsTopEnum::u]);
    let tenc = ber::object::encode_pdu(&t).unwrap_or_default();
    check("IsTop BER", same(&tenc, &vec![0x30, 0x06, 0x0A, 0x01, 0x01, 0x0A, 0x01, 0x00]), &mut f);
    check("IsTop BER round-trip", ber::object::decode_pdu::<IsTop::IsTop>(&tenc).is_ok_and(|b| b == t), &mut f);
    check(
        "IsTop XER",
        same(&xer::object::encode_pdu(&t).unwrap_or_default().as_str(), &"<IsTop><v/><u/></IsTop>\n"),
        &mut f,
    );

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "OK" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
