// Regression test for gambas-asn1#447: a directly self-referential CHOICE
// alternative (203-automatic-tags-OK.asn1's
// RecChoice ::= [0] CHOICE { a INTEGER, b INTEGER, c RecChoice }) generated
// a plain (un-boxed) enum variant, which rustc rejects outright as an
// infinite-size recursive type:
//
//   error[E0072]: recursive type `RecChoice` has infinite size
//
// Same schema/PDU gambas-asn1#436 fixed for C++ (boxed val_storage_ slot).
// Fix here: RustBackend boxes a directly self-referential alternative
// (`C(Box<RecChoice>)` instead of `C(RecChoice)`) — see
// RustBackend::emit_choice_declaration's Box<> comment.
//
// Note: RecChoice's own `[0]` tag interacts with a separate, pre-existing
// AUTOMATIC TAGS bug (gambas-asn1#448 — a CHOICE alternative referencing
// an already-tagged type is wrongly forced EXPLICIT) that currently
// produces a double-wrapped encoding for alternative `c`, in both this
// crate's output and the equivalent C++ output (confirmed identical bytes
// both ways — a real bug, but a wire-format one, unrelated to what this
// test regresses). So this test checks round-trip correctness and
// cross-language byte parity against the C++ runtime, not exact bytes
// against real asn1c ground truth — that assertion belongs with #448's
// own fix instead.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use rec_choice::RecChoice;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    println!("\n\u{2500}\u{2500} self_ref_choice_203: directly self-referential CHOICE alternative \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut failures = 0;

    // Depth 1: RecChoice = c(a(7)) — cross-language byte parity against the
    // equivalent C++ runtime output (BerCodec::instance().encode() on the
    // equivalent C++ RecChoice value).
    let r = RecChoice::C(Box::new(RecChoice::A(7)));
    let bytes = r.encode();
    let cpp_bytes: &[u8] = &[0xa0, 0x07, 0xa2, 0x05, 0xa0, 0x03, 0x80, 0x01, 0x07];
    check("depth-1 BER matches C++ output (byte parity, see #448)", bytes == cpp_bytes, &mut failures);

    let back = RecChoice::decode(&bytes);
    check("depth-1 BER decode ok", back.is_ok(), &mut failures);
    check("depth-1 BER round-trip", back == Ok(r.clone()), &mut failures);

    let bytes2 = back.unwrap().encode();
    check("depth-1 BER idempotent", bytes == bytes2, &mut failures);

    // Depth 3: RecChoice = c(c(c(b(99)))).
    let r3 = RecChoice::C(Box::new(RecChoice::C(Box::new(RecChoice::C(Box::new(RecChoice::B(99)))))));
    let bytes3 = r3.encode();
    let back3 = RecChoice::decode(&bytes3);
    check("depth-3 BER decode ok", back3.is_ok(), &mut failures);
    check("depth-3 BER round-trip", back3 == Ok(r3), &mut failures);

    // XER round-trip.
    let rx = RecChoice::C(Box::new(RecChoice::A(-13)));
    let xml = rx.encode_xer();
    check("XER encode non-empty", !xml.is_empty(), &mut failures);
    let back_xml = RecChoice::decode_xer(&xml);
    check("XER decode ok", back_xml.is_ok(), &mut failures);
    check("XER round-trip", back_xml == Ok(rx), &mut failures);

    println!("\n{}  {failures} failure(s)", if failures != 0 { "\x1b[31mFAIL\x1b[0m" } else { "\x1b[32mPASS\x1b[0m" });
    if failures != 0 {
        std::process::exit(1);
    }
}
