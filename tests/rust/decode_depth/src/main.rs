// Rust leg of the decode nesting limit test (self_ref_choice_test.asn1,
// RecChoice ::= CHOICE { a INTEGER, b INTEGER, c RecChoice }); mirrors the
// nesting-limit section of tests/seq/test_self_ref_choice.cpp. A forged
// input nesting `c` far deeper than `nesting::MAX_DECODE_DEPTH` is rejected
// with an error by every decoder instead of overflowing the stack; one just
// within the limit decodes. RecSeq (`next RecSeq OPTIONAL`) does the same
// through IMPLICIT-tagged members only.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::nesting::MAX_DECODE_DEPTH;
use RecChoice::RecChoice as Rec;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

// c(c(...c(a(5))...)), built directly rather than encoded.
fn deep_ber(levels: usize) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0x05];
    for _ in 0..levels {
        let n = v.len();
        let mut w = vec![0xA2];
        if n < 128 {
            w.push(n as u8);
        } else {
            let b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|&x| x == 0).collect();
            w.push(0x80 | b.len() as u8);
            w.extend_from_slice(&b);
        }
        w.extend_from_slice(&v);
        v = w;
    }
    v
}

fn deep_xer(levels: usize) -> String {
    format!("<RecChoice>{}<a>5</a>{}</RecChoice>", "<c>".repeat(levels), "</c>".repeat(levels))
}

fn deep_jer(levels: usize) -> String {
    format!("{}{{\"a\":5}}{}", "{\"c\":".repeat(levels), "}".repeat(levels))
}

// UPER: CHOICE index '10' (c) per level, '00' (a), then INTEGER 5 as an
// unconstrained whole number (length 1, one octet).
fn deep_per(levels: usize) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    for _ in 0..levels {
        bits.extend([true, false]);
    }
    bits.extend([false, false]);
    for b in [1u8, 5] {
        bits.extend((0..8).rev().map(|k| (b >> k) & 1 == 1));
    }
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            out[i / 8] |= 0x80 >> (i % 8);
        }
    }
    out
}

// A RecSeq whose `next` chain is `levels` deep: each level's contents are
// v [0] = 0 followed by next [1] IMPLICIT RecSeq.
fn deep_rec_seq_ber(levels: usize) -> Vec<u8> {
    fn wrap(mut prefix: Vec<u8>, tag: u8, v: &[u8]) -> Vec<u8> {
        prefix.push(tag);
        let n = v.len();
        if n < 128 {
            prefix.push(n as u8);
        } else {
            let b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|&x| x == 0).collect();
            prefix.push(0x80 | b.len() as u8);
            prefix.extend_from_slice(&b);
        }
        prefix.extend_from_slice(v);
        prefix
    }
    let mut v = vec![0x80, 0x01, 0x00];
    for _ in 0..levels {
        v = wrap(vec![0x80, 0x01, 0x00], 0xA1, &v);
    }
    wrap(vec![], 0x30, &v)
}

// A decoded value nested this deep would recurse in Drop; unwind it first.
fn drop_flat(v: Rec) {
    let mut cur = v;
    while let Rec::c(inner) = cur {
        cur = *inner;
    }
}

fn main() {
    let mut failures = 0;
    let max = MAX_DECODE_DEPTH as usize;
    for levels in [max - 2, 100_000] {
        let within = levels < max;
        let verdict = if within { "succeeds" } else { "is an error" };
        let mut expect = |codec: &str, r: Option<Rec>| {
            check(&format!("{codec} decode of {levels} levels {verdict}"), r.is_some() == within, &mut failures);
            if let Some(v) = r {
                drop_flat(v);
            }
        };
        expect("BER", asn1cpp_wire::ber::object::decode_pdu::<Rec>(&deep_ber(levels)).ok());
        expect("XER", asn1cpp_wire::xer::object::decode_pdu::<Rec>(&deep_xer(levels)).ok());
        expect("JER", asn1cpp_wire::jer::object::decode_pdu::<Rec>(&deep_jer(levels)).ok());
        expect("PER", asn1cpp_wire::per::object::decode_pdu::<Rec>(&deep_per(levels)).ok());
        let r = asn1cpp_wire::ber::object::decode_pdu::<RecSeq::RecSeq>(&deep_rec_seq_ber(levels));
        check(&format!("BER RecSeq (IMPLICIT) decode of {levels} levels {verdict}"), r.is_ok() == within, &mut failures);
    }
    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "PASSED" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
