// Rust leg of the NamedBitList BIT STRING PER test (per_named_bits_test.asn1);
// mirrors tests/per/test_per_named_bits.cpp. Trailing 0 bits are removed and
// the value is padded with 0 bits up to the SIZE lower bound (X.691 §15.2,
// §15.3); `plain` has no NamedBitList and keeps its length. Expected bytes are
// asn1c's UPER output for the same values. Decoding gives back the value in
// that transmitted form.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::bit_string::BitString;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

/// BitString from a string of '0'/'1' characters, first character = bit 0.
fn bits(s: &str) -> BitString {
    let mut bytes = vec![0u8; s.len().div_ceil(8)];
    for (i, c) in s.chars().enumerate() {
        if c == '1' {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    BitString { bytes, unused_bits: ((8 - s.len() % 8) % 8) as u8 }
}

/// The transmitted form of a NamedBitList value: trailing 0 bits removed,
/// then 0 bits added up to `lb`.
fn sent(s: &str, lb: usize) -> BitString {
    let t = s.trim_end_matches('0');
    bits(&format!("{t:0<lb$}"))
}

/// Encode {flags, sized, fixed, ext, named, alias, typed, plain}, compare with
/// asn1c's bytes, decode and compare with the transmitted form of each member.
fn check_rec(label: &str, v: [&str; 8], expected: &[u8], f: &mut i32) {
    let rec = NamedBitsRec::NamedBitsRec {
        flags: bits(v[0]),
        sized: bits(v[1]),
        fixed: bits(v[2]),
        ext: bits(v[3]),
        named: Flags::Flags(bits(v[4])),
        alias: Flags::Flags(bits(v[5])),
        typed: SizedFlags::SizedFlags(bits(v[6])),
        plain: bits(v[7]),
    };
    check(&format!("{label} encodes"), asn1cpp_wire::per::object::encode_pdu(&rec).unwrap() == expected, f);
    // The BER encoder runs each member's constraint check.
    asn1cpp_wire::validate::reset_validate_fail_count();
    let _ = asn1cpp_wire::ber::object::encode_pdu(&rec);
    check(&format!("{label} satisfies its constraints"), asn1cpp_wire::validate::validate_fail_count() == 0, f);
    let want = NamedBitsRec::NamedBitsRec {
        flags: sent(v[0], 0),
        sized: sent(v[1], 2),
        fixed: sent(v[2], 8),
        ext: sent(v[3], 2),
        named: Flags::Flags(sent(v[4], 0)),
        alias: Flags::Flags(sent(v[5], 0)),
        typed: SizedFlags::SizedFlags(sent(v[6], 2)),
        plain: bits(v[7]),
    };
    let back = asn1cpp_wire::per::object::decode_pdu::<NamedBitsRec::NamedBitsRec>(expected);
    check(&format!("{label} decodes"), back.as_ref().is_ok_and(|b| *b == want), f);
}

fn main() {
    let mut f = 0;
    check_rec("'01000000'B", ["01000000"; 8], &[0x02, 0x42, 0x80, 0x08, 0x12, 0x04, 0x84, 0x21, 0x00], &mut f);
    check_rec("all zero", ["00000000"; 8], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00], &mut f);
    check_rec("'1'B", ["1", "1", "10000000", "1", "1", "1", "1", "1"], &[0x01, 0x8a, 0x00, 0x20, 0x18, 0x0c, 0x40, 0x30], &mut f);
    check_rec("'1'B, fixed padded to SIZE (8)", ["1"; 8], &[0x01, 0x8a, 0x00, 0x20, 0x18, 0x0c, 0x40, 0x30], &mut f);
    check_rec(
        "'0110100000'B",
        ["0110100000", "0110100000", "01101000", "0110100000", "0110100000", "0110100000", "0110100000", "0110100000"],
        &[0x05, 0x6b, 0x6b, 0x41, 0xb4, 0x15, 0xa0, 0xad, 0x6d, 0x0a, 0x68, 0x00],
        &mut f,
    );
    check_rec(
        "'101'B, ext outside its root",
        ["101", "101", "10100001", "101000001", "101", "101", "101", "101"],
        &[0x03, 0xa6, 0xd0, 0xc2, 0x68, 0x20, 0x74, 0x0e, 0x9a, 0x07, 0x40],
        &mut f,
    );

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "PASSED" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
