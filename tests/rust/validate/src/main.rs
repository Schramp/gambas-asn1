// Rust leg of the constraint validation test (validate_test.asn1); mirrors
// tests/seq/test_validate.cpp. Every member is typed by a named constrained
// type, whose bounds live in that type's own `{Type}_CONSTRAINTS`; the
// SEQUENCE walker checks each member against them on encode and decode.
// ENUMERATED values outside the root cannot be built in Rust (a generated
// enum only has the declared variants), so the C++ out-of-map cases have no
// counterpart here.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::ber::object::{decode_pdu, encode_pdu};
use asn1cpp_wire::spec::object::Asn1Pdu;
use asn1cpp_wire::bit_string::BitString;
use asn1cpp_wire::integer::{Integer, UInteger};
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::strings::{BmpString, Ia5String, NumericString, PrintableString, UniversalString, Utf8String, VisibleString};
use asn1cpp_wire::validate::{reset_validate_fail_count, validate_fail_count};

static mut FAILURES: u32 = 0;

fn report(label: &str, expected: u64, got: u64) {
    if got == expected {
        println!("  \x1b[32mPASS\x1b[0m  {label} ({got} fail{})", if got == 1 { "" } else { "s" });
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label} — expected {expected} fails, got {got}");
        unsafe { FAILURES += 1 };
    }
}

/// Validate-counter delta of one BER encode of `v`.
fn expect_delta<T: Asn1Pdu>(label: &str, v: T, expected: u64) {
    reset_validate_fail_count();
    let _ = encode_pdu(&v);
    report(label, expected, validate_fail_count());
}

/// Validate-counter delta of a BER encode of `v` plus the decode of its octets.
fn expect_roundtrip<T: Asn1Pdu + Default + PartialEq + std::fmt::Debug>(label: &str, v: T, expected: u64) {
    reset_validate_fail_count();
    let ber = encode_pdu(&v).expect("encode");
    let back = decode_pdu::<T>(&ber).expect("decode");
    assert_eq!(back, v, "{label}: round trip");
    report(label, expected, validate_fail_count());
}

fn int(v: i64) -> Integer { Integer(v) }
fn os(n: usize) -> OctetString { OctetString(vec![0; n]) }
fn bits(bytes: &[u8], unused: u8) -> BitString { BitString { bytes: bytes.to_vec(), unused_bits: unused } }

fn main() {
    println!("\n=== Validation of members typed by named constrained types ===\n");

    println!("PercentInt (0..100)");
    let pct = |v| HasPct::HasPct { v: PercentInt::PercentInt(int(v)) };
    expect_delta("just below 0  → fail", pct(-1), 1);
    expect_delta("exactly 0     → pass", pct(0), 0);
    expect_delta("exactly 100   → pass", pct(100), 0);
    expect_delta("just above 100→ fail", pct(101), 1);

    println!("Tariff (1000..2000)");
    let tariff = |v| HasTariff::HasTariff { v: Tariff::Tariff(int(v)) };
    expect_delta("just below 1000 → fail", tariff(999), 1);
    expect_delta("exactly 1000    → pass", tariff(1000), 0);
    expect_delta("exactly 2000    → pass", tariff(2000), 0);
    expect_delta("just above 2000 → fail", tariff(2001), 1);

    println!("PositiveInt (10..MAX)");
    let pos = |v| HasPos::HasPos { v: PositiveInt::PositiveInt(UInteger(v)) };
    expect_delta("just below 10   → fail", pos(9), 1);
    expect_delta("exactly 10      → pass", pos(10), 0);
    expect_delta("large value     → pass", pos(1_000_000), 0);
    expect_delta("zero (below lb) → fail", pos(0), 1);

    println!("SignedSmall (-50..50)");
    let signed = |v| HasSigned::HasSigned { v: SignedSmall::SignedSmall(int(v)) };
    expect_delta("just below -50 → fail", signed(-51), 1);
    expect_delta("exactly -50    → pass", signed(-50), 0);
    expect_delta("exactly 50     → pass", signed(50), 0);
    expect_delta("just above 50  → fail", signed(51), 1);

    println!("NegRange (-1000..-1)");
    let neg = |v| HasNeg::HasNeg { v: NegRange::NegRange(int(v)) };
    expect_delta("just below -1000  → fail", neg(-1001), 1);
    expect_delta("exactly -1000     → pass", neg(-1000), 0);
    expect_delta("exactly -1        → pass", neg(-1), 0);
    expect_delta("just above -1 (0) → fail", neg(0), 1);

    println!("WideUnsigned (5..1000000)");
    let wide = |v| HasWide::HasWide { v: WideUnsigned::WideUnsigned(int(v)) };
    expect_delta("just below 5       → fail", wide(4), 1);
    expect_delta("exactly 5          → pass", wide(5), 0);
    expect_delta("exactly 1000000    → pass", wide(1_000_000), 0);
    expect_delta("just above 1000000 → fail", wide(1_000_001), 1);

    println!("\nTinyBlob OCTET STRING (SIZE 2..4)");
    let tiny = |n| HasTiny::HasTiny { v: TinyBlob::TinyBlob(os(n)) };
    expect_delta("size 1 (under)    → fail", tiny(1), 1);
    expect_delta("size 2 (boundary) → pass", tiny(2), 0);
    expect_delta("size 4 (boundary) → pass", tiny(4), 0);
    expect_delta("size 5 (over)     → fail", tiny(5), 1);

    println!("MidBlob OCTET STRING (SIZE 5..12)");
    let mid = |n| HasMid::HasMid { v: MidBlob::MidBlob(os(n)) };
    expect_delta("size 4 (under)     → fail", mid(4), 1);
    expect_delta("size 5 (boundary)  → pass", mid(5), 0);
    expect_delta("size 12 (boundary) → pass", mid(12), 0);
    expect_delta("size 13 (over)     → fail", mid(13), 1);

    println!("FixedBlob OCTET STRING (SIZE 8)");
    let fixed = |n| HasFixed::HasFixed { v: FixedBlob::FixedBlob(os(n)) };
    expect_delta("size 7 (under) → fail", fixed(7), 1);
    expect_delta("size 8 (exact) → pass", fixed(8), 0);
    expect_delta("size 9 (over)  → fail", fixed(9), 1);

    println!("\nFlagsByte BIT STRING (SIZE 8)");
    let fb = |b: &[u8], u| HasFlagsByte::HasFlagsByte { v: FlagsByte::FlagsByte(bits(b, u)) };
    expect_delta("7 bits (under) → fail", fb(&[0xff], 1), 1);
    expect_delta("8 bits (exact) → pass", fb(&[0xff], 0), 0);
    expect_delta("16 bits (over) → fail", fb(&[0xff, 0xff], 0), 1);

    println!("FlagsRange BIT STRING (SIZE 16..24)");
    let fr = |b: &[u8], u| HasFlagsRange::HasFlagsRange { v: FlagsRange::FlagsRange(bits(b, u)) };
    expect_delta("15 bits (under)    → fail", fr(&[0xff, 0xff], 1), 1);
    expect_delta("16 bits (boundary) → pass", fr(&[0xff, 0xff], 0), 0);
    expect_delta("24 bits (boundary) → pass", fr(&[0xff, 0xff, 0xff], 0), 0);
    expect_delta("32 bits (over)     → fail", fr(&[0xff, 0xff, 0xff, 0xff], 0), 1);

    println!("\nCode NumericString (SIZE 3..6)");
    let code = |s: &str| HasCode::HasCode { v: Code::Code(NumericString(s.into())) };
    expect_delta("size 2 (under)    → fail", code("12"), 1);
    expect_delta("size 3 (boundary) → pass", code("123"), 0);
    expect_delta("size 6 (boundary) → pass", code("123456"), 0);
    expect_delta("size 7 (over)     → fail", code("1234567"), 1);
    expect_delta("alphabet ('X')    → fail", code("12X"), 1);

    println!("Name PrintableString (SIZE 2..20)");
    let name = |s: &str| HasName::HasName { v: Name::Name(PrintableString(s.into())) };
    expect_delta("size 1 (under)     → fail", name("x"), 1);
    expect_delta("size 2 (boundary)  → pass", name("hi"), 0);
    expect_delta("size 20 (boundary) → pass", name(&"a".repeat(20)), 0);
    expect_delta("size 21 (over)     → fail", name(&"a".repeat(21)), 1);
    expect_delta("alphabet ('#')     → fail", name("hi#bad"), 1);

    println!("Token IA5String (SIZE 4..10)");
    let token = |s: &str| HasToken::HasToken { v: Token::Token(Ia5String(s.into())) };
    expect_delta("size 3 (under)     → fail", token("abc"), 1);
    expect_delta("size 4 (boundary)  → pass", token("abcd"), 0);
    expect_delta("size 10 (boundary) → pass", token(&"a".repeat(10)), 0);
    expect_delta("size 11 (over)     → fail", token(&"a".repeat(11)), 1);
    expect_delta("alphabet (U+0080)  → fail", token("ab\u{80}x"), 1);

    println!("Visi VisibleString (SIZE 6..12)");
    let visi = |s: &str| HasVisi::HasVisi { v: Visi::Visi(VisibleString(s.into())) };
    expect_delta("size 5 (under)     → fail", visi("hello"), 1);
    expect_delta("size 6 (boundary)  → pass", visi("hellos"), 0);
    expect_delta("size 12 (boundary) → pass", visi(&"a".repeat(12)), 0);
    expect_delta("size 13 (over)     → fail", visi(&"a".repeat(13)), 1);
    expect_delta("alphabet (0x01)    → fail", visi("hellosx\x01"), 1);

    println!("\nHexDigit IA5String (FROM 0-9A-F, SIZE 1..8)");
    let hex = |s: &str| HasHex::HasHex { v: HexDigit::HexDigit(Ia5String(s.into())) };
    expect_delta("\"DEADBEEF\" valid → pass", hex("DEADBEEF"), 0);
    expect_delta("size 1 (boundary) → pass", hex("0"), 0);
    expect_delta("empty (under)     → fail", hex(""), 1);
    expect_delta("size 10 (over)    → fail", hex("0123456789"), 1);
    expect_delta("lowercase (FROM)  → fail", hex("DEADbeef"), 1);
    expect_delta("'G','O' (FROM)    → fail", hex("DEADGOOD"), 1);

    println!("YesNo IA5String (FROM N|Y, SIZE 1..3)");
    let yn = |s: &str| HasYesNo::HasYesNo { v: YesNo::YesNo(Ia5String(s.into())) };
    expect_delta("\"Y\" valid         → pass", yn("Y"), 0);
    expect_delta("size 3 (boundary)  → pass", yn("NYN"), 0);
    expect_delta("empty (under)      → fail", yn(""), 1);
    expect_delta("size 4 (over)      → fail", yn("NYNY"), 1);
    expect_delta("lowercase 'y'      → fail", yn("y"), 1);
    expect_delta("'X' (FROM)         → fail", yn("YX"), 1);

    println!("Vowels PrintableString (FROM aeiou, SIZE 1..5)");
    let vow = |s: &str| HasVowels::HasVowels { v: Vowels::Vowels(PrintableString(s.into())) };
    expect_delta("\"aeiou\" valid    → pass", vow("aeiou"), 0);
    expect_delta("size 1 (boundary) → pass", vow("a"), 0);
    expect_delta("empty (under)     → fail", vow(""), 1);
    expect_delta("size 6 (over)     → fail", vow("aeioua"), 1);
    expect_delta("'h','l' (FROM)    → fail", vow("hello"), 1);
    expect_delta("uppercase (FROM)  → fail", vow("AEIOU"), 1);

    println!("\nUmlauts UTF8String (SIZE 1..4)");
    let uml = |s: &str| HasUmlauts::HasUmlauts { v: Umlauts::Umlauts(Utf8String(s.into())) };
    expect_delta("4 chars, 8 bytes → pass", uml("ÄÖÜß"), 0);
    expect_delta("5 chars (over)   → fail", uml("€€€€€"), 1);

    println!("Pair BMPString (SIZE 1..2)");
    let pair = |b: &[u8]| HasPair::HasPair { v: Pair::Pair(BmpString(b.to_vec())) };
    expect_delta("2 chars, 4 bytes → pass", pair(b"\0A\0B"), 0);
    expect_delta("3 chars (over)   → fail", pair(b"\0A\0B\0C"), 1);

    println!("Caps BMPString (FROM \"A\"..\"Z\")");
    let caps = |b: &[u8]| HasCaps::HasCaps { v: Caps::Caps(BmpString(b.to_vec())) };
    expect_delta("\"AZ\" (FROM)   → pass", caps(b"\0A\0Z"), 0);
    expect_delta("'a' (FROM)     → fail", caps(b"\0a"), 1);
    expect_delta("U+0141 (FROM)  → fail", caps(b"\x01A"), 1);

    println!("Quad UniversalString (SIZE 1..2)");
    let quad = |b: &[u8]| HasQuad::HasQuad { v: Quad::Quad(UniversalString(b.to_vec())) };
    expect_delta("2 chars, 8 bytes → pass", quad(b"\0\0\0A\0\0\0B"), 0);
    expect_delta("3 chars (over)   → fail", quad(b"\0\0\0A\0\0\0B\0\0\0C"), 1);

    println!("\nShortList SEQUENCE OF (SIZE 1..3)");
    let short = |v: &[i64]| HasShortList::HasShortList { v: ShortList::ShortList(v.iter().map(|&x| PercentInt::PercentInt(int(x))).collect()) };
    expect_delta("size 0 (under)    → fail", short(&[]), 1);
    expect_delta("size 1 (boundary) → pass", short(&[10]), 0);
    expect_delta("size 3 (boundary) → pass", short(&[10, 20, 30]), 0);
    expect_delta("size 4 (over)     → fail", short(&[10, 20, 30, 40]), 1);

    println!("MidList SEQUENCE OF (SIZE 2..8)");
    let midl = |n: i64| HasMidList::HasMidList { v: MidList::MidList((1..=n).map(|x| SignedSmall::SignedSmall(int(x))).collect()) };
    expect_delta("size 1 (under)    → fail", midl(1), 1);
    expect_delta("size 2 (boundary) → pass", midl(2), 0);
    expect_delta("size 8 (boundary) → pass", midl(8), 0);
    expect_delta("size 9 (over)     → fail", midl(9), 1);

    println!("ByteCount (0..MAX)");
    let bc = |v| HasByteCount::HasByteCount { v: ByteCount::ByteCount(UInteger(v)) };
    expect_delta("exactly 0    → pass", bc(0), 0);
    expect_delta("large value  → pass", bc(1_000_000), 0);
    expect_delta("above i64::MAX → pass", bc(i64::MAX as u64 + 1), 0);

    println!("\n=== Decode-side validation (encode + decode) ===");
    expect_roundtrip("PercentInt valid   → 0", pct(50), 0);
    expect_roundtrip("PercentInt invalid → 2", pct(200), 2);
    expect_roundtrip("Tariff valid       → 0", tariff(1500), 0);
    expect_roundtrip("Tariff invalid     → 2", tariff(500), 2);
    expect_roundtrip("TinyBlob valid (size 3)   → 0", tiny(3), 0);
    expect_roundtrip("TinyBlob invalid (size 1) → 2", tiny(1), 2);
    expect_roundtrip("Code invalid ('X')        → 2", code("12X"), 2);

    let failures = unsafe { FAILURES };
    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
