// Rust leg of the wide INTEGER range PER test (per_int64_bounds_test.asn1);
// mirrors tests/per/test_per_int64_bounds.cpp. Every record is followed by
// micro (0..999999) = 2 in 20 bits.
//
//   - U64Rec.seconds INTEGER (0..2^64−1) and S64Rec.value INTEGER
//     (−2^63..2^63−1): 2^64 values, value − lb in 64 bits (X.691 §11.5.6).
//   - S33Rec.value INTEGER (−2^32..2^32−1): 2^33 values, 33 bits.
//   - UncRec.value INTEGER: unconstrained whole number, length octet plus
//     minimal two's complement (X.691 §11.8, §12.2.6).
//   - A negative BER value for U64Rec has no unsigned storage and fails
//     the decode; an S33Rec value outside its range decodes and records a
//     constraint violation.
//
// S64Rec, S33Rec and UncRec bytes are asn1c's UPER output. asn1c cannot
// encode U64Rec (upper bound above INT64_MAX, Schramp/asn1c#12); its bytes
// equal asn1c's S64Rec bytes for value − 2^63, the same 64-bit field.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::integer::{Integer, UInteger};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

/// Encode `v`, compare with `expected`, decode it back and compare with `v`.
fn check_rec<T>(label: &str, v: T, expected: &[u8], failures: &mut i32)
where
    T: asn1cpp_wire::spec::object::Asn1Pdu + Default + PartialEq + std::fmt::Debug,
{
    check(&format!("{label} encodes"), asn1cpp_wire::per::object::encode_pdu(&v) == expected, failures);
    let back = asn1cpp_wire::per::object::decode_pdu::<T>(expected);
    check(&format!("{label} decodes"), back.as_ref().is_ok_and(|b| *b == v), failures);
}

/// BER {value, micro = 2} with `content` as the value's INTEGER contents.
fn ber_rec(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30, (content.len() + 5) as u8, 0x80, content.len() as u8];
    out.extend_from_slice(content);
    out.extend_from_slice(&[0x81, 0x01, 0x02]);
    out
}

fn u64rec(seconds: u64) -> U64Rec::U64Rec {
    U64Rec::U64Rec { seconds: UInteger(seconds), micro: Integer(2) }
}
fn s64rec(value: i64) -> S64Rec::S64Rec {
    S64Rec::S64Rec { value: Integer(value), micro: Integer(2) }
}
fn s33rec(value: i64) -> S33Rec::S33Rec {
    S33Rec::S33Rec { value: Integer(value), micro: Integer(2) }
}
fn uncrec(value: i64) -> UncRec::UncRec {
    UncRec::UncRec { value: Integer(value), micro: Integer(2) }
}

fn main() {
    let mut f = 0;
    let tail = [0x00, 0x00, 0x20];
    let with_tail = |head: &[u8]| [head, &tail].concat();

    check_rec("U64Rec 1", u64rec(1), &with_tail(&[0, 0, 0, 0, 0, 0, 0, 1]), &mut f);
    check_rec("U64Rec 2^32", u64rec(1 << 32), &with_tail(&[0, 0, 0, 1, 0, 0, 0, 0]), &mut f);
    check_rec("U64Rec 2^32+1", u64rec((1 << 32) + 1), &with_tail(&[0, 0, 0, 1, 0, 0, 0, 1]), &mut f);
    check_rec("U64Rec 2^64-2", u64rec(u64::MAX - 1), &with_tail(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]), &mut f);
    check_rec("U64Rec 2^64-1", u64rec(u64::MAX), &with_tail(&[0xff; 8]), &mut f);

    check_rec("S64Rec -2^63", s64rec(i64::MIN), &with_tail(&[0; 8]), &mut f);
    check_rec("S64Rec -2", s64rec(-2), &with_tail(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]), &mut f);
    check_rec("S64Rec -1", s64rec(-1), &with_tail(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), &mut f);
    check_rec("S64Rec 0", s64rec(0), &with_tail(&[0x80, 0, 0, 0, 0, 0, 0, 0]), &mut f);
    check_rec("S64Rec 2^32", s64rec(1 << 32), &with_tail(&[0x80, 0, 0, 1, 0, 0, 0, 0]), &mut f);
    check_rec("S64Rec 2^32+1", s64rec((1 << 32) + 1), &with_tail(&[0x80, 0, 0, 1, 0, 0, 0, 1]), &mut f);
    check_rec("S64Rec 2^63-1", s64rec(i64::MAX), &with_tail(&[0xff; 8]), &mut f);

    check_rec("S33Rec -2^32", s33rec(-(1 << 32)), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10], &mut f);
    check_rec("S33Rec -2", s33rec(-2), &[0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x10], &mut f);
    check_rec("S33Rec -1", s33rec(-1), &[0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x10], &mut f);
    check_rec("S33Rec 0", s33rec(0), &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10], &mut f);
    check_rec("S33Rec 2^32-1", s33rec((1 << 32) - 1), &[0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x10], &mut f);

    check_rec("UncRec -(2^32+4)", uncrec(-((1 << 32) + 4)), &with_tail(&[0x05, 0xfe, 0xff, 0xff, 0xff, 0xfc]), &mut f);
    check_rec("UncRec -2", uncrec(-2), &with_tail(&[0x01, 0xfe]), &mut f);
    check_rec("UncRec -1", uncrec(-1), &with_tail(&[0x01, 0xff]), &mut f);
    check_rec("UncRec 2^32", uncrec(1 << 32), &with_tail(&[0x05, 0x01, 0, 0, 0, 0]), &mut f);
    check_rec("UncRec 2^32+1", uncrec((1 << 32) + 1), &with_tail(&[0x05, 0x01, 0, 0, 0, 1]), &mut f);
    check_rec("UncRec -2^63", uncrec(i64::MIN), &with_tail(&[0x08, 0x80, 0, 0, 0, 0, 0, 0, 0]), &mut f);
    check_rec("UncRec 2^63-1", uncrec(i64::MAX), &with_tail(&[0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), &mut f);

    use asn1cpp_wire::ber::object::decode_pdu as ber_dec;
    check("U64Rec -1 in BER is rejected", ber_dec::<U64Rec::U64Rec>(&ber_rec(&[0xff])).is_err(), &mut f);
    check("U64Rec -2 in BER is rejected", ber_dec::<U64Rec::U64Rec>(&ber_rec(&[0xfe])).is_err(), &mut f);
    let violates = |content: &[u8]| {
        asn1cpp_wire::validate::reset_validate_fail_count();
        ber_dec::<S33Rec::S33Rec>(&ber_rec(content)).is_ok() && asn1cpp_wire::validate::validate_fail_count() > 0
    };
    check("S33Rec -(2^32+4) in BER records a violation", violates(&[0xfe, 0xff, 0xff, 0xff, 0xfc]), &mut f);
    check("S33Rec 2^32 in BER records a violation", violates(&[0x01, 0x00, 0x00, 0x00, 0x00]), &mut f);
    check("S33Rec -2^32 in BER records no violation", !violates(&[0xff, 0x00, 0x00, 0x00, 0x00]), &mut f);

    println!("\n{} ({f} failure{})", if f > 0 { "FAILED" } else { "PASSED" }, if f == 1 { "" } else { "s" });
    std::process::exit(if f > 0 { 1 } else { 0 });
}
