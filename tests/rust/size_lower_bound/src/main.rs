// Rust leg of the SIZE(lb..MAX) / 64K-edge test (size_lower_bound_test.asn1,
// X.680 §51.5, X.691 §11.9.4); mirrors tests/per/test_size_lower_bound.cpp,
// including its asn1c vectors (cross-checked with Erlang/OTP asn1 -buper).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::bit_string::BitString;
use asn1cpp_wire::constraints::{validate_bit_string, validate_size, Constraints};
use asn1cpp_wire::integer::Integer;
use asn1cpp_wire::octet_string::OctetString;
use asn1cpp_wire::per::object::{decode_pdu, encode_pdu};
use asn1cpp_wire::per::reader::Reader;
use asn1cpp_wire::per::writer::Writer;
use asn1cpp_wire::spec::object::{AsMemberRef, MemberRef, MemberRefMut};
use asn1cpp_wire::spec::primitive::{per_decode_primitive, per_encode_primitive};
use asn1cpp_wire::strings::Ia5String;
use Probe::Probe as Rec;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn probe(os_len: usize, ia5: &str, bit_count: usize, ints: usize) -> Rec {
    let mut p = Rec::default();
    p.os = Os::Os(OctetString((1..=os_len as u8).collect::<Vec<_>>().into()));
    p.ia5 = Ia5::Ia5(Ia5String(ia5.to_string()));
    // 1010 0101 1...: the bit pattern of the vectors below.
    let mut bytes = vec![0u8; bit_count.div_ceil(8)];
    bytes[0] = 0xA5;
    if bit_count > 8 {
        bytes[1] = 0x80;
    }
    p.bits = Bits::Bits(BitString { bytes, unused_bits: ((8 - bit_count % 8) % 8) as u8 });
    p.ints = Ints::Ints([1, 2, 7][..ints].iter().map(|&v| Integer(v)).collect());
    p
}

fn per_encode_octets<T: AsMemberRef>(v: &T, c: &Constraints) -> Vec<u8> {
    let MemberRef::Primitive(p) = v.as_member_ref() else { unreachable!() };
    let mut w = Writer::new();
    per_encode_primitive(p, &mut w, c).expect("encode");
    w.into_bytes()
}

fn per_round_trips<T: AsMemberRef + Default + PartialEq>(v: &T, buf: &[u8], c: &Constraints) -> bool {
    let mut back = T::default();
    let MemberRefMut::Primitive(p) = back.as_member_ref_mut() else { unreachable!() };
    per_decode_primitive(p, &mut Reader::new(buf), c).is_ok() && back == *v
}

fn abs(n: usize) -> String {
    "ab".repeat(n)
}

fn main() {
    let mut failures = 0;

    println!("=== validate: SIZE(lb..MAX) lower bound ===");
    let ok = probe(4, "abc", 8, 2);
    let short = probe(3, "ab", 7, 1);
    check("OCTET STRING (SIZE(4..MAX)) with 4 octets is valid", validate_size(ok.os.0 .0.len(), &Os::Os_CONSTRAINTS) == 0, &mut failures);
    check("IA5String (SIZE(3..MAX)) with 3 chars is valid", validate_size(ok.ia5.0 .0.len(), &Ia5::Ia5_CONSTRAINTS) == 0, &mut failures);
    check("BIT STRING (SIZE(8..MAX)) with 8 bits is valid", validate_bit_string(&ok.bits.0, &Bits::Bits_CONSTRAINTS) == 0, &mut failures);
    check("SEQUENCE (SIZE(2..MAX)) OF with 2 elements is valid", validate_size(ok.ints.0.len(), &Ints::Ints_CONSTRAINTS) == 0, &mut failures);
    check("OCTET STRING (SIZE(4..MAX)) with 3 octets is rejected", validate_size(short.os.0 .0.len(), &Os::Os_CONSTRAINTS) != 0, &mut failures);
    check("IA5String (SIZE(3..MAX)) with 2 chars is rejected", validate_size(short.ia5.0 .0.len(), &Ia5::Ia5_CONSTRAINTS) != 0, &mut failures);
    check("BIT STRING (SIZE(8..MAX)) with 7 bits is rejected", validate_bit_string(&short.bits.0, &Bits::Bits_CONSTRAINTS) != 0, &mut failures);
    check("SEQUENCE (SIZE(2..MAX)) OF with 1 element is rejected", validate_size(short.ints.0.len(), &Ints::Ints_CONSTRAINTS) != 0, &mut failures);

    println!("=== UPER: SIZE(lb..MAX) uses the unconstrained length ===");
    for (label, p, want) in [
        ("Probe{4 octets, \"abc\", 8 bits, 2 ints}", probe(4, "abc", 8, 2), "040102030403c38b1845281140"),
        ("Probe{5 octets, \"abcd\", 9 bits, 3 ints}", probe(5, "abcd", 9, 3), "05010203040504c38b1e409a58195c"),
    ] {
        let buf = encode_pdu(&p).expect("encode");
        check(&format!("{label} encodes to {want}"), hex(&buf) == want, &mut failures);
        check(&format!("{label} round-trips"), decode_pdu::<Rec>(&buf).is_ok_and(|r| r == p), &mut failures);
    }

    println!("=== UPER: 64K edge of the length determinant ===");
    let cases: [(&str, &Constraints, usize, String); 8] = [
        ("Ub65535 SIZE(0..65535)", &Ub65535::Ub65535_CONSTRAINTS, 10, format!("000a{}", abs(10))),
        ("Ub65535 SIZE(0..65535)", &Ub65535::Ub65535_CONSTRAINTS, 200, format!("00c8{}", abs(200))),
        ("Ub65536 SIZE(0..65536)", &Ub65536::Ub65536_CONSTRAINTS, 10, format!("0a{}", abs(10))),
        ("Ub65536 SIZE(0..65536)", &Ub65536::Ub65536_CONSTRAINTS, 200, format!("80c8{}", abs(200))),
        ("Lb10Ub70k SIZE(10..70000)", &Lb10Ub70k::Lb10Ub70k_CONSTRAINTS, 10, format!("0a{}", abs(10))),
        ("Lb10Ub70k SIZE(10..70000)", &Lb10Ub70k::Lb10Ub70k_CONSTRAINTS, 200, format!("80c8{}", abs(200))),
        ("Lb10Max SIZE(10..MAX)", &Lb10Max::Lb10Max_CONSTRAINTS, 10, format!("0a{}", abs(10))),
        ("Lb10Max SIZE(10..MAX)", &Lb10Max::Lb10Max_CONSTRAINTS, 200, format!("80c8{}", abs(200))),
    ];
    for (label, c, n, want) in cases {
        let v = Ub65535::Ub65535(OctetString(vec![0xAB; n].into()));
        check(&format!("{label} n={n} encodes to asn1c bytes"), hex(&per_encode_octets(&v, c)) == want, &mut failures);
    }

    // (type, constraints, n, total size, (offset, value) of each length octet)
    let long: [(&str, &Constraints, usize, usize, &[(usize, u8)]); 4] = [
        ("Ub65535 SIZE(0..65535)", &Ub65535::Ub65535_CONSTRAINTS, 65535, 65537, &[(0, 0xff), (1, 0xff)]),
        ("Ub65536 SIZE(0..65536)", &Ub65536::Ub65536_CONSTRAINTS, 65535, 65538, &[(0, 0xc3), (49153, 0xbf), (49154, 0xff)]),
        ("Lb10Max SIZE(10..MAX)", &Lb10Max::Lb10Max_CONSTRAINTS, 16384, 16386, &[(0, 0xc1), (16385, 0x00)]),
        ("Lb10Ub70k SIZE(10..70000)", &Lb10Ub70k::Lb10Ub70k_CONSTRAINTS, 65536, 65538, &[(0, 0xc4), (65537, 0x00)]),
    ];
    for (label, c, n, total, headers) in long {
        let v = Ub65535::Ub65535(OctetString(vec![0xAB; n].into()));
        let buf = per_encode_octets(&v, c);
        let layout = buf.len() == total
            && buf.iter().enumerate().all(|(i, &b)| {
                headers.iter().find(|h| h.0 == i).map_or(b == 0xAB, |h| b == h.1)
            });
        check(&format!("{label} n={n} matches asn1c layout"), layout, &mut failures);
        check(&format!("{label} n={n} round-trips"), per_round_trips(&v, &buf, c), &mut failures);
    }

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
