// Constructed-form strings in BER (X.690 §8.6.4, §8.7.3, §8.23.6; CER §9.2),
// Rust codegen leg — port of tests/seq/test_constructed_strings.cpp.
//
// tests/vectors/constructed_strings_test.vectors holds, per row, a BER
// encoding with constructed strings (asn1c's CER, or a worked example from
// X.690) and asn1c's DER of the same value. Decoding the BER must give the
// value the DER gives, and re-encoding either must give the DER.
// Malformed segment structures must fail to decode, with the C++ messages.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::containing::ContainedStatus;
use asn1cpp_wire::spec::choice::BerTagging;
use asn1cpp_wire::spec::object::{AsMemberRef, Asn1Pdu, MemberRef, MemberRefMut};
use asn1cpp_wire::Reader;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Decode `ber` as `T` (the whole input), then re-encode it.
fn roundtrip<T: Asn1Pdu>(ber: &[u8]) -> Result<Vec<u8>, String> {
    let mut v = T::default();
    let mut r = Reader::new(ber);
    asn1cpp_wire::ber::object::decode_pdu_into(&mut v, &mut r).map_err(|e| e.message)?;
    if !r.at_end() {
        return Err("trailing octets".into());
    }
    asn1cpp_wire::ber::object::encode_pdu(&v).map_err(|e| format!("{e:?}"))
}

/// `roundtrip` for a builtin alias (a top-level BIT STRING or VisibleString),
/// which has no `Asn1Pdu` root: decoded and encoded through the primitive
/// dispatch with its natural tag.
fn roundtrip_alias<T: AsMemberRef + Default>(ber: &[u8]) -> Result<Vec<u8>, String> {
    use asn1cpp_wire::spec::primitive::{ber_decode_primitive, ber_encode_primitive};
    let mut v = T::default();
    let mut r = Reader::new(ber);
    let MemberRefMut::Primitive(p) = v.as_member_ref_mut() else { panic!("not a primitive alias") };
    ber_decode_primitive(p, BerTagging::Delegate, &mut r).map_err(|e| e.message)?;
    if !r.at_end() {
        return Err("trailing octets".into());
    }
    let MemberRef::Primitive(p) = v.as_member_ref() else { unreachable!() };
    let mut out = Vec::new();
    ber_encode_primitive(p, BerTagging::Delegate, &mut out).map_err(|e| format!("{e:?}"))?;
    Ok(out)
}

fn by_type(name: &str, ber: &[u8]) -> Result<Vec<u8>, String> {
    match name {
        "Tagged" => roundtrip::<Tagged::Tagged>(ber),
        "Plain" => roundtrip::<Plain::Plain>(ber),
        "Bits" => roundtrip_alias::<Bits::Bits>(ber),
        "Name" => roundtrip_alias::<Name::Name>(ber),
        "Wrapped" => roundtrip::<Wrapped::Wrapped>(ber),
        "Opt" => roundtrip::<Opt::Opt>(ber),
        "OptSet" => roundtrip::<OptSet::OptSet>(ber),
        "CtxChoice" => roundtrip::<CtxChoice::CtxChoice>(ber),
        "NestChoice" => roundtrip::<NestChoice::NestChoice>(ber),
        "MixChoice" => roundtrip::<MixChoice::MixChoice>(ber),
        "Num" => roundtrip::<Num::Num>(ber),
        "When" => roundtrip::<When::When>(ber),
        "Holder" => roundtrip::<Holder::Holder>(ber),
        _ => panic!("unknown type {name}"),
    }
}

fn vectors(path: &str, f: &mut i32) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut rows = 0;
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (ty, source, ber, der) = (cols[0], cols[1], cols[2], cols[3]);
        rows += 1;
        let label = format!("{ty} ({source}, row {rows})");
        let from_ber = by_type(ty, &unhex(ber));
        let note = from_ber.as_ref().err().map(|e| format!(": {e}")).unwrap_or_default();
        check(&format!("{label}: BER decodes{note}"), from_ber.is_ok(), f);
        check(&format!("{label}: BER re-encodes to asn1c's DER"), from_ber.as_deref().map(hex).ok().as_deref() == Some(der), f);
        let from_der = by_type(ty, &unhex(der));
        check(&format!("{label}: DER re-encodes to itself"), from_der.map(|b| hex(&b)).ok().as_deref() == Some(der), f);
    }
    check("vector rows read", rows == 6, f);
}

fn accepted(label: &str, ty: &str, ber: &str, der: &str, f: &mut i32) {
    let o = by_type(ty, &unhex(ber));
    let note = o.as_ref().err().map(|e| format!(": {e}")).unwrap_or_default();
    check(&format!("{label}{note}"), o.map(|b| hex(&b)).ok().as_deref() == Some(der), f);
}

fn refused(label: &str, ty: &str, ber: &[u8], error: &str, f: &mut i32) {
    match by_type(ty, ber) {
        Ok(_) => check(&format!("{label}: decoded"), false, f),
        Err(e) => check(&format!("{label}: {e}"), e.contains(error), f),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 2, "usage: constructed_strings constructed_strings_test.vectors");
    let mut f = 0;
    vectors(&args[1], &mut f);

    accepted("empty constructed VisibleString", "Name", "3A00", "1A00", &mut f);
    accepted("empty constructed indefinite VisibleString", "Name", "3A800000", "1A00", &mut f);
    accepted("empty constructed BIT STRING", "Bits", "2300", "030100", &mut f);
    accepted("nested constructed segment", "Name", "3A0B240504034A6F6E04026573", "1A054A6F6E6573", &mut f);
    accepted("nested indefinite segment", "Name", "3A80248004034A6F6E0000040265730000", "1A054A6F6E6573", &mut f);
    accepted("segments at several nesting levels", "Name",
             "3A80248004014124800401420000040143000024060401440401450401460000", "1A06414243444546", &mut f);
    accepted("CONTAINING value split across segments", "Wrapped",
             "300DA00B04021A0504054A6F6E6573", "300980071A054A6F6E6573", &mut f);
    accepted("BIT STRING, unused bits in the last segment", "Bits", "230803020080030205E0", "03030580E0", &mut f);
    accepted("constructed OPTIONAL and extension members", "Opt",
             "3080A08004024A6F04016E0000A2070402ABCD0401EF0000", "300A80034A6F6E8203ABCDEF", &mut f);
    accepted("constructed OPTIONAL character string", "Opt", "3080A10504034A6F6E0000", "300581034A6F6E", &mut f);
    accepted("SET members out of order, one constructed", "OptSet",
             "310AA1050403414243800141", "31088001418103414243", &mut f);

    refused("character string segment with its own tag", "Name", &unhex("3A051A034A6F6E"),
            "segment of a constructed string is not an OCTET STRING", &mut f);
    refused("BIT STRING segment with an OCTET STRING tag", "Bits", &unhex("2304040200FF"),
            "segment of a constructed BIT STRING is not a BIT STRING", &mut f);
    refused("end-of-contents in a definite constructed string", "Name", &unhex("3A0404000000"),
            "segment of a constructed string is not an OCTET STRING", &mut f);
    refused("unused bits before the last BIT STRING segment", "Bits", &unhex("230803020180030200FF"),
            "BIT STRING segment other than the last has unused bits", &mut f);
    refused("BIT STRING segment without its unused-bits octet", "Bits", &unhex("23020300"),
            "BIT STRING segment is empty", &mut f);
    refused("BIT STRING segment with unused bits and no octets", "Bits", &unhex("2303030103"),
            "BIT STRING segment has 3 unused bits in 0 octets", &mut f);
    refused("IMPLICIT member segment with the member's tag", "Tagged", &unhex("300DA00680044A6F6E658101008200"),
            "segment of a constructed string is not an OCTET STRING", &mut f);

    // The contained value is decoded from the joined segments, not from the segment TLVs.
    let w: Result<Wrapped::Wrapped, _> = asn1cpp_wire::ber::object::decode_pdu(&unhex("300DA00B04021A0504054A6F6E6573"));
    check("CONTAINING value decoded from the joined segments",
          w.as_ref().is_ok_and(|w| w.c.status() == ContainedStatus::Decoded
                                   && w.c.value().is_some_and(|n| n.0 .0.as_str() == "Jones")), &mut f);

    // asn1c's limit: 29 nested segments inside the string decode, 30 do not.
    let nested = |n: usize| [vec![0x3Au8, 0x80], [0x24u8, 0x80].repeat(n), vec![0x04, 0x01, 0x41], vec![0u8; 2 * (n + 1)]].concat();
    accepted("segments nested 29 deep", "Name", &hex(&nested(29)), "1A0141", &mut f);
    refused("segments nested 30 deep", "Name", &nested(30), "constructed string segments nest deeper than 30 levels", &mut f);
    refused("segments nested 300 deep", "Name", &nested(300), "constructed string segments nest deeper than 30 levels", &mut f);

    // Segmented CHOICE alternatives, through each alternative lookup.
    accepted("CHOICE context-tag index, segmented alternative", "CtxChoice", "A006040141040142", "80024142", &mut f);
    accepted("CHOICE context-tag index, segmented character string", "CtxChoice", "A106040141040142", "81024142", &mut f);
    accepted("CHOICE dispatch table, segmented alternative", "NestChoice", "A206040141040142", "82024142", &mut f);
    accepted("CHOICE dispatch table, via the untagged CHOICE", "NestChoice", "A106040141040142", "81024142", &mut f);
    accepted("CHOICE linear scan, segmented IMPLICIT alternative", "MixChoice", "A006040141040142", "80024142", &mut f);
    accepted("CHOICE linear scan, segmented untagged string", "MixChoice", "3606040141040142", "16024142", &mut f);

    // Forms X.690 does not allow (asn1c refuses each too).
    refused("constructed IMPLICIT INTEGER", "Num", &unhex("3005A103020105"), "expected tag", &mut f);
    refused("UTCTime member with an OCTET STRING tag", "When", &unhex("300724050403313233"), "expected tag", &mut f);
    refused("OPTIONAL SEQUENCE in primitive form", "Holder", &unhex("30051003020105"), "expected tag", &mut f);

    println!("{}", if f == 0 { "all passed" } else { "FAILED" });
    std::process::exit(if f == 0 { 0 } else { 1 });
}
