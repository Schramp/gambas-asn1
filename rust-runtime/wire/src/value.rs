//! Builtin primitive leaf types' `TypeTag` impls, plus their per-codec unit
//! tests (each run through `spec::primitive`'s production dispatch via
//! `spec::primitive::test_codec`).
//!
//! Primitives carry no codec trait: every codec reaches a primitive value
//! through `MemberRef::Primitive(PrimitiveRef)` and the matching
//! `spec::primitive::{ber,xer,jer,per}_{encode,decode}_primitive` function.

#[cfg(test)]
mod per_blanket_tests {
    use crate::integer::Integer;
    use crate::constraints::Constraints;
    use crate::per::{reader::Reader, writer::Writer};

    fn ranged(lo: i64, hi: i64) -> Constraints {
        Constraints {
            flags: Constraints::CONSTRAINED,
            range_bits: (64 - ((hi - lo) as u64).leading_zeros()),
            lower_bound: lo,
            upper_bound: hi,
            ..Default::default()
        }
    }

    fn bytes_of(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.flush();
        w.into_bytes()
    }

    #[test]
    fn i64_trait_path_matches_free_function_and_roundtrips() {
        let c = ranged(0, 15);
        let via_trait = bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&Integer(9), w, &c));
        let direct = bytes_of(|w| crate::per::integer::encode_int(w, &c, 9));
        assert_eq!(via_trait, direct);
        let mut back = Integer(0);
        crate::spec::primitive::test_codec::per_decode_into(&mut back, &mut Reader::new(&via_trait), &c).unwrap();
        assert_eq!(back, 9);
    }

    #[test]
    fn i64_validate_uses_the_passed_constraints() {
        let c = ranged(0, 15);
        assert_eq!(crate::constraints::validate_s64(20, &c), -5);
        assert_eq!(crate::constraints::validate_s64(5, &c), 0);
        assert_eq!(crate::constraints::validate_s64(20, &crate::constraints::UNCONSTRAINED), 0);
    }

    #[test]
    fn octet_string_per_roundtrips_and_validates_size() {
        let c = Constraints { flags: Constraints::SIZE_CONSTRAINED, size_range_bits: 2, size_lower: 1, size_upper: 3, ..Default::default() };
        let v = crate::octet_string::OctetString(vec![1, 2]);
        let enc = bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&v, w, &c));
        let mut back = crate::octet_string::OctetString::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut back, &mut Reader::new(&enc), &c).unwrap();
        assert_eq!(back, v);
        assert_eq!(crate::constraints::validate_size(5, &c), -2);
    }

    #[test]
    fn string_kinds_use_their_own_tag_for_the_alphabet_width() {
        let c = crate::constraints::UNCONSTRAINED;
        let num = crate::strings::NumericString("12345".to_string());
        let ia5 = crate::strings::Ia5String("12345".to_string());
        // NumericString packs 4 bits/char, IA5String 7 — different lengths on the wire.
        assert_ne!(bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&num, w, &c)), bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&ia5, w, &c)));
        let mut back = crate::strings::NumericString::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut back, &mut Reader::new(&bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&num, w, &c))), &c).unwrap();
        assert_eq!(back, num);
    }

    #[test]
    fn seq_of_integer_reflective_per_matches_size_field_plus_element_loop() {
        static ELEM: Constraints = Constraints {
            flags: Constraints::CONSTRAINED, range_bits: 4, lower_bound: 0, upper_bound: 15,
            lower_u64: 0, upper_u64: 0, size_range_bits: 0, size_lower: 0, size_upper: 0,
            encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,
        };
        let coll = Constraints {
            flags: Constraints::SIZE_CONSTRAINED, size_range_bits: 3, size_lower: 0, size_upper: 7,
            element: Some(&ELEM), ..Default::default()
        };
        let v = crate::ber::sequence::SeqOf(vec![Integer(1), Integer(9), Integer(15)]);
        let via_walker = bytes_of(|w| crate::per::object::encode_seqof_content(&v, &coll, w).unwrap());
        let manual = bytes_of(|w| {
            w.put_bits(3, 3); // SIZE (0..7): count 3 in 3 bits
            for x in [1i64, 9, 15] {
                crate::per::integer::encode_int(w, &ELEM, x);
            }
        });
        assert_eq!(via_walker, manual);
        let mut back = crate::ber::sequence::SeqOf::<Integer>(vec![]);
        crate::per::object::decode_seqof_content_into(&mut back, &coll, &mut Reader::new(&via_walker)).unwrap();
        assert_eq!(back.0, vec![Integer(1), Integer(9), Integer(15)]);
    }

    #[test]
    fn wide_string_trait_path_roundtrips_raw_bytes() {
        let c = crate::constraints::UNCONSTRAINED;
        let v = crate::strings::BmpString(vec![0x00, 0x41, 0x00, 0x42]);
        let enc = bytes_of(|w| crate::spec::primitive::test_codec::per_encode(&v, w, &c));
        let mut back = crate::strings::BmpString::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut back, &mut Reader::new(&enc), &c).unwrap();
        assert_eq!(back, v);
    }
}

#[cfg(test)]
mod tests {
    use crate::xer::reader::XerReader;
    use crate::ber::reader::Reader;
    use crate::boolean::Boolean;
    use crate::integer::Integer;
    use crate::null::Null;
    use crate::real::Real;

    #[test]
    fn i64_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&Integer(300), &mut out);
        assert_eq!(out, vec![0x02, 0x02, 0x01, 0x2C]);

        let mut r = Reader::new(&out);
        let mut got = Integer(0);
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, 300);
    }

    #[test]
    fn i64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        crate::spec::primitive::test_codec::xer_encode(&Integer(1), &mut out, 0);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got = Integer(0);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1);
    }

    #[test]
    fn i64_xer_negative_and_whitespace() {
        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Integer(-42), &mut out, 0);
        assert_eq!(out, "-42");

        let mut r = XerReader::new("  -42  ");
        let mut got = Integer(0);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, -42);
    }

    #[test]
    fn i64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got = Integer(0);
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn bool_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&Boolean(true), &mut out);
        assert_eq!(out, vec![0x01, 0x01, 0xFF]);

        let mut r = Reader::new(&out);
        let mut got = Boolean(false);
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert!(got.0);
    }

    #[test]
    fn unit_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&Null, &mut out);
        assert_eq!(out, vec![0x05, 0x00]);

        let mut r = Reader::new(&out);
        let mut got = Null;
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, Null);
    }

    #[test]
    fn unit_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        crate::spec::primitive::test_codec::xer_encode(&Null, &mut out, 0);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = Null;
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert_eq!(got, Null);
    }

    #[test]
    fn bit_string_ber_round_trips_through_the_trait() {
        use crate::bit_string::BitString;

        let v = BitString { bytes: vec![0b1010_1000], unused_bits: 4 };
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&v, &mut out);
        assert_eq!(out, vec![0x03, 0x02, 0x04, 0b1010_1000]);

        let mut r = Reader::new(&out);
        let mut got = BitString::default();
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_xer_round_trips_wrapped_by_hand() {
        use crate::bit_string::BitString;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        // 1010 0000, 4 unused bits -> logical bits "1010" (bit_count=4).
        // Padding bits are zero here deliberately: XER only carries the
        // logical bit sequence (bit_count), zero-filling padding on decode
        // (X.680's XMLBitStringValue captures no padding-bit-value
        // information) — a fixture with *non-zero* padding wouldn't
        // round-trip byte-for-byte through XER, which is expected, not a bug.
        let v = BitString { bytes: vec![0b1010_0000], unused_bits: 4 };
        let mut out = String::new();
        write_open_tag(&mut out, "flags");
        crate::spec::primitive::test_codec::xer_encode(&v, &mut out, 0);
        write_close_tag(&mut out, "flags");
        assert_eq!(out, "<flags>\n    1010\n</flags>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flags").unwrap();
        let mut got = BitString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("flags").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_xer_empty_round_trips() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("");
        let mut got = BitString { bytes: vec![0xFF], unused_bits: 0 };
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, BitString::default());
    }

    #[test]
    fn bit_string_xer_rejects_invalid_character() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("10G");
        let mut got = BitString::default();
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn bit_string_xer_strict_rejects_hex() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("04AA");
        let mut got = BitString::default();
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn bit_string_xer_lenient_accepts_hex_pairs() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new_lenient("04AABB");
        let mut got = BitString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, BitString { bytes: vec![0x04, 0xAA, 0xBB], unused_bits: 0 });
    }

    #[test]
    fn bit_string_xer_lenient_pure_binary_string_still_decodes_as_binary() {
        use crate::bit_string::BitString;

        // "0001" has no digit outside 0/1 — indistinguishable from binary,
        // matches asn1c's own heuristic (see xer_decode_into's own doc).
        let mut r = XerReader::new_lenient("0001");
        let mut got = BitString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, BitString { bytes: vec![0b0001_0000], unused_bits: 4 });
    }

    #[test]
    fn bit_string_xer_lenient_rejects_odd_length_hex() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new_lenient("04A");
        let mut got = BitString::default();
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn oid_ber_round_trips_through_the_trait() {
        use crate::oid::ObjectIdentifier;

        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&v, &mut out);
        assert_eq!(out, vec![0x06, 0x03, 0x55, 0x04, 0x03]);

        let mut r = Reader::new(&out);
        let mut got = ObjectIdentifier::default();
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_xer_round_trips_wrapped_by_hand() {
        use crate::oid::ObjectIdentifier;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = String::new();
        write_open_tag(&mut out, "oid");
        crate::spec::primitive::test_codec::xer_encode(&v, &mut out, 0);
        write_close_tag(&mut out, "oid");
        assert_eq!(out, "<oid>2.5.4.3</oid>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("oid").unwrap();
        let mut got = ObjectIdentifier::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("oid").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_xer_single_arc_round_trips() {
        use crate::oid::ObjectIdentifier;

        let mut r = XerReader::new("2");
        let mut got = ObjectIdentifier::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, ObjectIdentifier(vec![2]));
    }

    #[test]
    fn oid_xer_empty_round_trips() {
        use crate::oid::ObjectIdentifier;

        let mut r = XerReader::new("");
        let mut got = ObjectIdentifier(vec![1, 2, 3]);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, ObjectIdentifier::default());
    }

    #[test]
    fn relative_oid_ber_round_trips_through_the_trait() {
        use crate::relative_oid::RelativeOid;

        let v = RelativeOid(vec![8571, 1]);
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&v, &mut out);
        assert_eq!(out, vec![0x0D, 0x03, 0xC2, 0x7B, 0x01]);

        let mut r = Reader::new(&out);
        let mut got = RelativeOid::default();
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn relative_oid_xer_round_trips_wrapped_by_hand() {
        use crate::relative_oid::RelativeOid;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let v = RelativeOid(vec![8571, 1]);
        let mut out = String::new();
        write_open_tag(&mut out, "roid");
        crate::spec::primitive::test_codec::xer_encode(&v, &mut out, 0);
        write_close_tag(&mut out, "roid");
        assert_eq!(out, "<roid>8571.1</roid>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("roid").unwrap();
        let mut got = RelativeOid::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("roid").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn relative_oid_xer_empty_round_trips() {
        use crate::relative_oid::RelativeOid;

        let mut r = XerReader::new("");
        let mut got = RelativeOid(vec![1, 2]);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, RelativeOid::default());
    }

    #[test]
    fn f64_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&Real(1.5), &mut out);

        let mut r = Reader::new(&out);
        let mut got = Real(0.0);
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        crate::spec::primitive::test_codec::xer_encode(&Real(1.5), &mut out, 0);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1.5</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got = Real(0.0);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_zero_preserves_sign() {
        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Real(0.0), &mut out, 0);
        assert_eq!(out, "0");

        // X.693 §17.9: -0.0 is distinct decimal text from +0.0, unlike
        // the special-value keywords (PLUS-INFINITY/NOT-A-NUMBER), which
        // have no sign-of-zero analogue to lose.
        let mut out2 = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Real(-0.0), &mut out2, 0);
        assert_eq!(out2, "-0");
    }

    #[test]
    fn f64_xer_special_values_round_trip() {
        for v in [Real(f64::INFINITY), Real(f64::NEG_INFINITY)] {
            let mut out = String::new();
            crate::spec::primitive::test_codec::xer_encode(&v, &mut out, 0);
            let mut r = XerReader::new(&out);
            let mut got = Real(0.0);
            crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
            assert_eq!(got, v);
        }

        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Real(f64::NAN), &mut out, 0);
        assert_eq!(out, "<NOT-A-NUMBER/>");
        let mut r = XerReader::new(&out);
        let mut got = Real(0.0);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert!(got.is_nan());
    }

    #[test]
    fn f64_xer_trims_trailing_zeros_but_keeps_one_digit() {
        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Real(2.0), &mut out, 0);
        assert_eq!(out, "2.0");
    }

    #[test]
    fn f64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got = Real(0.0);
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn bool_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        crate::spec::primitive::test_codec::xer_encode(&Boolean(true), &mut out, 0);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag><true/></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = Boolean(false);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert!(got.0);
    }

    #[test]
    fn bool_xer_false_round_trips() {
        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&Boolean(false), &mut out, 0);
        assert_eq!(out, "<false/>");

        let mut r = XerReader::new("<false/>");
        let mut got = Boolean(true);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert!(!got.0);
    }

    #[test]
    fn bool_xer_rejects_non_empty_element_form() {
        let mut r = XerReader::new("true");
        let mut got = Boolean(false);
        assert!(crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).is_err());
    }

    #[test]
    fn bool_xer_lenient_accepts_text_content() {
        let mut r = XerReader::new_lenient("true");
        let mut got = Boolean(false);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert!(got.0);

        let mut r = XerReader::new_lenient("false");
        let mut got = Boolean(true);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert!(!got.0);
    }

    #[test]
    fn bool_xer_lenient_still_accepts_empty_element_form() {
        let mut r = XerReader::new_lenient("<true/>");
        let mut got = Boolean(false);
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert!(got.0);
    }

    #[test]
    fn string_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&crate::strings::Ia5String("hi".to_string()), &mut out);
        assert_eq!(out, vec![0x16, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = crate::strings::Ia5String::default();
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got.0, "hi");
    }

    #[test]
    fn string_xer_escapes_and_round_trips() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "label");
        crate::spec::primitive::test_codec::xer_encode(&crate::strings::Ia5String("a<b>&c".to_string()), &mut out, 0);
        write_close_tag(&mut out, "label");
        assert_eq!(out, "<label>a&lt;b&gt;&amp;c</label>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("label").unwrap();
        let mut got = crate::strings::Ia5String::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("label").unwrap();
        assert_eq!(got.0, "a<b>&c");
    }

    #[test]
    fn oid_per_round_trips() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![1, 2, 840, 113549]);
        let mut w = crate::per::writer::Writer::new();
        crate::spec::primitive::test_codec::per_encode(&v, &mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut got = ObjectIdentifier::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut got, &mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_per_length_prefix_matches_ber_content_byte_count() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![2, 5, 4, 3]); // commonName, 3 content bytes
        let mut ber_content = Vec::new();
        crate::oid::encode_object_identifier_content(&mut ber_content, &v);
        let mut w = crate::per::writer::Writer::new();
        crate::spec::primitive::test_codec::per_encode(&v, &mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let per_bytes = w.into_bytes();
        assert_eq!(per_bytes[0] as usize, ber_content.len());
        assert_eq!(&per_bytes[1..], &ber_content[..]);
    }

    #[test]
    fn relative_oid_per_round_trips() {
        use crate::relative_oid::RelativeOid;
        let v = RelativeOid(vec![8571, 1]);
        let mut w = crate::per::writer::Writer::new();
        crate::spec::primitive::test_codec::per_encode(&v, &mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut got = RelativeOid::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut got, &mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    // -----------------------------------------------------------------
    // JER — known-correct JSON strings are from the C++ reference's own
    // `tests/jer/*.cpp` (ground truth, not just round-trip-with-itself).

    #[test]
    fn integer_jer_round_trips_and_matches_reference() {
        use crate::integer::Integer;
        let v = Integer(42);
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "42");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Integer::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);

        let neg = Integer(-1);
        let mut out2 = String::new();
        crate::spec::primitive::test_codec::jer_encode(&neg, &mut out2);
        assert_eq!(out2, "-1");
    }

    #[test]
    fn boolean_jer_round_trips_and_matches_reference() {
        use crate::boolean::Boolean;
        for (v, text) in [(true, "true"), (false, "false")] {
            let b = Boolean(v);
            let mut out = String::new();
            crate::spec::primitive::test_codec::jer_encode(&b, &mut out);
            assert_eq!(out, text);
            let mut r = crate::jer::reader::Reader::new(&out);
            let mut got = Boolean::default();
            crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
            assert_eq!(got, b);
        }
    }

    #[test]
    fn null_jer_round_trips_and_matches_reference() {
        use crate::null::Null;
        let v = Null;
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "null");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Null;
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
    }

    #[test]
    fn real_jer_special_values_match_reference() {
        // X.697 Table 2: "-0"/"-INF"/"INF"/"NaN" -- not "PLUS-INFINITY"/
        // "MINUS-INFINITY" (that's X.693/XER's spelling, a different
        // clause; confirmed against the standard text directly).
        use crate::real::Real;
        for (v, text) in [
            (f64::NAN, "\"NaN\""),
            (f64::INFINITY, "\"INF\""),
            (f64::NEG_INFINITY, "\"-INF\""),
            (0.0, "0"),
            (-0.0, "\"-0\""),
        ] {
            let r = Real(v);
            let mut out = String::new();
            crate::spec::primitive::test_codec::jer_encode(&r, &mut out);
            assert_eq!(out, text);
        }
    }

    #[test]
    fn real_jer_round_trips_finite_value() {
        use crate::real::Real;
        let v = Real(1.5);
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Real::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got.0, v.0);
    }

    #[test]
    fn oid_jer_round_trips_and_matches_reference() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "\"2.5.4.3\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = ObjectIdentifier::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn octet_string_jer_round_trips_and_matches_reference() {
        use crate::octet_string::OctetString;
        let v = OctetString(vec![0xAB, 0xCD]);
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "\"ABCD\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = OctetString::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_jer_round_trips_and_matches_reference() {
        use crate::bit_string::BitString;
        let v = BitString { bytes: vec![0xAB], unused_bits: 0 };
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "{\"value\":\"AB\",\"length\":8}");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = BitString::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn utf8_string_jer_round_trips() {
        use crate::strings::Utf8String;
        let v = Utf8String("hello".to_string());
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "\"hello\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Utf8String::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn t61_string_jer_uses_hex() {
        use crate::strings::T61String;
        let v = T61String("AB".to_string());
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        // "AB" -> UTF-8 bytes 0x41 0x42 -> hex "4142"
        assert_eq!(out, "\"4142\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = T61String::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn seq_of_jer_round_trips_and_matches_reference() {
        use crate::ber::sequence::SeqOf;
        use crate::integer::Integer;

        let empty: SeqOf<Integer> = SeqOf(vec![]);
        let mut out = String::new();
        crate::jer::object::encode_seqof_into(&empty, &crate::constraints::UNCONSTRAINED, &mut out).unwrap();
        assert_eq!(out, "[]");

        let v: SeqOf<Integer> = SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        let mut out2 = String::new();
        crate::jer::object::encode_seqof_into(&v, &crate::constraints::UNCONSTRAINED, &mut out2).unwrap();
        assert_eq!(out2, "[1,2,3]");
        let mut r = crate::jer::reader::Reader::new(&out2);
        let mut got: SeqOf<Integer> = SeqOf::default();
        crate::jer::object::decode_seqof_into(&mut got, &crate::constraints::UNCONSTRAINED, &mut r).unwrap();
        assert_eq!(got.0, v.0);
    }
}

// TypeTag impls (see type_tag.rs's own module doc).
impl crate::type_tag::TypeTag for crate::integer::Integer {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::integer::UInteger {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::integer::BigInteger {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::boolean::Boolean {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::boolean::BOOLEAN_TAG);
}
impl crate::type_tag::TypeTag for crate::null::Null {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::null::NULL_TAG);
}
impl crate::type_tag::TypeTag for crate::bit_string::BitString {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::bit_string::BIT_STRING_TAG);
}
impl crate::type_tag::TypeTag for crate::oid::ObjectIdentifier {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::oid::OBJECT_IDENTIFIER_TAG);
}
impl crate::type_tag::TypeTag for crate::relative_oid::RelativeOid {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::relative_oid::RELATIVE_OID_TAG);
}
impl crate::type_tag::TypeTag for crate::real::Real {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::real::REAL_TAG);
}
