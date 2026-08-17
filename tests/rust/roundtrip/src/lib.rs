//! Generated-code + asn1cpp-ber roundtrip check (gambas-asn1#219) — proves
//! the actual codegen -> runtime pipeline, not just that the two pieces are
//! compatible by hand. `point_generated.rs` (via `include!`) is produced by
//! `build.rs`, which pulls in the real `asn1cpp --target=rust` compiler's
//! output — see `tests/CMakeLists.txt`'s `gen_rust_simple_seq` custom target
//! (same generation pattern as `SIMPLE_SEQ_GEN_DIR` on the C++ side).
//!
//! Test cases mirror `tests/ber/seq/test_seq_simple.cpp`'s BER section
//! exactly (same schema, same values, same asn1c-cross-validated wire
//! bytes) — one schema, both languages, directly comparable.
//!
//! `widget_generated.rs` (gambas-asn1#282) is the mixed-type broaden-past-
//! INTEGER counterpart — `Widget` from `tests/asn1/rust_wide_types_test.asn1`
//! (`INTEGER`/`BOOLEAN`/`OCTET STRING`/`IA5String` members). Its expected
//! wire bytes (BER and, since gambas-asn1#283, XER) were captured from the
//! real C++ runtime (`BerCodec`/`XerCodec` encoding the equivalent C++
//! `Widget` value), not hand-derived.
//!
//! `selector_generated.rs` (gambas-asn1#284 BER, #285 XER) is the first
//! table-driven CHOICE — `Selector` from `tests/asn1/rust_choice_test.asn1`,
//! same four alternative kinds `Widget` covers for SEQUENCE. Expected wire
//! bytes (both formats) captured from the real C++ runtime the same way.
//!
//! `gauge_generated.rs` (gambas-asn1#463) is `Gauge` from
//! `tests/asn1/rust_range_test.asn1` — a member with an inline X.680 §19/§51
//! INTEGER value-range constraint. Proves `MemberDescriptor::validate`
//! (`rust-runtime/ber/src/sequence.rs`) is reached through the real
//! generated `{name}_range_delta` free function
//! (`RustBackend::emit_member_type_descriptor`), not just the hand-written
//! `RangedPoint` dogfood type `sequence.rs`'s own unit tests use.
//!
//! `blob_generated.rs` (gambas-asn1#464) is `Blob` from
//! `tests/asn1/rust_size_test.asn1` — OCTET STRING / BIT STRING members
//! with an inline X.680 §22/§21/§51 SIZE constraint, same role for
//! `{name}_size_delta` that `Gauge` plays for `{name}_range_delta`.

include!(concat!(env!("OUT_DIR"), "/point_generated.rs"));
include!(concat!(env!("OUT_DIR"), "/widget_generated.rs"));
include!(concat!(env!("OUT_DIR"), "/selector_generated.rs"));
include!(concat!(env!("OUT_DIR"), "/gauge_generated.rs"));
include!(concat!(env!("OUT_DIR"), "/blob_generated.rs"));

#[cfg(test)]
mod tests {
    use super::{Blob, Gauge};
    use super::Point;

    fn ber_roundtrip(x: i64, y: i64) -> bool {
        let p = Point { x, y };
        match Point::decode(&p.encode()) {
            Ok(got) => got == p,
            Err(_) => false,
        }
    }

    fn ber_encodes_as(x: i64, y: i64, expected: &[u8]) -> bool {
        Point { x, y }.encode() == expected
    }

    #[test]
    fn point_3_4_ber_encodes_as_30_06_02_01_03_02_01_04() {
        assert!(ber_encodes_as(3, 4, &[0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04]));
    }

    #[test]
    fn point_0_0_ber_encodes_as_30_06_02_01_00_02_01_00() {
        assert!(ber_encodes_as(0, 0, &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]));
    }

    #[test]
    fn point_100_neg7_ber_encodes_as_30_06_02_01_64_02_01_f9() {
        assert!(ber_encodes_as(100, -7, &[0x30, 0x06, 0x02, 0x01, 0x64, 0x02, 0x01, 0xf9]));
    }

    #[test]
    fn point_3_4_ber_round_trip() {
        assert!(ber_roundtrip(3, 4));
    }

    #[test]
    fn point_0_0_ber_round_trip() {
        assert!(ber_roundtrip(0, 0));
    }

    #[test]
    fn point_neg1_1000_ber_round_trip() {
        assert!(ber_roundtrip(-1, 1000));
    }

    #[test]
    fn rejects_wrong_tag() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not SEQUENCE
        assert!(Point::decode(&data).is_err());
    }

    use super::Widget;

    fn widget(id: i64, flag: bool, data: &[u8], label: &str) -> Widget {
        Widget { id, flag, data: asn1cpp_ber::octet_string::OctetString(data.to_vec()), label: label.to_string() }
    }

    #[test]
    fn widget_encodes_as_ground_truth_from_the_cpp_runtime() {
        // Captured by encoding the equivalent C++ Widget value via
        // BerCodec::instance().encode() directly (see module doc).
        let expected = [
            0x30, 0x0e, 0x02, 0x01, 0x07, 0x01, 0x01, 0xff, 0x04, 0x02, 0x68, 0x69, 0x16, 0x02,
            0x68, 0x69,
        ];
        assert_eq!(widget(7, true, b"hi", "hi").encode(), expected);
    }

    #[test]
    fn widget_round_trip() {
        let w = widget(7, true, b"hi", "hi");
        assert_eq!(Widget::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn widget_false_and_empty_round_trip() {
        let w = widget(0, false, b"", "");
        assert_eq!(Widget::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn widget_negative_id_round_trip() {
        let w = widget(-42, true, b"\x00\xff", "abc");
        assert_eq!(Widget::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn widget_rejects_wrong_tag() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not SEQUENCE
        assert!(Widget::decode(&data).is_err());
    }

    #[test]
    fn widget_encodes_xer_as_ground_truth_from_the_cpp_runtime() {
        // Captured by encoding the equivalent C++ Widget value via
        // XerCodec::instance().encode() directly (see module doc).
        let expected =
            "<Widget>\n    <id>7</id>\n    <flag><true/></flag>\n    <data>6869</data>\n    <label>hi</label>\n</Widget>\n";
        assert_eq!(widget(7, true, b"hi", "hi").encode_xer(), expected);
    }

    #[test]
    fn widget_xer_round_trip() {
        let w = widget(7, true, b"hi", "hi");
        assert_eq!(Widget::decode_xer(&w.encode_xer()).unwrap(), w);
    }

    #[test]
    fn widget_xer_false_and_empty_round_trip() {
        let w = widget(0, false, b"", "");
        assert_eq!(Widget::decode_xer(&w.encode_xer()).unwrap(), w);
    }

    #[test]
    fn widget_xer_escapes_label() {
        let w = widget(1, true, b"\x00", "a<b>&c");
        let xml = w.encode_xer();
        assert!(xml.contains("<label>a&lt;b&gt;&amp;c</label>"));
        assert_eq!(Widget::decode_xer(&xml).unwrap(), w);
    }

    #[test]
    fn widget_xer_rejects_wrong_outer_tag() {
        assert!(Widget::decode_xer("<NotWidget></NotWidget>").is_err());
    }

    use super::Selector;

    #[test]
    fn selector_num_encodes_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Num(7).encode(), vec![0x02, 0x01, 0x07]);
    }

    #[test]
    fn selector_flag_encodes_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Flag(true).encode(), vec![0x01, 0x01, 0xff]);
    }

    #[test]
    fn selector_data_encodes_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Data(asn1cpp_ber::octet_string::OctetString(vec![0x68, 0x69])).encode(), vec![0x04, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn selector_label_encodes_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Label("hi".to_string()).encode(), vec![0x16, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn selector_round_trips_every_alternative() {
        for s in [
            Selector::Num(-42),
            Selector::Flag(false),
            Selector::Data(asn1cpp_ber::octet_string::OctetString(vec![0xAA, 0xBB])),
            Selector::Label("round-trip".to_string()),
        ] {
            let bytes = s.encode();
            assert_eq!(Selector::decode(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn selector_rejects_unrecognized_tag() {
        let data = [0x30, 0x00]; // SEQUENCE tag — not a Selector alternative
        assert!(Selector::decode(&data).is_err());
    }

    #[test]
    fn selector_rejects_empty_input() {
        assert!(Selector::decode(&[]).is_err());
    }

    #[test]
    fn selector_num_encodes_xer_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Num(7).encode_xer(), "<Selector>\n    <num>7</num>\n</Selector>\n");
    }

    #[test]
    fn selector_flag_encodes_xer_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Flag(true).encode_xer(), "<Selector>\n    <flag><true/></flag>\n</Selector>\n");
    }

    #[test]
    fn selector_data_encodes_xer_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Data(asn1cpp_ber::octet_string::OctetString(vec![0x68, 0x69])).encode_xer(), "<Selector>\n    <data>6869</data>\n</Selector>\n");
    }

    #[test]
    fn selector_label_encodes_xer_as_ground_truth_from_the_cpp_runtime() {
        assert_eq!(Selector::Label("hi".to_string()).encode_xer(), "<Selector>\n    <label>hi</label>\n</Selector>\n");
    }

    #[test]
    fn selector_xer_round_trips_every_alternative() {
        for s in [
            Selector::Num(-42),
            Selector::Flag(false),
            Selector::Data(asn1cpp_ber::octet_string::OctetString(vec![0xAA, 0xBB])),
            Selector::Label("round-trip".to_string()),
        ] {
            let xml = s.encode_xer();
            assert_eq!(Selector::decode_xer(&xml).unwrap(), s);
        }
    }

    #[test]
    fn selector_xer_rejects_unrecognized_element() {
        assert!(Selector::decode_xer("<nope>1</nope>").is_err());
    }

    #[test]
    fn selector_xer_rejects_empty_input() {
        assert!(Selector::decode_xer("").is_err());
    }

    // gambas-asn1#463: real-codegen MemberDescriptor::validate coverage.
    // VALIDATE_FAIL_COUNT is one process-global atomic
    // (rust-runtime/ber/src/validate.rs) and `cargo test` runs in parallel
    // by default — same lock discipline that crate's own tests use.
    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gauge_in_range_member_round_trips_and_does_not_bump_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let g = Gauge { level: 50, note: -7, hint: Some(3) };
        assert_eq!(Gauge::decode(&g.encode()).unwrap(), g);
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 0);
    }

    #[test]
    fn gauge_out_of_range_member_bumps_the_validate_counter_on_encode() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let g = Gauge { level: 500, note: 1, hint: None };
        let _ = g.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 1);
    }

    // Regression: `hint`'s field is `Option<i64>` (OPTIONAL + constrained),
    // not `i64` — the generated MemberDescriptor::validate closure has to
    // unwrap it, not forward it straight to a `fn(i64) -> i64`. Compiled
    // fine before this test existed only because no other schema in the
    // codegen sweep combined OPTIONAL with an inline INTEGER value range.
    #[test]
    fn gauge_absent_optional_constrained_member_does_not_bump_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let g = Gauge { level: 50, note: 1, hint: None };
        let _ = g.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 0);
    }

    #[test]
    fn gauge_out_of_range_optional_constrained_member_bumps_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let g = Gauge { level: 50, note: 1, hint: Some(500) };
        let _ = g.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 1);
    }

    #[test]
    fn gauge_out_of_range_member_bumps_the_validate_counter_on_decode() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        // level == -5 is invalid per Gauge's own schema (0..100), but BER
        // itself has no notion of "invalid content" for a plain INTEGER —
        // building the wire bytes with a sibling in-range Gauge's encoder
        // isn't an option (Gauge::encode() would itself trip the same
        // counter), so hand-assemble the two-member SEQUENCE content
        // directly via the runtime's own low-level integer writer.
        let mut level_bytes = Vec::new();
        asn1cpp_ber::integer::write_integer_tagged(&mut level_bytes, asn1cpp_ber::integer::INTEGER_TAG, -5);
        let mut note_bytes = Vec::new();
        asn1cpp_ber::integer::write_integer_tagged(&mut note_bytes, asn1cpp_ber::integer::INTEGER_TAG, 1);
        let mut content = level_bytes;
        content.extend_from_slice(&note_bytes);
        let mut wire = Vec::new();
        asn1cpp_ber::writer::write_constructed(&mut wire, asn1cpp_ber::sequence::SEQUENCE_TAG, &content);

        let g = Gauge::decode(&wire).unwrap();
        assert_eq!(g.level, -5);
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 1);
    }

    // gambas-asn1#464: real-codegen MemberDescriptor::validate coverage for
    // OCTET STRING / BIT STRING SIZE.
    use asn1cpp_ber::bit_string::BitString;
    use asn1cpp_ber::octet_string::OctetString;

    fn blob(data: Vec<u8>, flags_bytes: Vec<u8>, flags_unused_bits: u8) -> Blob {
        Blob {
            data: OctetString(data),
            flags: BitString { bytes: flags_bytes, unused_bits: flags_unused_bits },
            tag: OctetString(vec![]),
        }
    }

    #[test]
    fn blob_in_size_members_round_trip_and_do_not_bump_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let b = blob(vec![1, 2], vec![0xFF], 4);
        assert_eq!(Blob::decode(&b.encode()).unwrap(), b);
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 0);
    }

    #[test]
    fn blob_too_long_octet_string_bumps_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        let b = blob(vec![1, 2, 3, 4, 5], vec![0xFF], 4);
        let _ = b.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 1);
    }

    #[test]
    fn blob_too_short_bit_string_bumps_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        // bit_count() == 0 (empty bytes, no unused_bits) — below the
        // SIZE(1..16) lower bound.
        let b = blob(vec![1], vec![], 0);
        let _ = b.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 1);
    }

    #[test]
    fn blob_unconstrained_octet_string_member_never_bumps_the_validate_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        asn1cpp_ber::validate::reset_validate_fail_count();
        // `tag` has no SIZE constraint at all — arbitrarily long is fine.
        let b = blob(vec![1], vec![0xFF], 4);
        let mut b = b;
        b.tag = OctetString(vec![0; 1000]);
        let _ = b.encode();
        assert_eq!(asn1cpp_ber::validate::validate_fail_count(), 0);
    }
}
