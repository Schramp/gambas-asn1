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

include!(concat!(env!("OUT_DIR"), "/point_generated.rs"));
include!(concat!(env!("OUT_DIR"), "/widget_generated.rs"));

#[cfg(test)]
mod tests {
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
        Widget { id, flag, data: data.to_vec(), label: label.to_string() }
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
}
