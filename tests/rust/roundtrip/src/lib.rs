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

include!(concat!(env!("OUT_DIR"), "/point_generated.rs"));

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
}
