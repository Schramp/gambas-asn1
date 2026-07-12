//! Generated-code + asn1cpp-ber roundtrip check (gambas-asn1#219) — proves
//! the actual codegen -> runtime pipeline, not just that the two pieces are
//! compatible by hand: `point_generated.rs` is produced by
//! `run_roundtrip_test.py` running the real `asn1cpp --target=rust`
//! compiler against `tests/asn1/simple_seq.asn1` immediately before this
//! crate's tests run — not committed (regenerated every run, see
//! `.gitignore`).

#[path = "point_generated.rs"]
mod point;
pub use point::Point;

#[cfg(test)]
mod tests {
    use super::Point;

    #[test]
    fn roundtrip() {
        let p = Point { x: 42, y: -7 };
        let bytes = p.encode();
        let decoded = Point::decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_extremes() {
        for (x, y) in [(0, 0), (i64::MAX, i64::MIN), (-1, 1), (300, -300)] {
            let p = Point { x, y };
            assert_eq!(Point::decode(&p.encode()).unwrap(), p);
        }
    }

    #[test]
    fn matches_hand_computed_ber_vector() {
        let p = Point { x: 1, y: 2 };
        // SEQUENCE (0x30), length 6, then two INTEGER TLVs.
        assert_eq!(p.encode(), vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn rejects_wrong_tag() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not SEQUENCE
        assert!(Point::decode(&data).is_err());
    }
}
