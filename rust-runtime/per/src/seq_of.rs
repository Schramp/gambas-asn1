//! Generic SEQUENCE OF / SET OF PER encode/decode (X.691 §19/§20 combined
//! with §10.9 length handling). Mirrors `SeqOfPerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly: `encode_size_field`/
//! `decode_size_field` (`length.rs`) already implement that handler's own
//! fixed-SIZE/constrained/unconstrained count-encoding logic — this module
//! only adds the per-element loop around it.
//!
//! Generic over the element type (`T: PerValue`) rather than tied to a
//! specific wrapper — `RustBackend`'s own `SeqOf<T>`/`SetOf<T>` newtypes
//! (`rust-runtime/ber/src/sequence.rs`) both `Deref`/`DerefMut` to `Vec<T>`,
//! so a member's `Constrained` access closure calls these functions
//! directly on the field (`&v.field`/`&mut v.field`, coerced through
//! `Deref` to `&[T]`/`&mut Vec<T>`) with no wrapper-specific code needed
//! here at all.

use crate::constraints::Constraints;
use crate::length::{decode_size_field, encode_size_field};
use crate::reader::{DecodeError, Reader};
use crate::value::PerValue;
use crate::writer::Writer;

pub fn encode_seq_of_content<T: PerValue>(w: &mut Writer, pc: &Constraints, items: &[T]) {
    encode_size_field(w, pc, items.len());
    for item in items {
        item.per_encode(w);
    }
}

pub fn decode_seq_of_content<T: PerValue + Default>(
    r: &mut Reader,
    pc: &Constraints,
) -> Result<Vec<T>, DecodeError> {
    let count = decode_size_field(r, pc)?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let mut v = T::default();
        v.per_decode_into(r)?;
        result.push(v);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::{decode_int, encode_int};

    // Dogfood-only fixture (#[cfg(test)]-gated, never public API).
    #[derive(Debug, Default, PartialEq)]
    struct DogfoodInt(i64);
    impl PerValue for DogfoodInt {
        fn per_encode(&self, w: &mut Writer) {
            encode_int(w, &ELEM_CONSTRAINED, self.0);
        }
        fn per_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
            self.0 = decode_int(r, &ELEM_CONSTRAINED)?;
            Ok(())
        }
    }

    const ELEM_CONSTRAINED: Constraints = Constraints {
        flags: crate::constraints::CONSTRAINED,
        range_bits: 4,
        lower_bound: 0,
        upper_bound: 15,
        lower_u64: 0,
        upper_u64: 0,
        size_range_bits: 0,
        size_lower: 0,
        size_upper: 0,
    };

    fn sized(lower: i64, upper: i64) -> Constraints {
        let range = (upper - lower + 1) as f64;
        let range_bits = if range <= 1.0 { 0 } else { range.log2().ceil() as u32 };
        Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: range_bits,
            size_lower: lower,
            size_upper: upper,
            ..Default::default()
        }
    }

    fn roundtrip(pc: &Constraints, items: &[DogfoodInt]) -> Vec<DogfoodInt> {
        let mut w = Writer::new();
        encode_seq_of_content(&mut w, pc, items);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_seq_of_content(&mut r, pc).unwrap()
    }

    #[test]
    fn sized_roundtrip() {
        let pc = sized(0, 8);
        let items = vec![DogfoodInt(1), DogfoodInt(2), DogfoodInt(3)];
        assert_eq!(roundtrip(&pc, &items), items);
    }

    #[test]
    fn unconstrained_roundtrip() {
        let pc = Constraints::default();
        let items = vec![DogfoodInt(5)];
        assert_eq!(roundtrip(&pc, &items), items);
    }

    #[test]
    fn empty_roundtrip() {
        let pc = sized(0, 8);
        let items: Vec<DogfoodInt> = vec![];
        assert_eq!(roundtrip(&pc, &items), items);
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real SEQUENCE OF TypeDescriptor (`List ::= SEQUENCE
    // (SIZE(0..8)) OF Elem` where `Elem ::= INTEGER (0..15)`) with the
    // identical element shape and values.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = sized(0, 8);
        let mut w = Writer::new();
        encode_seq_of_content(&mut w, &pc, &[DogfoodInt(1), DogfoodInt(2), DogfoodInt(3)]);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x31, 0x23]);

        let mut w2 = Writer::new();
        encode_seq_of_content::<DogfoodInt>(&mut w2, &pc, &[]);
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x00]);
    }
}
