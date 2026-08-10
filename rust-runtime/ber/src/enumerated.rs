//! ENUMERATED encode/decode — X.680 §20, X.690 §8.4.
//!
//! Same minimal two's-complement value-byte encoding as INTEGER
//! (`integer::encode_integer_bytes`/`decode_integer_bytes` — X.690 §8.4
//! defers to §8.3's INTEGER rules directly), only the tag differs
//! (universal 10, not 2). Every generated ENUMERATED type shares this
//! crate's `i64` wire representation regardless of its own Rust
//! `#[repr(i64)]` enum discriminant — codegen emits a per-type
//! `impl Asn1Value` converting through `i64` via `as i64` (encode) /
//! `TryFrom<i64>` (decode, already generated for every ENUMERATED type by
//! `emit_enumerated_definition`).

use crate::integer::{decode_integer_bytes, encode_integer_bytes};
use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const ENUMERATED_TAG: Tag = Tag::universal(universal::ENUMERATED, false);

pub fn write_enumerated_tagged(out: &mut Vec<u8>, tag: Tag, n: i64) {
    write_primitive(out, tag, &encode_integer_bytes(n));
}

pub fn read_enumerated_tagged(r: &mut Reader, tag: Tag) -> Result<i64, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected ENUMERATED tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_integer_bytes(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_universal_ten_not_integers_two() {
        assert_eq!(ENUMERATED_TAG.number, 10);
        assert_ne!(ENUMERATED_TAG, crate::integer::INTEGER_TAG);
    }

    #[test]
    fn full_tlv_round_trip() {
        let mut buf = Vec::new();
        write_enumerated_tagged(&mut buf, ENUMERATED_TAG, 2);
        assert_eq!(buf, vec![0x0A, 0x01, 0x02]); // universal primitive 10, len 1, value 2
        let mut r = Reader::new(&buf);
        assert_eq!(read_enumerated_tagged(&mut r, ENUMERATED_TAG).unwrap(), 2);
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_0 = Tag::context(0, false);
        let mut buf = Vec::new();
        write_enumerated_tagged(&mut buf, context_0, 1);
        assert_eq!(buf, vec![0x80, 0x01, 0x01]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_enumerated_tagged(&mut r, context_0).unwrap(), 1);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x02]; // INTEGER tag, not ENUMERATED
        let mut r = Reader::new(&data);
        assert!(read_enumerated_tagged(&mut r, ENUMERATED_TAG).is_err());
    }
}
