//! Character-string type encode/decode — X.680 §41, X.690 §8.7 (same
//! primitive-octet-string shape OCTET STRING uses, just under each string
//! type's own universal tag).
//!
//! Mirrors `AsnStringBerHandler` (`runtime/src/BerCodec.cpp`): value octets
//! are the raw string bytes, no escaping at the BER layer (escaping is an
//! XER-only concern, see `xer.rs`). Scoped to `IA5String` for now
//! (gambas-asn1#282) — the other 11 string kinds share this exact shape,
//! differing only in universal tag number, so widening later is adding a
//! tag constant, not new logic.
//!
//! **Known divergence from ground truth (found on review, gambas-asn1#282):**
//! `AsnStringBerHandler::decode` copies value octets into `std::string`
//! unconditionally — no charset validation at all, C++ accepts *any* byte
//! sequence as IA5String content. `read_ia5_string` below requires valid
//! UTF-8 (`String::from_utf8`), because the field's Rust type is `String`,
//! which can't hold arbitrary bytes. A malformed/fuzzed IA5String (e.g. raw
//! high bytes that aren't valid UTF-8) that C++ decodes successfully will
//! be *rejected* here. Left as-is for this issue's scope — flagging so it
//! isn't rediscovered as a surprise during #286 (randgen cross-validation
//! against asn1c), where such inputs are exactly what a corruption-mode
//! fuzz run would produce. A real fix would need either a lossy
//! from_utf8_lossy substitution (changes the decoded value, still not
//! byte-identical to C++) or a non-`String` field representation for text
//! types (bigger scope than this issue).

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const IA5_STRING_TAG: Tag = Tag::universal(universal::IA5_STRING, false);

pub fn write_ia5_string(out: &mut Vec<u8>, value: &str) {
    write_primitive(out, IA5_STRING_TAG, value.as_bytes());
}

pub fn read_ia5_string(r: &mut Reader) -> Result<String, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != IA5_STRING_TAG {
        return Err(DecodeError::new(format!("expected IA5String tag, got {:?}", tlv.tag), r.pos()));
    }
    String::from_utf8(tlv.value.to_vec())
        .map_err(|_| DecodeError::new("IA5String: invalid UTF-8".to_string(), r.pos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ascii() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hi");
        assert_eq!(buf, vec![0x16, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn empty_string_round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "");
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hello");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "hello");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x04, 0x02, 0x68, 0x69]; // OCTET STRING tag, not IA5String
        let mut r = Reader::new(&data);
        assert!(read_ia5_string(&mut r).is_err());
    }

    #[test]
    fn non_utf8_bytes_are_rejected_unlike_the_cpp_runtime() {
        // See the module doc's "known divergence" note: AsnStringBerHandler
        // (C++) copies these bytes into std::string unvalidated and would
        // decode this successfully. 0xFF is not a valid UTF-8 lead byte.
        let data = [0x16, 0x01, 0xFF];
        let mut r = Reader::new(&data);
        assert!(read_ia5_string(&mut r).is_err());
    }
}
