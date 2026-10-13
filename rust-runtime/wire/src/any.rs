//! ANY — the X.208 legacy open type, held as the raw captured TLV bytes
//! (X.680/X.690 no longer define it; X.691 treats a legacy ANY as an open
//! type). Its own newtype rather than a bare `Vec<u8>`, with its own
//! `PrimitiveRef` variant. No natural tag of its own — the raw bytes it
//! holds are already a complete TLV of whatever type was actually on the
//! wire, replayed/captured verbatim (`encode_any`/`decode_any`). An ANY
//! member is always tagged (X.680 §30.1's TaggedType construction; an
//! untagged one is an unsupported row in codegen), so it reaches the wire
//! through `spec::primitive`'s EXPLICIT-framing dispatch
//! (`ber_encode_explicit_`/`ber_decode_explicit_`, which special-case
//! `PrimitiveRef::Any`/`PrimitiveRefMut::Any`). PER treats the captured
//! content as an X.691 §10.2 open-type field (length-prefixed raw octets,
//! `per::any`). No defined XER form.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Any(pub Vec<u8>);

impl std::ops::Deref for Any {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl std::ops::DerefMut for Any {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl crate::type_tag::TypeTag for Any {
    // ANY (X.208 legacy) has no fixed tag of its own.
    const TAG: Option<crate::ber::tag::Tag> = None;
}

/// Replays the captured TLV verbatim — see this module's own doc for why
/// ANY has no content-only BER form to delegate to instead.
pub(crate) fn encode_any(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes);
}

pub(crate) fn decode_any(remaining: &[u8]) -> Vec<u8> {
    remaining.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per::reader::Reader;
    use crate::per::writer::Writer;

    #[test]
    fn per_round_trips_arbitrary_captured_bytes() {
        let v = Any(vec![0x30, 0x03, 0x02, 0x01, 0x2A]); // a captured INTEGER TLV
        let mut w = Writer::new();
        crate::spec::primitive::test_codec::per_encode(&v, &mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let mut got = Any::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut got, &mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn per_empty_content_round_trips() {
        let v = Any(vec![]);
        let mut w = Writer::new();
        crate::spec::primitive::test_codec::per_encode(&v, &mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0x00]);
        let mut r = Reader::new(&bytes);
        let mut got = Any::default();
        crate::spec::primitive::test_codec::per_decode_into(&mut got, &mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn jer_encodes_as_quoted_hex_and_round_trips() {
        let v = Any(vec![0x30, 0x03, 0x02, 0x01, 0x2A]);
        let mut out = String::new();
        crate::spec::primitive::test_codec::jer_encode(&v, &mut out);
        assert_eq!(out, "\"300302012A\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Any::default();
        crate::spec::primitive::test_codec::jer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got, v);
    }
}
