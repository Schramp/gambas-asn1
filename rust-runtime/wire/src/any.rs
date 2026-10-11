//! ANY — the X.208 legacy open type, held as the raw captured TLV bytes
//! (X.680/X.690 no longer define it; X.691 treats a legacy ANY as an open
//! type). A real type rather than a bare `Vec<u8>` so it has its own
//! `Asn1Value` impl. No natural tag of its own — the raw bytes it holds
//! are already a complete TLV of whatever type was actually on the wire —
//! so `ber_encode`/`ber_decode_into` are overridden directly (replay/
//! capture verbatim) rather than composed from `ber_natural_tag` +
//! content the way every other type's default does. An ANY member is
//! always tagged (X.680 §30.1's TaggedType construction), so it reaches
//! the wire through `ber_encode_explicit`/`ber_decode_into_explicit`'s
//! default bodies — `MemberAccess::ExplicitScalar`, like any other
//! EXPLICIT-tagged member (`spec::sequence`'s own doc). PER treats the
//! captured content as an X.691 §10.2 open-type field (length-prefixed
//! raw octets — `per_encode`/`per_decode_into` below). No defined XER
//! form.

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::value::Asn1Value;

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

impl Asn1Value for Any {
    fn ber_natural_tag(&self) -> Tag {
        unreachable!("ANY has no natural tag — its wire form is a full TLV of whatever type was actually present, replayed verbatim by ber_encode")
    }

    fn ber_encode_content(&self, _out: &mut Vec<u8>) {
        unreachable!("ANY has no content-only representation — ber_encode is overridden directly")
    }

    fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), DecodeError> {
        unreachable!("ANY has no content-only representation — ber_decode_into is overridden directly")
    }

    fn ber_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        self.0 = r.remaining().to_vec();
        Ok(())
    }

    /// X.691 §10.2 "Open type fields": length-prefixed raw octets, no
    /// bit-packing — mirrors `AnyPerHandler` (`runtime/src/PerCodec.cpp`)
    /// and asn1c's own `ANY_encode_uper` (`ANY_uper.c`) exactly. Legacy
    /// ANY (X.208) has no defined type of its own, so PER treats its
    /// captured content the same way it treats an unknown CHOICE
    /// extension alternative's payload.
    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        crate::per::length::put_length(w, self.0.len());
        for b in &self.0 {
            w.put_bits(*b as u64, 8);
        }
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        let len = crate::per::length::get_length(r)?;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(r.get_bits(8)? as u8);
        }
        self.0 = bytes;
        Ok(())
    }

    /// Quoted uppercase hex of the captured bytes — same convention
    /// `OctetString`'s own JER impl uses (`jer::octet_string`), not the
    /// trait's default `unimplemented!()`. gambas-asn1#668: the C++ side
    /// used to assume ANY's captured bytes were already well-formed JSON
    /// text and pass them through raw, which produced invalid JSON for
    /// every real caller (nothing in either runtime ever populates ANY
    /// with actual JSON — RandomFiller/decode both capture raw BER
    /// bytes). Fixed there to match AnyXerHandler's own hex convention;
    /// mirrored here from day one rather than inheriting the same gap.
    fn jer_encode(&self, out: &mut String) {
        crate::jer::octet_string::encode(&self.0, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::octet_string::decode(r)?;
        Ok(())
    }
}

impl crate::type_tag::TypeTag for Any {
    // ANY (X.208 legacy) has no fixed tag of its own.
    const TAG: Option<crate::ber::tag::Tag> = None;
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
        v.per_encode(&mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let mut got = Any::default();
        got.per_decode_into(&mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn per_empty_content_round_trips() {
        let v = Any(vec![]);
        let mut w = Writer::new();
        v.per_encode(&mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0x00]);
        let mut r = Reader::new(&bytes);
        let mut got = Any::default();
        got.per_decode_into(&mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn jer_encodes_as_quoted_hex_and_round_trips() {
        let v = Any(vec![0x30, 0x03, 0x02, 0x01, 0x2A]);
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "\"300302012A\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Any::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }
}
