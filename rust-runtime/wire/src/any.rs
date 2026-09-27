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
//! EXPLICIT-tagged member (`spec::sequence`'s own doc). BER-only: no
//! defined XER or PER form here.

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
}

impl crate::type_tag::TypeTag for Any {
    // ANY (X.208 legacy) has no fixed tag of its own.
    const TAG: Option<crate::ber::tag::Tag> = None;
}
