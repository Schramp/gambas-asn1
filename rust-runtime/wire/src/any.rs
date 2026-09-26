//! ANY — the X.208 legacy open type, held as the raw captured TLV bytes
//! (X.680/X.690 no longer define it; X.691 treats a legacy ANY as an open
//! type). A real type rather than a bare `Vec<u8>` so it has its own
//! `Asn1Value` impl. BER-only in practice: an ANY member is always reached
//! through its `MemberAccess::ExplicitAny` raw closures
//! (`sequence.rs`), never through the natural-tag/content split, and has
//! no defined XER or PER form here.

use crate::reader::DecodeError;
use crate::tag::Tag;
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
        unreachable!("ANY has no natural tag — it is always reached through raw EXPLICIT closures")
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = content.to_vec();
        Ok(())
    }
}
