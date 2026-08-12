//! BER input — parses TLVs from a byte slice, zero-copy.
//!
//! Mirrors `BerReader` (`runtime/include/asn1cpp/codec/BerReader.hpp`):
//! same `read_tlv`/`peek_tag` entry points, same definite- and
//! indefinite-length support (X.690 §8.1.3.2 — see `Reader::read_tlv`'s
//! own doc for how the two forms end up producing identical `.value` bytes).

use crate::tag::{read_tag, Tag};
use std::fmt;

/// Decode failure with a human-readable reason and the byte offset it
/// occurred at. Mirrors `asn1::DecodeError` (`runtime/include/asn1cpp/Error.hpp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub message: String,
    pub pos: usize,
}

impl DecodeError {
    // pub, not pub(crate): both fields are already public (a caller could
    // always construct one via struct-literal syntax), and generated code
    // (e.g. RustBackend's ENUMERATED decode closures, "invalid <Type> value:
    // <n>") legitimately needs to raise a DecodeError of its own from
    // outside this crate — restricting just the constructor bought no real
    // encapsulation.
    pub fn new(message: impl Into<String>, pos: usize) -> DecodeError {
        DecodeError { message: message.into(), pos }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.pos)
    }
}

impl std::error::Error for DecodeError {}

/// One decoded TLV: tag plus a zero-copy view of the value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
}

/// Decoded length octets — definite (`len` bytes) or indefinite (X.690
/// §8.1.3.2, a lone `0x80` length octet; `len` meaningless when
/// `indefinite` is true, actual content extent found by scanning for the
/// matching end-of-contents octets instead, see `Reader::read_tlv`).
struct LengthResult {
    len: usize,
    indefinite: bool,
}

/// Cursor over a read-only byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// All bytes from the current position to the end, unconsumed —
    /// used for ANY's raw capture: an X.208 legacy type, not defined at
    /// all in the current standard (X.680/X.690 don't mention it), with
    /// X.691's own note that a legacy ANY should be treated as an open
    /// type. No fixed tag to validate against, so decoding it is "take
    /// whatever bytes are here", not a typed TLV read — mirrors
    /// `AnyBerHandler::decode` (`runtime/src/BerCodec.cpp`), which reads
    /// `r.remaining()` from whatever (already outer-tag-bounded) reader
    /// it's handed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Peek at the next TLV's tag without consuming it — used for CHOICE
    /// dispatch (inspect the tag, then decide which variant's decoder to call).
    pub fn peek_tag(&self) -> Option<Tag> {
        let mut p = self.pos;
        read_tag(self.data, &mut p)
    }

    /// Read and consume the length octets of a TLV.
    /// @see X.690 §8.1.3 — Length octets.
    fn read_length(&mut self) -> Result<LengthResult, DecodeError> {
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| DecodeError::new("unexpected end of data reading length", self.pos))?;
        self.pos += 1;
        if first == 0x80 {
            return Ok(LengthResult { len: 0, indefinite: true });
        }
        if first & 0x80 == 0 {
            return Ok(LengthResult { len: first as usize, indefinite: false });
        }
        let n = (first & 0x7F) as usize;
        if n > 8 {
            return Err(DecodeError::new(
                format!("unsupported length encoding ({} bytes)", n),
                self.pos - 1,
            ));
        }
        if self.data.len() - self.pos < n {
            return Err(DecodeError::new("truncated length field", self.pos));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.data[self.pos] as usize;
            self.pos += 1;
        }
        Ok(LengthResult { len, indefinite: false })
    }

    /// Read and consume one complete TLV — definite or indefinite length
    /// (X.690 §8.1.3.2). Mirrors `BerReader::read_tlv`'s slow path
    /// (`runtime/include/asn1cpp/codec/BerReader.hpp`): an indefinite-length
    /// TLV's content runs until the matching end-of-contents octets (`00
    /// 00`) at the *same* nesting depth — found by walking nested TLVs
    /// (each definite one skipped by its own length, each nested
    /// indefinite one incrementing depth), not by a byte count. `value`
    /// ends up holding exactly the same bytes either way (definite or
    /// indefinite), EOC octets excluded — so everything downstream of
    /// `read_tlv` (which only ever inspects `.value` as "N content bytes to
    /// walk") needs no indefinite-specific handling at all; unlike the C++
    /// `TLV` struct, no `indefinite` flag is carried on `Tlv` here, nothing
    /// downstream needs to know which form produced these bytes.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, DecodeError> {
        let tag = read_tag(self.data, &mut self.pos)
            .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
        let len_r = self.read_length()?;
        if len_r.indefinite {
            // X.690 §8.1.3.2: indefinite-length is only valid for
            // constructed encodings — a primitive value has no TLVs nested
            // inside it to scan for an EOC marker within.
            if !tag.constructed {
                return Err(DecodeError::new(
                    "indefinite-length encoding on primitive type",
                    self.pos - 1,
                ));
            }
            let start = self.pos;
            let mut depth = 1usize;
            while depth > 0 {
                if self.data.len() - self.pos < 2 {
                    return Err(DecodeError::new("unterminated indefinite-length encoding", self.pos));
                }
                if self.data[self.pos] == 0x00 && self.data[self.pos + 1] == 0x00 {
                    self.pos += 2;
                    depth -= 1;
                } else {
                    let inner_tag = read_tag(self.data, &mut self.pos)
                        .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
                    let inner_len = self.read_length()?;
                    if inner_len.indefinite {
                        if !inner_tag.constructed {
                            return Err(DecodeError::new(
                                "indefinite-length encoding on primitive type",
                                self.pos - 1,
                            ));
                        }
                        depth += 1;
                    } else {
                        if self.data.len() - self.pos < inner_len.len {
                            return Err(DecodeError::new("truncated nested value", self.pos));
                        }
                        self.pos += inner_len.len;
                    }
                }
            }
            let end = self.pos - 2;
            return Ok(Tlv { tag, value: &self.data[start..end] });
        }
        let len = len_r.len;
        if self.data.len() - self.pos < len {
            return Err(DecodeError::new(
                format!("need {} bytes but only {} remain", len, self.data.len() - self.pos),
                self.pos,
            ));
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(Tlv { tag, value })
    }
}

/// EXPLICIT tagging (X.690 §8.14.3) decode — read the
/// constructed outer TLV, check its tag, then decode the inner value from a
/// sub-`Reader` over the outer TLV's content (the complete inner natural-tag
/// encoding, unchanged). See `writer::write_explicit`'s doc comment for the
/// encode side and the IMPLICIT-vs-EXPLICIT distinction.
pub fn read_explicit<T>(
    r: &mut Reader,
    tag: Tag,
    inner_decode: impl FnOnce(&mut Reader) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected EXPLICIT tag, got {:?}", tlv.tag), r.pos()));
    }
    let mut inner = Reader::new(tlv.value);
    inner_decode(&mut inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag::universal;

    #[test]
    fn reads_primitive_tlv() {
        let data = [0x04, 0x02, 0x68, 0x69];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.tag, Tag::universal(universal::OCTET_STRING, false));
        assert_eq!(tlv.value, &[0x68, 0x69]);
        assert!(r.at_end());
    }

    #[test]
    fn reads_long_form_length() {
        let mut data = vec![0x04, 0x82, 0x01, 0x2C];
        data.extend(std::iter::repeat_n(0xAA, 300));
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value.len(), 300);
    }

    #[test]
    fn peek_tag_does_not_advance() {
        let data = [0x02, 0x01, 0x05];
        let r = Reader::new(&data);
        assert_eq!(r.peek_tag(), Some(Tag::universal(universal::INTEGER, false)));
        assert_eq!(r.pos(), 0);
    }

    #[test]
    fn truncated_value_is_error() {
        let data = [0x04, 0x05, 0x68, 0x69]; // claims 5 bytes, only 2 present
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn indefinite_length_empty_sequence_decodes() {
        // SEQUENCE (0x30), indefinite length (0x80), immediately EOC (0x00 0x00).
        let data = [0x30, 0x80, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.tag, Tag::universal(universal::SEQUENCE, true));
        assert!(tlv.value.is_empty());
        assert!(r.at_end());
    }

    #[test]
    fn indefinite_length_sequence_with_nested_definite_tlv_decodes() {
        // SEQUENCE (indefinite) containing one INTEGER 42 (definite), then EOC.
        let data = [0x30, 0x80, 0x02, 0x01, 0x2A, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value, &[0x02, 0x01, 0x2A]);
        assert!(r.at_end());

        // The captured content re-parses as an ordinary definite-length TLV.
        let mut inner = Reader::new(tlv.value);
        let inner_tlv = inner.read_tlv().unwrap();
        assert_eq!(inner_tlv.tag, crate::integer::INTEGER_TAG);
        assert_eq!(inner_tlv.value, &[0x2A]);
    }

    #[test]
    fn indefinite_length_nested_indefinite_tlv_decodes() {
        // Outer SEQUENCE (indefinite) containing an inner SEQUENCE
        // (indefinite, empty), then outer EOC — exercises depth tracking.
        let data = [0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00];
        let mut r = Reader::new(&data);
        let tlv = r.read_tlv().unwrap();
        assert_eq!(tlv.value, &[0x30, 0x80, 0x00, 0x00]);
        assert!(r.at_end());
    }

    #[test]
    fn indefinite_length_on_primitive_type_is_rejected() {
        // OCTET STRING (0x04, primitive) can't be indefinite-length —
        // X.690 §8.1.3.2 restricts that form to constructed encodings.
        let data = [0x04, 0x80, 0x00, 0x00];
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn indefinite_length_unterminated_is_rejected() {
        let data = [0x30, 0x80, 0x02, 0x01, 0x2A]; // no EOC
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }

    #[test]
    fn explicit_unwraps_the_outer_tlv_and_decodes_the_inner_natural_tag() {
        // [5] EXPLICIT wrapping INTEGER 42 — same bytes writer.rs's
        // explicit_wraps_the_inner_encoding_in_an_outer_constructed_tlv test produces.
        let data = [0xA5, 0x03, 0x02, 0x01, 0x2A];
        let mut r = Reader::new(&data);
        let v = read_explicit(&mut r, Tag::context(5, true), |inner| {
            let tlv = inner.read_tlv()?;
            Ok(tlv.value[0] as i64)
        })
        .unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn explicit_rejects_the_wrong_outer_tag() {
        let data = [0xA5, 0x03, 0x02, 0x01, 0x2A];
        let mut r = Reader::new(&data);
        let result = read_explicit(&mut r, Tag::context(6, true), |inner| {
            let tlv = inner.read_tlv()?;
            Ok(tlv.value[0] as i64)
        });
        assert!(result.is_err());
    }
}
