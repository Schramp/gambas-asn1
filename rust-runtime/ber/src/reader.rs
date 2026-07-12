//! BER input — parses TLVs from a byte slice, zero-copy.
//!
//! Mirrors `BerReader` (`runtime/include/asn1cpp/codec/BerReader.hpp`):
//! same `read_tlv`/`peek_tag` entry points, same definite-length-only scope
//! (indefinite-length, X.690 §8.1.3.2, isn't implemented here — out of scope
//! for gambas-asn1#218's "core primitives" goal; the C++ reader's
//! `read_tlv()` slow path handles it, this doesn't yet).

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
    pub(crate) fn new(message: impl Into<String>, pos: usize) -> DecodeError {
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

    /// Peek at the next TLV's tag without consuming it — used for CHOICE
    /// dispatch (inspect the tag, then decide which variant's decoder to call).
    pub fn peek_tag(&self) -> Option<Tag> {
        let mut p = self.pos;
        read_tag(self.data, &mut p)
    }

    /// Read and consume the length octets of a TLV (definite form only).
    /// @see X.690 §8.1.3 — Length octets.
    fn read_length(&mut self) -> Result<usize, DecodeError> {
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| DecodeError::new("unexpected end of data reading length", self.pos))?;
        self.pos += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        if first == 0x80 {
            return Err(DecodeError::new(
                "indefinite-length encoding not supported",
                self.pos - 1,
            ));
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
        Ok(len)
    }

    /// Read and consume one complete definite-length TLV.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, DecodeError> {
        let tag = read_tag(self.data, &mut self.pos)
            .ok_or_else(|| DecodeError::new("truncated or oversized tag", self.pos))?;
        let len = self.read_length()?;
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
    fn indefinite_length_is_rejected() {
        let data = [0x30, 0x80, 0x00, 0x00];
        let mut r = Reader::new(&data);
        assert!(r.read_tlv().is_err());
    }
}
