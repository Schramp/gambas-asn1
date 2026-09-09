//! PER bit-level input — reads bits MSB-first from a byte slice, zero-copy.
//!
//! Mirrors `PerDecodeStream` (`runtime/include/asn1cpp/codec/PerCodec.hpp`):
//! same `get_bits`/`at_end` entry points, same MSB-first unpacking order.

use std::fmt;

/// Decode failure with a human-readable reason and the bit offset it
/// occurred at. Bit offset, not byte offset (unlike `asn1cpp_ber`'s
/// `DecodeError`) — PER fields are rarely byte-aligned, so a byte-only
/// offset would lose precision a reader debugging a wire dump actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub message: String,
    pub bit_pos: usize,
}

impl DecodeError {
    pub fn new(message: impl Into<String>, bit_pos: usize) -> DecodeError {
        DecodeError { message: message.into(), bit_pos }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at bit {})", self.message, self.bit_pos)
    }
}

impl std::error::Error for DecodeError {}

/// Bit-level PER input reader over a borrowed byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    byte_pos: usize,
    bit_pos: usize,
    skipped_ext_count: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, byte_pos: 0, bit_pos: 0, skipped_ext_count: 0 }
    }

    /// True once all input bits have been consumed.
    pub fn at_end(&self) -> bool {
        self.byte_pos >= self.buf.len()
    }

    /// Current read position in bits (committed bytes × 8 + consumed bits).
    pub fn bit_pos(&self) -> usize {
        self.byte_pos * 8 + self.bit_pos
    }

    /// Total number of bits available in the underlying buffer.
    pub fn total_bits(&self) -> usize {
        self.buf.len() * 8
    }

    /// Read and consume `n` bits, MSB-first. `n` must be in `0..=64`.
    pub fn get_bits(&mut self, n: u32) -> Result<u64, DecodeError> {
        let start = self.bit_pos();
        let mut result: u64 = 0;
        for _ in 0..n {
            if self.byte_pos >= self.buf.len() {
                return Err(DecodeError::new("PER: unexpected end of data", start));
            }
            let bit = (self.buf[self.byte_pos] >> (7 - self.bit_pos)) & 1;
            result = (result << 1) | bit as u64;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.byte_pos += 1;
                self.bit_pos = 0;
            }
        }
        Ok(result)
    }

    /// Number of extension alternatives skipped since the last
    /// `reset_skipped_extensions()`. Non-zero indicates a version skew
    /// between encoder and decoder schemas.
    pub fn skipped_extensions(&self) -> usize {
        self.skipped_ext_count
    }

    pub fn reset_skipped_extensions(&mut self) {
        self.skipped_ext_count = 0;
    }

    pub fn increment_skipped_extensions(&mut self) {
        self.skipped_ext_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_split_reads() {
        let data = [0b10111111u8];
        let mut r = Reader::new(&data);
        assert_eq!(r.get_bits(3).unwrap(), 0b101);
        assert_eq!(r.get_bits(5).unwrap(), 0b11111);
        assert!(r.at_end());
    }

    #[test]
    fn spans_byte_boundary() {
        let data = [0xFFu8, 0b10000000];
        let mut r = Reader::new(&data);
        assert_eq!(r.get_bits(8).unwrap(), 0xFF);
        assert_eq!(r.get_bits(1).unwrap(), 1);
    }

    #[test]
    fn zero_width_is_noop() {
        let data = [0xAAu8];
        let mut r = Reader::new(&data);
        assert_eq!(r.get_bits(0).unwrap(), 0);
        assert_eq!(r.bit_pos(), 0);
    }

    #[test]
    fn eof_reports_bit_position() {
        let data = [0xFFu8];
        let mut r = Reader::new(&data);
        r.get_bits(8).unwrap();
        let err = r.get_bits(1).unwrap_err();
        assert_eq!(err.bit_pos, 8);
    }

    #[test]
    fn writer_reader_roundtrip() {
        use crate::writer::Writer;
        let mut w = Writer::new();
        w.put_bits(0b10110, 5);
        w.put_bits(0b1, 1);
        w.put_bits(0b11, 2);
        w.put_bits(0xABCD, 16);
        w.flush();
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.get_bits(5).unwrap(), 0b10110);
        assert_eq!(r.get_bits(1).unwrap(), 0b1);
        assert_eq!(r.get_bits(2).unwrap(), 0b11);
        assert_eq!(r.get_bits(16).unwrap(), 0xABCD);
    }
}
