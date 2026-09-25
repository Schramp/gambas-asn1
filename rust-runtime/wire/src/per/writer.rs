//! PER bit-level output — packs bits MSB-first into a byte buffer.
//!
//! Mirrors `PerEncodeStream` (`runtime/include/asn1cpp/codec/PerCodec.hpp`):
//! same `put_bits`/`flush` shape, same MSB-first packing order (X.691 §3,
//! "the bits of an octet are numbered 1 to 8, bit 1 being the most
//! significant bit").

/// Bit-level PER output buffer. Construct empty, `put_bits` any number of
/// times, `flush()` once at the end to pad and commit the final partial
/// byte — mirrors `PerEncodeStream`'s own contract exactly (`flush()` must
/// be called after the last `put_bits()`).
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    current: u8,
    bits: u8,
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    /// Current write position in bits (committed bytes × 8 + pending bits).
    pub fn bit_pos(&self) -> usize {
        self.buf.len() * 8 + self.bits as usize
    }

    /// Write the low `n` bits of `value`, MSB-first. `n` must be in
    /// `0..=64`; a `n` of 0 is a no-op (matches callers that compute a
    /// zero-width field for an unconstrained/degenerate case).
    pub fn put_bits(&mut self, value: u64, n: u32) {
        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.current |= bit << (7 - self.bits);
            self.bits += 1;
            if self.bits == 8 {
                self.buf.push(self.current);
                self.current = 0;
                self.bits = 0;
            }
        }
    }

    /// Pad and flush the current partial byte to the buffer. Must be
    /// called after the last `put_bits()` to ensure the final byte is
    /// committed — matches `PerEncodeStream::flush()`, including its
    /// empty-buffer case (a zero-length PER encoding still emits one
    /// all-zero byte, since callers expect the "no content" case to still
    /// look like a well-formed one-byte encoding rather than an empty
    /// `Vec`).
    pub fn flush(&mut self) {
        if self.bits > 0 || self.buf.is_empty() {
            self.buf.push(self.current);
            self.current = 0;
            self.bits = 0;
        }
    }

    /// Consume the writer, returning the accumulated bytes. Caller must
    /// have already called `flush()` — an un-flushed partial byte is
    /// silently dropped otherwise (same risk `PerEncodeStream::buf()`
    /// carries; this crate's own codec entry points always flush before
    /// returning, this method is for that call site and direct unit tests).
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_roundtrip_shape() {
        let mut w = Writer::new();
        w.put_bits(0b101, 3);
        w.put_bits(0b11111, 5);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b10111111]);
    }

    #[test]
    fn spans_byte_boundary() {
        let mut w = Writer::new();
        w.put_bits(0xFF, 8);
        w.put_bits(0b1, 1);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0xFF, 0b10000000]);
    }

    #[test]
    fn zero_width_is_noop() {
        let mut w = Writer::new();
        w.put_bits(0, 0);
        w.put_bits(0b1010, 4);
        assert_eq!(w.bit_pos(), 4);
    }

    #[test]
    fn empty_encoding_still_flushes_one_byte() {
        let mut w = Writer::new();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0u8]);
    }

    #[test]
    fn already_byte_aligned_flush_is_noop() {
        let mut w = Writer::new();
        w.put_bits(0xAB, 8);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0xAB]);
    }

    // Cross-checked byte-for-byte against runtime::PerEncodeStream with the
    // identical put_bits() sequence (same tool/method every other crate in
    // this repo uses to validate a port — never hand-craft expected bytes).
    #[test]
    fn matches_cpp_ground_truth() {
        let mut w = Writer::new();
        w.put_bits(0b10110, 5);
        w.put_bits(0b1, 1);
        w.put_bits(0b11, 2);
        w.put_bits(0xABCD, 16);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0xb7, 0xab, 0xcd]);
    }
}
