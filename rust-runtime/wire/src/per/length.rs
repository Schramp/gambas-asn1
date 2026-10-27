//! Length-determinant and SIZE-field encoding shared by strings and (later)
//! SEQUENCE OF. Mirrors `per_detail::put_length`/`get_length` and
//! `encode_size_field`/`decode_size_field` (`runtime/src/PerCodec.cpp`).
//!
//! Lists of 16K items or more use the fragmentation procedure (X.691
//! §10.9.3.8): `put_length_and_items` / `get_length_and_items` write and
//! read the length together with the items, since fragments interleave
//! length octets with content.

use crate::constraints::Constraints;
use crate::encode_error::EncodeError;
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

/// Fragment granularity of X.691 §10.9.3.8: 16K items.
const FRAGMENT_UNIT: usize = 16384;

/// X.691 §10.9.3.6–10.9.3.7 length determinant for `n` < 16K: short form
/// (≤127, one octet) or long form (two octets, top bits `0b10`). A count
/// of 16K or more is only valid together with its items, through
/// [`put_length_and_items`].
pub fn put_length(w: &mut Writer, n: usize) {
    debug_assert!(n < FRAGMENT_UNIT, "lengths >= 16K need put_length_and_items");
    if n <= 127 {
        w.put_bits(n as u64, 8);
    } else {
        w.put_bits(0x80 | (n as u64 >> 8), 8);
        w.put_bits(n as u64 & 0xFF, 8);
    }
}

/// Decode counterpart of [`put_length`]; a fragment header (`0b11`) is an
/// error here, since only [`get_length_and_items`] can consume fragments.
pub fn get_length(r: &mut Reader) -> Result<usize, DecodeError> {
    let first = r.get_bits(8)?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    if first & 0xC0 == 0x80 {
        let second = r.get_bits(8)?;
        return Ok((((first & 0x3F) << 8) | second) as usize);
    }
    Err(DecodeError::new("PER: fragmented length where a single length is required", r.bit_pos()))
}

/// @brief Writes a general length determinant for `n` items followed by
///        the items, fragmenting at 16K (X.691 §10.9.3.5–10.9.3.8).
/// @param n     Total item count (octets, bits, characters or components).
/// @param items Writes the items with indices in the given range.
/// @note While 16K or more items remain, a header octet `0b11000kkk`
///       announces k (1..=4) blocks of 16K items, then the remaining
///       count is encoded the same way; a remainder of 0 yields the
///       trailing `00` octet of §10.9.3.8.3's note.
pub fn put_length_and_items(w: &mut Writer, n: usize, mut items: impl FnMut(&mut Writer, std::ops::Range<usize>)) {
    let mut start = 0;
    loop {
        let rem = n - start;
        if rem < FRAGMENT_UNIT {
            put_length(w, rem);
            items(w, start..n);
            return;
        }
        let k = (rem / FRAGMENT_UNIT).min(4);
        w.put_bits(0xC0 | k as u64, 8);
        items(w, start..start + k * FRAGMENT_UNIT);
        start += k * FRAGMENT_UNIT;
    }
}

/// @brief Decode counterpart of [`put_length_and_items`]: reads every
///        fragment, handing each item count to `items`.
/// @param items Reads the given number of items.
/// @return The total item count.
pub fn get_length_and_items(
    r: &mut Reader,
    mut items: impl FnMut(&mut Reader, usize) -> Result<(), DecodeError>,
) -> Result<usize, DecodeError> {
    let mut total = 0usize;
    loop {
        let first = r.get_bits(8)?;
        if first & 0xC0 == 0xC0 {
            let k = (first & 0x3F) as usize;
            if !(1..=4).contains(&k) {
                return Err(DecodeError::new("PER: fragment multiplier outside 1..4", r.bit_pos()));
            }
            items(r, k * FRAGMENT_UNIT)?;
            total += k * FRAGMENT_UNIT;
            continue;
        }
        let n = if first & 0x80 == 0 {
            first as usize
        } else {
            (((first & 0x3F) << 8) | r.get_bits(8)?) as usize
        };
        items(r, n)?;
        return Ok(total + n);
    }
}

/// @brief General length plus octets (open types, OID/REAL/ANY contents).
pub fn put_octets(w: &mut Writer, bytes: &[u8]) {
    put_length_and_items(w, bytes.len(), |w, range| {
        for &b in &bytes[range] {
            w.put_bits(b as u64, 8);
        }
    });
}

/// @brief Decode counterpart of [`put_octets`].
pub fn get_octets(r: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    get_length_and_items(r, |r, m| {
        out.reserve(m);
        for _ in 0..m {
            out.push(r.get_bits(8)? as u8);
        }
        Ok(())
    })?;
    Ok(out)
}

/// X.691 §10.9.3.4 "normally small length" — used for a SEQUENCE's
/// extension-addition count. Flag=0: `n` in `1..=64`, encode `n-1` in 6
/// bits. Flag=1: delegate to [`put_length`].
pub fn put_nslength(w: &mut Writer, n: usize) {
    if (1..=64).contains(&n) {
        w.put_bits(0, 1);
        w.put_bits((n - 1) as u64, 6);
    } else {
        w.put_bits(1, 1);
        put_length(w, n);
    }
}

pub fn get_nslength(r: &mut Reader) -> Result<usize, DecodeError> {
    let flag = r.get_bits(1)?;
    if flag == 0 {
        Ok(r.get_bits(6)? as usize + 1)
    } else {
        get_length(r)
    }
}

/// X.691 §10.6 "normally small non-negative whole number" — used for a
/// CHOICE's extension alternative index. Flag=0: value in `0..=63`, encode
/// in 6 bits. Flag=1: delegate to [`put_length`].
pub fn put_nsnn(w: &mut Writer, n: i64) {
    if n <= 63 {
        w.put_bits(0, 1);
        w.put_bits(n as u64, 6);
    } else {
        w.put_bits(1, 1);
        put_length(w, n as usize);
    }
}

pub fn get_nsnn(r: &mut Reader) -> Result<i64, DecodeError> {
    let flag = r.get_bits(1)?;
    if flag == 0 {
        Ok(r.get_bits(6)? as i64)
    } else {
        Ok(get_length(r)? as i64)
    }
}

/// True when a SIZE constraint selects the constrained-count form of the
/// length (X.691 §10.9.4.1, UNALIGNED): constrained with ub < 64K, the
/// rule asn1c applies. Otherwise the general, fragmentable length is used.
fn size_count_is_constrained(pc: &Constraints) -> bool {
    pc.is_size_constrained() && pc.size_upper < 65536
}

/// @brief Writes a SIZE length determinant for `n` items, then the items
///        (X.691 §10.9): nothing for a fixed size, the offset from the
///        lower bound for a constrained size with ub < 64K, otherwise the
///        general length with fragmentation. The constrained form cannot
///        represent a count outside the SIZE range (§10.9.4.1), so such a
///        count is an error and nothing is written.
/// @param items Writes the items with indices in the given range.
pub fn encode_size_and_items(w: &mut Writer, pc: &Constraints, n: usize, mut items: impl FnMut(&mut Writer, std::ops::Range<usize>)) -> Result<(), EncodeError> {
    if size_count_is_constrained(pc) {
        if !(pc.size_lower..=pc.size_upper).contains(&(n as i64)) {
            return Err(EncodeError::new(format!(
                "PER: length {n} outside the non-extensible SIZE ({}..{})",
                pc.size_lower, pc.size_upper
            )));
        }
        if pc.size_range_bits > 0 {
            w.put_bits((n as i64 - pc.size_lower) as u64, pc.size_range_bits);
        }
        items(w, 0..n);
    } else {
        put_length_and_items(w, n, items);
    }
    Ok(())
}

/// @brief Decode counterpart of [`encode_size_and_items`].
/// @param items Reads the given number of items.
/// @return The total item count.
pub fn decode_size_and_items(
    r: &mut Reader,
    pc: &Constraints,
    mut items: impl FnMut(&mut Reader, usize) -> Result<(), DecodeError>,
) -> Result<usize, DecodeError> {
    if size_count_is_constrained(pc) {
        let n = if pc.size_range_bits == 0 {
            pc.size_lower as usize
        } else {
            r.get_bits(pc.size_range_bits)? as usize + pc.size_lower as usize
        };
        items(r, n)?;
        Ok(n)
    } else {
        get_length_and_items(r, items)
    }
}

/// @brief [`encode_size_and_items`] for OCTET STRING (X.691 §17.3), BIT
///        STRING (§16.6) and SEQUENCE OF / SET OF (§20.4), whose extensible
///        SIZE adds one bit first: 0 and the root form when `n` is within
///        the root, otherwise 1 and the general length (§10.9).
pub fn encode_ext_size_and_items(w: &mut Writer, pc: &Constraints, n: usize, items: impl FnMut(&mut Writer, std::ops::Range<usize>)) -> Result<(), EncodeError> {
    if pc.is_extensible() && pc.is_size_constrained() {
        let in_root = (pc.size_lower..=pc.size_upper).contains(&(n as i64));
        w.put_bits(!in_root as u64, 1);
        if !in_root {
            put_length_and_items(w, n, items);
            return Ok(());
        }
    }
    encode_size_and_items(w, pc, n, items)
}

/// @brief Decode counterpart of [`encode_ext_size_and_items`].
pub fn decode_ext_size_and_items(
    r: &mut Reader,
    pc: &Constraints,
    items: impl FnMut(&mut Reader, usize) -> Result<(), DecodeError>,
) -> Result<usize, DecodeError> {
    if pc.is_extensible() && pc.is_size_constrained() && r.get_bits(1)? == 1 {
        return get_length_and_items(r, items);
    }
    decode_size_and_items(r, pc, items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_length(n: usize) -> usize {
        let mut w = Writer::new();
        put_length(&mut w, n);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        get_length(&mut r).unwrap()
    }

    #[test]
    fn short_and_long_form_roundtrip() {
        for n in [0usize, 1, 127, 128, 200, 16383] {
            assert_eq!(roundtrip_length(n), n);
        }
    }

    #[test]
    fn nslength_roundtrip() {
        for n in [1usize, 32, 64, 65, 200] {
            let mut w = Writer::new();
            put_nslength(&mut w, n);
            w.flush();
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(get_nslength(&mut r).unwrap(), n);
        }
    }

    #[test]
    fn nsnn_roundtrip() {
        for n in [0i64, 32, 63, 64, 200] {
            let mut w = Writer::new();
            put_nsnn(&mut w, n);
            w.flush();
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(get_nsnn(&mut r).unwrap(), n);
        }
    }

    // Cross-checked against live put_nslength()/put_nsnn() calls in
    // runtime/src/PerCodec.cpp for the identical input.
    #[test]
    fn nslength_nsnn_match_cpp_ground_truth() {
        let mut w = Writer::new();
        put_nslength(&mut w, 3); // <=64: flag 0 + (3-1)=2 in 6 bits = 0 000010
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b0_000010_0]);

        let mut w2 = Writer::new();
        put_nsnn(&mut w2, 5); // <=63: flag 0 + 5 in 6 bits = 0 000101
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0b0_000101_0]);
    }

    fn sized(lower: i64, upper: i64) -> Constraints {
        let range = (upper - lower + 1) as f64;
        let range_bits = if range <= 1.0 { 0 } else { range.log2().ceil() as u32 };
        Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: range_bits,
            size_lower: lower,
            size_upper: upper,
            ..Default::default()
        }
    }

    #[test]
    fn fixed_size_writes_nothing() {
        let pc = sized(5, 5);
        let mut w = Writer::new();
        encode_size_and_items(&mut w, &pc, 5, |_, _| {}).unwrap();
        assert_eq!(w.bit_pos(), 0);
    }

    #[test]
    fn size_range_roundtrip() {
        let pc = sized(1, 8); // range_bits = 3
        for len in 1..=8usize {
            let mut w = Writer::new();
            encode_size_and_items(&mut w, &pc, len, |_, _| {}).unwrap();
            w.flush();
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(decode_size_and_items(&mut r, &pc, |_, _| Ok(())).unwrap(), len);
        }
    }

    #[test]
    fn unconstrained_size_uses_length_determinant() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        encode_size_and_items(&mut w, &pc, 200, |_, _| {}).unwrap();
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_size_and_items(&mut r, &pc, |_, _| Ok(())).unwrap(), 200);
    }

    // Cross-checked against a live encode_size_field()/decode_size_field()
    // call in runtime/src/PerCodec.cpp for the identical Constraints shape.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = sized(1, 8);
        let mut w = Writer::new();
        encode_size_and_items(&mut w, &pc, 5, |_, _| {}).unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b100_00000]); // 3 bits: (5-1)=4=0b100
    }

    fn frag_roundtrip(n: usize) -> Vec<u8> {
        // Items are octets whose value is the index modulo 251, so any
        // misplaced fragment shows up as a content mismatch.
        let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let mut w = Writer::new();
        put_octets(&mut w, &data);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(get_octets(&mut r).unwrap(), data, "n = {n}");
        bytes
    }

    #[test]
    fn fragment_headers_follow_x691_10_9_3_8() {
        // 16383: plain two-octet length, no fragment.
        assert_eq!(&frag_roundtrip(16383)[..2], &[0xBF, 0xFF]);
        // 16K exactly: one 16K fragment (C1), then the zero-length tail (00).
        let b = frag_roundtrip(16384);
        assert_eq!(b[0], 0xC1);
        assert_eq!(b[1 + 16384], 0x00);
        assert_eq!(b.len(), 1 + 16384 + 1);
        // 64K exactly: one 64K fragment (C4), then 00.
        let b = frag_roundtrip(65536);
        assert_eq!(b[0], 0xC4);
        assert_eq!(b[1 + 65536], 0x00);
        // 64K + 1: C4, 64K octets, then length 1 and the last octet.
        let b = frag_roundtrip(65537);
        assert_eq!(b[1 + 65536], 0x01);
        assert_eq!(b.len(), 1 + 65536 + 1 + 1);
        // X.691 §10.9.3.8.1 note 2: 144K + 1 = 64K + 64K + 16K + 1.
        let b = frag_roundtrip(144 * 1024 + 1);
        assert_eq!(b[0], 0xC4);
        assert_eq!(b[1 + 65536], 0xC4);
        assert_eq!(b[2 + 2 * 65536], 0xC1);
        assert_eq!(b[3 + 2 * 65536 + 16384], 0x01);
    }

    #[test]
    fn size_ub_64k_or_more_uses_the_general_length() {
        // SIZE (16384..70000): range fits 16 bits but ub >= 64K, so the
        // count is a general (fragmentable) length, as asn1c encodes it.
        let pc = sized(16384, 70000);
        let mut w = Writer::new();
        encode_size_and_items(&mut w, &pc, 16384, |w, range| {
            for _ in range {
                w.put_bits(0, 8);
            }
        }).unwrap();
        w.flush();
        assert_eq!(w.into_bytes()[0], 0xC1);
        // SIZE (16384..20000): ub < 64K, constrained 12-bit offset.
        let pc = sized(16384, 20000);
        let mut w = Writer::new();
        encode_size_and_items(&mut w, &pc, 16385, |_, _| {}).unwrap();
        assert_eq!(w.bit_pos(), 12);
    }

    #[test]
    fn extensible_size_writes_extension_bit() {
        let mut pc = sized(1, 4);
        pc.flags |= crate::constraints::EXTENSIBLE;
        // In root (n = 2): ext bit 0, then the 2-bit offset 01.
        let mut w = Writer::new();
        encode_ext_size_and_items(&mut w, &pc, 2, |_, _| {}).unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b0010_0000]);
        // Out of root (n = 6): ext bit 1, then the general length 6.
        let mut w = Writer::new();
        encode_ext_size_and_items(&mut w, &pc, 6, |_, _| {}).unwrap();
        w.flush();
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0b1000_0011, 0b0000_0000]);
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_ext_size_and_items(&mut r, &pc, |_, _| Ok(())).unwrap(), 6);
    }

    /// X.691 §10.9.4.1: a count outside a non-extensible SIZE has no PER
    /// encoding; the encoder reports it and writes nothing.
    #[test]
    fn count_outside_non_extensible_size_is_an_error() {
        let pc = sized(1, 4);
        for n in [0usize, 5, 15] {
            let mut w = Writer::new();
            assert!(encode_size_and_items(&mut w, &pc, n, |_, _| {}).is_err());
            assert_eq!(w.bit_pos(), 0);
            assert!(encode_ext_size_and_items(&mut w, &pc, n, |_, _| {}).is_err());
        }
        let mut w = Writer::new();
        assert!(encode_size_and_items(&mut w, &pc, 4, |_, _| {}).is_ok());
    }

}
