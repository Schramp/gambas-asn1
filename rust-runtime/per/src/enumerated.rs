//! Generic table-driven ENUMERATED PER encode/decode. Mirrors
//! `EnumeratedPerHandler` (`runtime/src/PerCodec.cpp`) exactly: the wire
//! ordinal is the value's position in a table sorted ascending by numeric
//! value (X.691 §22 — matches asn1c and the C++ runtime's own sorted
//! `EnumSpec::entries`, not ASN.1 declaration order), a constrained index
//! (X.691 §10.5.6) for a root value, `normally small non-negative whole
//! number` (X.691 §10.6) for an extension-addition value.

use crate::length::{get_nsnn, put_nsnn};
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

/// One row of an ENUMERATED's PER ordinal table. Codegen must emit this
/// table sorted ascending by `value` (mirrors the `std::sort` `CppBackend`
/// performs before writing its own `asn_MAP_`/`EnumSpec::entries`) — every
/// function here trusts that ordering rather than re-sorting.
#[derive(Clone, Copy)]
pub struct EnumEntry {
    pub value: i64,
}

/// X.691 §10.5.6 unaligned variant: minimum bit width to represent values
/// in `0..range`. Duplicated from `choice::range_bits` (`choice.rs`) rather
/// than factored into a shared helper — this crate stays one flat module
/// per construct, no internal utils module, same as the existing `choice`/
/// `sequence` split.
fn range_bits(range: usize) -> u32 {
    if range <= 1 {
        return 0;
    }
    let mut bits = 0;
    let mut r = range - 1;
    while r > 0 {
        bits += 1;
        r >>= 1;
    }
    bits
}

/// `root_count`: entries before the first extension-addition value, or `0`
/// when the ASN.1 ENUMERATED has no `...` marker — mirrors
/// `EnumeratedPerHandler`'s own `rcount = root_count > 0 ? root_count :
/// entries.len()` fallback exactly (`EnumeratedSpec::root_count`,
/// `Backend.hpp`).
pub fn encode_enum(w: &mut Writer, entries: &[EnumEntry], extensible: bool, root_count: usize, value: i64) {
    let rcount = if root_count > 0 { root_count } else { entries.len() };
    let ordinal = entries.iter().position(|e| e.value == value);
    let is_ext = !matches!(ordinal, Some(o) if o < rcount);
    if extensible {
        w.put_bits(is_ext as u64, 1);
    }
    if !is_ext {
        let o = ordinal.unwrap_or(0);
        w.put_bits(o as u64, range_bits(rcount));
    } else {
        let ext_ordinal = ordinal.map_or(0, |o| o - rcount);
        put_nsnn(w, ext_ordinal as i64);
    }
}

/// Decode counterpart of [`encode_enum`].
pub fn decode_enum(r: &mut Reader, entries: &[EnumEntry], extensible: bool, root_count: usize) -> Result<i64, DecodeError> {
    let rcount = if root_count > 0 { root_count } else { entries.len() };
    let mut is_ext = false;
    if extensible {
        is_ext = r.get_bits(1)? != 0;
    }
    if !is_ext {
        let idx = r.get_bits(range_bits(rcount))? as usize;
        if idx >= rcount {
            return Err(DecodeError::new("PER: ENUM index out of range", r.bit_pos()));
        }
        Ok(entries[idx].value)
    } else {
        let ord = get_nsnn(r)? as usize;
        let ext_entry = rcount + ord;
        if ext_entry >= entries.len() {
            return Err(DecodeError::new("PER: ENUM extension index out of range", r.bit_pos()));
        }
        Ok(entries[ext_entry].value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_ONLY: [EnumEntry; 3] = [
        EnumEntry { value: 0 },
        EnumEntry { value: 1 },
        EnumEntry { value: 2 },
    ];

    fn roundtrip(entries: &[EnumEntry], extensible: bool, root_count: usize, value: i64) -> i64 {
        let mut w = Writer::new();
        encode_enum(&mut w, entries, extensible, root_count, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_enum(&mut r, entries, extensible, root_count).unwrap()
    }

    #[test]
    fn root_values_roundtrip() {
        for v in [0, 1, 2] {
            assert_eq!(roundtrip(&ROOT_ONLY, false, 0, v), v);
        }
    }

    const WITH_EXT: [EnumEntry; 4] = [
        EnumEntry { value: 0 },
        EnumEntry { value: 1 },
        EnumEntry { value: 2 },
        EnumEntry { value: 3 },
    ];

    #[test]
    fn root_value_with_extension_marker_present() {
        assert_eq!(roundtrip(&WITH_EXT, true, 3, 1), 1);
    }

    #[test]
    fn extension_value() {
        assert_eq!(roundtrip(&WITH_EXT, true, 3, 3), 3);
    }

    #[test]
    fn out_of_range_root_index_is_rejected() {
        // range_bits(3) == 2 bits; idx 3 (`11`) is out of the 3-entry root
        // range — must land in the "index out of range" error path.
        let mut r = Reader::new(&[0b11_000000]);
        let err = decode_enum(&mut r, &ROOT_ONLY, false, 0).unwrap_err();
        assert!(err.message.contains("out of range"));
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real ENUMERATED TypeDescriptor (three root values
    // 0/1/2, non-extensible) — `Color ::= ENUMERATED { red, green, blue }`
    // compiled through asn1cpp itself, value `green` (ordinal 1, 2 bits).
    #[test]
    fn matches_cpp_ground_truth() {
        let mut w = Writer::new();
        encode_enum(&mut w, &ROOT_ONLY, false, 0, 1);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b0100_0000]);
    }
}
