//! Generic table-driven ENUMERATED PER encode/decode. Mirrors
//! `EnumeratedPerHandler` (`runtime/src/PerCodec.cpp`) exactly: the wire
//! ordinal is the value's position in a table sorted ascending by numeric
//! value (X.691 §22 — matches asn1c and the C++ runtime's own sorted
//! `EnumSpec::entries`, not ASN.1 declaration order), a constrained index
//! (X.691 §10.5.6) for a root value, `normally small non-negative whole
//! number` (X.691 §10.6) for an extension-addition value.

use crate::enumerated::EnumSpec;
use crate::per::length::{get_nsnn, put_nsnn};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode_enum(w: &mut Writer, spec: &EnumSpec, value: i64) {
    let rcount = spec.root_count;
    let ordinal = spec.entries.iter().position(|e| e.value == value);
    let is_ext = !matches!(ordinal, Some(o) if o < rcount);
    if spec.extensible {
        w.put_bits(is_ext as u64, 1);
    }
    if !is_ext {
        let o = ordinal.unwrap_or(0);
        w.put_bits(o as u64, spec.root_bits);
    } else {
        let ext_ordinal = ordinal.map_or(0, |o| o - rcount);
        put_nsnn(w, ext_ordinal as i64);
    }
}

/// Decode counterpart of [`encode_enum`].
pub fn decode_enum(r: &mut Reader, spec: &EnumSpec) -> Result<i64, DecodeError> {
    let rcount = spec.root_count;
    let mut is_ext = false;
    if spec.extensible {
        is_ext = r.get_bits(1)? != 0;
    }
    if !is_ext {
        let idx = r.get_bits(spec.root_bits)? as usize;
        if idx >= rcount {
            return Err(DecodeError::new("PER: ENUM index out of range", r.bit_pos()));
        }
        Ok(spec.entries[idx].value)
    } else {
        let ord = get_nsnn(r)? as usize;
        let ext_entry = rcount + ord;
        if ext_entry >= spec.entries.len() {
            return Err(DecodeError::new("PER: ENUM extension index out of range", r.bit_pos()));
        }
        Ok(spec.entries[ext_entry].value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerated::EnumEntry;

    const fn entry(value: i64) -> EnumEntry {
        EnumEntry { value, name: "" }
    }

    fn roundtrip(spec: &EnumSpec, value: i64) -> i64 {
        let mut w = Writer::new();
        encode_enum(&mut w, spec, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_enum(&mut r, spec).unwrap()
    }

    const ROOT_ONLY_SPEC: EnumSpec = EnumSpec {
        entries: &[entry(0), entry(1), entry(2)],
        extensible: false,
        root_count: 3,
        root_bits: 2,
    };

    #[test]
    fn root_values_roundtrip() {
        for v in [0, 1, 2] {
            assert_eq!(roundtrip(&ROOT_ONLY_SPEC, v), v);
        }
    }

    const WITH_EXT_SPEC: EnumSpec = EnumSpec {
        entries: &[entry(0), entry(1), entry(2), entry(3)],
        extensible: true,
        root_count: 3,
        root_bits: 2,
    };

    #[test]
    fn root_value_with_extension_marker_present() {
        assert_eq!(roundtrip(&WITH_EXT_SPEC, 1), 1);
    }

    #[test]
    fn extension_value() {
        assert_eq!(roundtrip(&WITH_EXT_SPEC, 3), 3);
    }

    #[test]
    fn out_of_range_root_index_is_rejected() {
        // range_bits(3) == 2 bits; idx 3 (`11`) is out of the 3-entry root
        // range — must land in the "index out of range" error path.
        let mut r = Reader::new(&[0b11_000000]);
        let err = decode_enum(&mut r, &ROOT_ONLY_SPEC).unwrap_err();
        assert!(err.message.contains("out of range"));
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real ENUMERATED TypeDescriptor (three root values
    // 0/1/2, non-extensible) — `Color ::= ENUMERATED { red, green, blue }`
    // compiled through asn1cpp itself, value `green` (ordinal 1, 2 bits).
    #[test]
    fn matches_cpp_ground_truth() {
        let mut w = Writer::new();
        encode_enum(&mut w, &ROOT_ONLY_SPEC, 1);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b0100_0000]);
    }
}
