//! Generic table-driven ENUMERATED PER encode/decode. Mirrors
//! `EnumeratedPerHandler` (`runtime/src/PerCodec.cpp`) exactly: the wire
//! ordinal is the value's position in a table sorted ascending by numeric
//! value (X.691 §22 — matches asn1c and the C++ runtime's own sorted
//! `EnumSpec::entries`, not ASN.1 declaration order), a constrained index
//! (X.691 §10.5.6) for a root value, `normally small non-negative whole
//! number` (X.691 §10.6) for an extension-addition value.

use crate::spec::enumerated::EnumSpec;
use crate::per::length::{get_nsnn, put_nsnn};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::encode_error::EncodeError;

/// @brief Encodes an ENUMERATED item: its root index, or for an extension
///        item the extension bit and its ordinal past the root (X.691 §14).
/// @return `Err` for a value that is no item of `spec`.
pub fn encode_enum(w: &mut Writer, spec: &EnumSpec, value: i64) -> Result<(), EncodeError> {
    let rcount = spec.root_count;
    let Some(ordinal) = spec.entries.iter().position(|e| e.value == value) else {
        return Err(EncodeError::new(format!("ENUMERATED {}: value {value} is not one of its items", spec.name)));
    };
    let is_ext = ordinal >= rcount;
    if spec.extensible {
        w.put_bits(is_ext as u64, 1);
    }
    if !is_ext {
        w.put_bits(ordinal as u64, spec.root_bits);
    } else {
        put_nsnn(w, (ordinal - rcount) as i64);
    }
    Ok(())
}

/// @brief Encodes an extension item of a newer schema version by the
///        ordinal PER carried (X.691 §14): extension bit, then the ordinal.
pub fn encode_unknown_ordinal(w: &mut Writer, ordinal: i64) {
    w.put_bits(1, 1);
    put_nsnn(w, ordinal);
}

/// @brief What a PER ENUMERATED field holds: an item's value, or the
///        ordinal of an extension item past the known ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedEnum {
    Item(i64),
    UnknownOrdinal(i64),
}

/// @brief Decode counterpart of [`encode_enum`]; an extension ordinal past
///        the known items is `DecodedEnum::UnknownOrdinal` (X.680 §52.1).
pub fn decode_enum(r: &mut Reader, spec: &EnumSpec) -> Result<DecodedEnum, DecodeError> {
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
        Ok(DecodedEnum::Item(spec.entries[idx].value))
    } else {
        // Compare before adding: the ordinal has no upper bound (X.691 §11.6).
        let ord = get_nsnn(r)?;
        if ord < (spec.entries.len() - rcount) as i64 {
            Ok(DecodedEnum::Item(spec.entries[rcount + ord as usize].value))
        } else {
            Ok(DecodedEnum::UnknownOrdinal(ord))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::enumerated::EnumEntry;

    const fn entry(value: i64) -> EnumEntry {
        EnumEntry { value, name: "" }
    }

    fn roundtrip(spec: &EnumSpec, value: i64) -> i64 {
        let mut w = Writer::new();
        encode_enum(&mut w, spec, value).unwrap();
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        match decode_enum(&mut r, spec).unwrap() {
            DecodedEnum::Item(v) => v,
            DecodedEnum::UnknownOrdinal(o) => panic!("unknown ordinal {o}"),
        }
    }

    const ROOT_ONLY_SPEC: EnumSpec = EnumSpec {
        name: "TestEnum",
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
        name: "TestEnum",
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
        encode_enum(&mut w, &ROOT_ONLY_SPEC, 1).unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b0100_0000]);
    }

    // X.680 §52.1: an extension ordinal past the known items is an item of
    // a newer schema version, kept by its ordinal; it encodes back the same.
    #[test]
    fn unknown_extension_ordinal_is_kept() {
        let mut w = Writer::new();
        encode_unknown_ordinal(&mut w, 5);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_enum(&mut r, &WITH_EXT_SPEC).unwrap(), DecodedEnum::UnknownOrdinal(5));
    }

    #[test]
    fn value_that_is_no_item_fails_encode() {
        let mut w = Writer::new();
        let err = encode_enum(&mut w, &WITH_EXT_SPEC, 9).unwrap_err();
        assert_eq!(err.message, "ENUMERATED TestEnum: value 9 is not one of its items");
    }
}
