//! CHOICE encode/decode — X.680 §29, X.690 §8.13.
//!
//! Table-driven (gambas-asn1#284), mirroring `MemberDescriptor<T>`/
//! `SequenceSpec<T>` (`sequence.rs`) and the C++ side's `ChoiceSpec`/
//! `ChoiceBerHandler` (`runtime/src/BerCodec.cpp`): `encode_choice`/
//! `decode_choice` are generic, driven entirely by an `AlternativeSpec<T>`
//! table — no per-type codegen'd `match`/`if` chain.
//!
//! **No `name` field on `ChoiceSpec<T>`, unlike `SequenceSpec<T>`.** A
//! CHOICE has no outer wrapper at all — X.690 §8.13.1: "the value is that
//! of the chosen alternative", so the wire tag IS the chosen alternative's
//! own tag; `ChoiceXerHandler` (`runtime/src/XerCodec.cpp`) confirms the
//! same is true in XER (encodes/decodes using the *alternative's* name as
//! the element tag, never the CHOICE type's own name — there's no `<Choice>`
//! wrapper the way `SequenceXerHandler` wraps every member in `<Widget>`).
//! So this isn't a case of the "shared type-meta abstraction" review
//! feedback from gambas-asn1#281 (PR #288) applying and being skipped —
//! there is no second `name` field to share or duplicate here at all.
//!
//! Each alternative needs two things a `MemberDescriptor<T>` row doesn't:
//! CHOICE is a sum type, so there's no single storage slot for `get`/
//! `get_mut` to point at. `encode: fn(&T, &mut Vec<u8>) -> bool` pattern-
//! matches whether `T` is *this* variant (returns whether it matched and,
//! if so, encoded); `decode_into: fn(&mut Reader) -> Result<T, DecodeError>`
//! builds the right variant from scratch (no `T::default()` pre-existing
//! value to write into, unlike `MemberDescriptor::get_mut` — a CHOICE value
//! doesn't exist yet until decode picks which alternative it is).
//!
//! `Choice` below is both the worked example and this module's own test
//! subject (dogfooding, same role `Point` plays for `sequence.rs`) — real
//! table-driven code, generated for real ASN.1 schemas by `RustBackend`.

use crate::reader::{DecodeError, Reader};
use crate::tag::Tag;
use crate::value::Asn1Value;

/// One CHOICE alternative — mirrors `ChoiceAlternativeSpec`
/// (`compiler/src/codegen/Backend.hpp`), minus everything not yet needed by
/// this crate's scope (EXPLICIT/IMPLICIT tag wrapping beyond the
/// alternative's own natural tag, extension alternatives — real gaps,
/// codegen simply doesn't emit alternatives needing them yet, same
/// incremental principle as every other gambas-asn1#214 sub-issue).
pub struct AlternativeSpec<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub encode: fn(&T, &mut Vec<u8>) -> bool,
    pub decode_into: fn(&mut Reader) -> Result<T, DecodeError>,
}

/// CHOICE alternative table — mirrors `ChoiceSpec` (`Backend.hpp`), minus
/// `name` (see module doc) and the PER/tag-index dispatch-optimization
/// fields (`tag_index_table`/`ber_tags` — follow-on work, not needed for
/// correctness; a linear tag scan is this crate's first cut, same choice
/// `sequence.rs`'s scope note makes for its own follow-on optimizations).
pub struct ChoiceSpec<T: 'static> {
    pub alternatives: &'static [AlternativeSpec<T>],
}

/// Generic CHOICE encoder — the Rust analogue of `ChoiceBerHandler::encode`.
/// Tries each alternative's `encode` in table order; the first one that
/// reports a match wins. Panics if no alternative matches — cannot happen
/// for a real generated `T` (every variant of a codegen'd CHOICE enum has a
/// corresponding table row by construction), so this is a codegen-bug
/// backstop, not a reachable runtime error path.
pub fn encode_choice<T>(spec: &ChoiceSpec<T>, value: &T) -> Vec<u8> {
    for alt in spec.alternatives {
        let mut out = Vec::new();
        if (alt.encode)(value, &mut out) {
            return out;
        }
    }
    panic!("encode_choice: no alternative matched — codegen/table mismatch");
}

/// Generic CHOICE decoder — the Rust analogue of `ChoiceBerHandler::decode`.
/// CHOICE has no outer tag of its own (see module doc): peek the wire tag,
/// linear-scan `spec.alternatives` for the row whose `tag` matches, and
/// delegate to that row's `decode_into`.
pub fn decode_choice<T>(spec: &ChoiceSpec<T>, data: &[u8]) -> Result<T, DecodeError> {
    let mut r = Reader::new(data);
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    for alt in spec.alternatives {
        if alt.tag == tag {
            return (alt.decode_into)(&mut r);
        }
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative tag {tag:?}"), 0))
}

/// `Choice ::= CHOICE { num INTEGER, data OCTET STRING }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Num(i64),
    Data(Vec<u8>),
}

static CHOICE_ALTERNATIVES: [AlternativeSpec<Choice>; 2] = [
    AlternativeSpec {
        name: "num",
        tag: crate::integer::INTEGER_TAG,
        encode: |x, out| {
            if let Choice::Num(v) = x {
                v.ber_encode(out);
                true
            } else {
                false
            }
        },
        decode_into: |r| {
            let mut v: i64 = Default::default();
            v.ber_decode_into(r)?;
            Ok(Choice::Num(v))
        },
    },
    AlternativeSpec {
        name: "data",
        tag: crate::octet_string::OCTET_STRING_TAG,
        encode: |x, out| {
            if let Choice::Data(v) = x {
                v.ber_encode(out);
                true
            } else {
                false
            }
        },
        decode_into: |r| {
            let mut v: Vec<u8> = Default::default();
            v.ber_decode_into(r)?;
            Ok(Choice::Data(v))
        },
    },
];

static CHOICE_SPEC: ChoiceSpec<Choice> = ChoiceSpec { alternatives: &CHOICE_ALTERNATIVES };

impl Choice {
    pub fn encode(&self) -> Vec<u8> {
        encode_choice(&CHOICE_SPEC, self)
    }

    pub fn decode(data: &[u8]) -> Result<Choice, DecodeError> {
        decode_choice(&CHOICE_SPEC, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_num_alternative() {
        assert_eq!(Choice::Num(5).encode(), vec![0x02, 0x01, 0x05]);
    }

    #[test]
    fn encodes_data_alternative() {
        assert_eq!(Choice::Data(vec![1, 2, 3]).encode(), vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn round_trips_both_alternatives() {
        for c in [Choice::Num(-42), Choice::Data(vec![0xAA, 0xBB])] {
            let bytes = c.encode();
            assert_eq!(Choice::decode(&bytes).unwrap(), c);
        }
    }

    #[test]
    fn unrecognized_tag_is_error() {
        let data = [0x30, 0x00]; // SEQUENCE tag — not a Choice alternative
        assert!(Choice::decode(&data).is_err());
    }

    #[test]
    fn empty_input_is_error() {
        assert!(Choice::decode(&[]).is_err());
    }
}
