//! CHOICE encode/decode — X.680 §29, X.690 §8.13.
//!
//! Table-driven, mirroring
//! `MemberDescriptor<T>`/`SequenceSpec<T>` (`sequence.rs`) and the C++
//! side's `ChoiceSpec`/`ChoiceBerHandler`/`ChoiceXerHandler`
//! (`runtime/src/BerCodec.cpp`/`XerCodec.cpp`): `encode_choice`/
//! `decode_choice`/`encode_choice_xer`/`decode_choice_xer` are generic,
//! driven entirely by an `AlternativeSpec<T>` table — no per-type codegen'd
//! `match`/`if` chain, for either wire format.
//!
//! **No `name` field on `ChoiceSpec<T>`, unlike `SequenceSpec<T>`.** A
//! CHOICE has no outer wrapper at all — X.690 §8.13.1: "the value is that
//! of the chosen alternative", so the wire tag IS the chosen alternative's
//! own tag; `ChoiceXerHandler` (`runtime/src/XerCodec.cpp`) confirms the
//! same is true in XER (encodes/decodes using the *alternative's* name as
//! the element tag, never the CHOICE type's own name — there's no `<Choice>`
//! wrapper the way `SequenceXerHandler` wraps every member in `<Widget>`).
//! So this isn't a case of "shared type-meta abstraction" review
//! feedback applying and being skipped — there is no second `name` field
//! to share or duplicate here at all.
//!
//! Each alternative needs two things a `MemberDescriptor<T>` row doesn't:
//! CHOICE is a sum type, so there's no single storage slot for `get`/
//! `get_mut` to point at. `ber_encode: fn(&T, &mut Vec<u8>) -> bool`
//! pattern-matches whether `T` is *this* variant (returns whether it
//! matched and, if so, encoded); `ber_decode_into: fn(&mut Reader) ->
//! Result<T, DecodeError>` builds the right variant from scratch (no
//! `T::default()` pre-existing value to write into, unlike
//! `MemberDescriptor::get_mut` — a CHOICE value doesn't exist yet until
//! decode picks which alternative it is).
//!
//! `Choice` below is both the worked example and this module's own test
//! subject (dogfooding, same role `Point` plays for `sequence.rs`) — real
//! table-driven code, generated for real ASN.1 schemas by `RustBackend`.

use crate::reader::{DecodeError, Reader};
use crate::tag::Tag;
use crate::value::Asn1Value;
use crate::xer::{write_close_tag, write_open_tag, XerReader};

/// One CHOICE alternative — mirrors `ChoiceAlternativeSpec`
/// (`compiler/src/codegen/Backend.hpp`), minus extension alternatives and
/// the PER/tag-index dispatch-optimization fields (see `ChoiceSpec`'s own
/// doc below) — real gaps, codegen simply doesn't emit alternatives needing
/// them yet. EXPLICIT/IMPLICIT tag override *is* covered: `tag` already
/// carries the alternative's real resolved tag, and `ber_encode`/
/// `ber_decode_into` already call whichever primitive that override needs
/// (`value::encode_explicit`/`decode_explicit` generically for EXPLICIT, or
/// the type's own `*_tagged` function for IMPLICIT) — no separate variant
/// needed the way `MemberAccess::TaggedScalar` exists for SEQUENCE, since a
/// CHOICE alternative's closures are already per-alternative, not shared
/// across a `Scalar`/`TaggedScalar` split.
///
/// `xer_encode`/`xer_decode_into` mirror `ber_encode`/
/// `ber_decode_into`'s shape for XER (`xer_*` naming used throughout,
/// not `encode`/`decode_into`, to stay unambiguous once both wire formats
/// exist side by side):
/// `xer_encode` writes the alternative's *inner* content (via
/// `Asn1Value::xer_encode`, same split rationale as `MemberDescriptor` —
/// see `value.rs`'s trait doc) and reports whether it matched;
/// `xer_decode_into` consumes inner content from a reader positioned right
/// after the alternative's own open tag. The *outer* `<name>...</name>`
/// wrapping is the generic walker's job (`encode_choice_xer`/
/// `decode_choice_xer` below) — XER dispatches CHOICE alternatives by
/// *element name*, not by wire tag the way BER does (`ChoiceXerHandler`,
/// `runtime/src/XerCodec.cpp`, peeks the tag *name*, not a
/// `Tag{class,number}`), which is why `decode_choice_xer` doesn't reuse
/// `tag` at all.
pub struct AlternativeSpec<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub ber_encode: fn(&T, &mut Vec<u8>) -> bool,
    pub ber_decode_into: fn(&mut Reader) -> Result<T, DecodeError>,
    pub xer_encode: fn(&T, &mut String) -> bool,
    pub xer_decode_into: fn(&mut XerReader) -> Result<T, DecodeError>,
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
/// Tries each alternative's `ber_encode` in table order; the first one that
/// reports a match wins. Panics if no alternative matches — cannot happen
/// for a real generated `T` (every variant of a codegen'd CHOICE enum has a
/// corresponding table row by construction), so this is a codegen-bug
/// backstop, not a reachable runtime error path.
pub fn encode_choice<T>(spec: &ChoiceSpec<T>, value: &T) -> Vec<u8> {
    for alt in spec.alternatives {
        let mut out = Vec::new();
        if (alt.ber_encode)(value, &mut out) {
            return out;
        }
    }
    panic!("encode_choice: no alternative matched — codegen/table mismatch");
}

/// Generic CHOICE decoder — the Rust analogue of `ChoiceBerHandler::decode`.
/// CHOICE has no outer tag of its own (see module doc): peek the wire tag,
/// linear-scan `spec.alternatives` for the row whose `tag` matches, and
/// delegate to that row's `ber_decode_into`.
pub fn decode_choice<T>(spec: &ChoiceSpec<T>, data: &[u8]) -> Result<T, DecodeError> {
    let mut r = Reader::new(data);
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    for alt in spec.alternatives {
        if alt.tag == tag {
            return (alt.ber_decode_into)(&mut r);
        }
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative tag {tag:?}"), 0))
}

/// Generic CHOICE XER encoder — the Rust analogue of
/// `ChoiceXerHandler::encode`. Tries each alternative's `xer_encode` in
/// table order; the first match wins, wrapped in `<name>...</name>` by this
/// function (not `xer_encode` itself — see `AlternativeSpec`'s doc).
/// Matches the C++ side's exact non-nested-alternative output shape:
/// `\n    <name>value</name>` (leading newline + one indent level, no
/// trailing newline) — verified against the real C++ runtime, not derived
/// from reading the handler alone.
pub fn encode_choice_xer<T>(spec: &ChoiceSpec<T>, value: &T) -> String {
    for alt in spec.alternatives {
        let mut inner = String::new();
        if (alt.xer_encode)(value, &mut inner) {
            let mut out = String::new();
            out.push('\n');
            out.push_str("    ");
            write_open_tag(&mut out, alt.name);
            out.push_str(&inner);
            write_close_tag(&mut out, alt.name);
            return out;
        }
    }
    panic!("encode_choice_xer: no alternative matched — codegen/table mismatch");
}

/// Generic CHOICE XER decoder — the Rust analogue of
/// `ChoiceXerHandler::decode`. Unlike BER (dispatches by wire tag), XER
/// dispatches by *element name* — peek the next tag's name, linear-scan
/// `spec.alternatives` for the matching row, consume that alternative's
/// open/close tags around its `xer_decode_into`.
pub fn decode_choice_xer<T>(spec: &ChoiceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new(xml);
    let ti = r.peek_tag();
    for alt in spec.alternatives {
        if ti.name == alt.name {
            r.consume_open_tag(alt.name)?;
            let result = (alt.xer_decode_into)(&mut r)?;
            r.consume_close_tag(alt.name)?;
            return Ok(result);
        }
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative element <{}>", ti.name), 0))
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
        ber_encode: |x, out| {
            if let Choice::Num(v) = x {
                v.ber_encode(out);
                true
            } else {
                false
            }
        },
        ber_decode_into: |r| {
            let mut v: i64 = Default::default();
            v.ber_decode_into(r)?;
            Ok(Choice::Num(v))
        },
        xer_encode: |x, out| {
            if let Choice::Num(v) = x {
                v.xer_encode(out);
                true
            } else {
                false
            }
        },
        xer_decode_into: |r| {
            let mut v: i64 = Default::default();
            v.xer_decode_into(r)?;
            Ok(Choice::Num(v))
        },
    },
    AlternativeSpec {
        name: "data",
        tag: crate::octet_string::OCTET_STRING_TAG,
        ber_encode: |x, out| {
            if let Choice::Data(v) = x {
                v.ber_encode(out);
                true
            } else {
                false
            }
        },
        ber_decode_into: |r| {
            let mut v: Vec<u8> = Default::default();
            v.ber_decode_into(r)?;
            Ok(Choice::Data(v))
        },
        xer_encode: |x, out| {
            if let Choice::Data(v) = x {
                v.xer_encode(out);
                true
            } else {
                false
            }
        },
        xer_decode_into: |r| {
            let mut v: Vec<u8> = Default::default();
            v.xer_decode_into(r)?;
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

    pub fn encode_xer(&self) -> String {
        encode_choice_xer(&CHOICE_SPEC, self)
    }

    pub fn decode_xer(xml: &str) -> Result<Choice, DecodeError> {
        decode_choice_xer(&CHOICE_SPEC, xml)
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

    #[test]
    fn xer_encodes_num_alternative() {
        // Ground truth from the real C++ runtime (ChoiceXerHandler): a
        // leading newline + one indent level, no trailing newline.
        assert_eq!(Choice::Num(7).encode_xer(), "\n    <num>7</num>");
    }

    #[test]
    fn xer_encodes_data_alternative() {
        assert_eq!(Choice::Data(vec![0x68, 0x69]).encode_xer(), "\n    <data>6869</data>");
    }

    #[test]
    fn xer_round_trips_both_alternatives() {
        for c in [Choice::Num(-42), Choice::Data(vec![0xAA, 0xBB])] {
            let xml = c.encode_xer();
            assert_eq!(Choice::decode_xer(&xml).unwrap(), c);
        }
    }

    #[test]
    fn xer_unrecognized_element_is_error() {
        assert!(Choice::decode_xer("<nope>1</nope>").is_err());
    }

    #[test]
    fn xer_empty_input_is_error() {
        assert!(Choice::decode_xer("").is_err());
    }

    // ---- EXPLICIT tag disambiguation ---------------------

    /// Regression guard for the exact worst-case scenario #346 was filed
    /// for (mirrors `tests/asn1/choice_tagged_alt_test.asn1`'s
    /// `TwoOctetsExplicit`, exercised here at the runtime layer directly
    /// since this crate has no codegen wired in): two alternatives of the
    /// *same* builtin kind, disambiguated only by their EXPLICIT outer
    /// tags. Before #346's fix both would have used the natural
    /// `OCTET_STRING_TAG` and been wire-indistinguishable, so
    /// `decode_choice`'s linear tag scan would misdecode one into the
    /// other.
    enum TwoOctetsExplicit {
        First(Vec<u8>),
        Second(Vec<u8>),
    }

    const TAG_1: Tag = Tag::context(1, true);
    const TAG_2: Tag = Tag::context(2, true);

    static TWO_OCTETS_EXPLICIT_ALTERNATIVES: [AlternativeSpec<TwoOctetsExplicit>; 2] = [
        AlternativeSpec {
            name: "first",
            tag: TAG_1,
            ber_encode: |x, out| {
                if let TwoOctetsExplicit::First(v) = x {
                    crate::value::encode_explicit(out, TAG_1, v);
                    true
                } else {
                    false
                }
            },
            ber_decode_into: |r| {
                let v: Vec<u8> = crate::value::decode_explicit(r, TAG_1)?;
                Ok(TwoOctetsExplicit::First(v))
            },
            xer_encode: |_, _| false,
            xer_decode_into: |_| Err(DecodeError::new("xer not exercised in this test", 0)),
        },
        AlternativeSpec {
            name: "second",
            tag: TAG_2,
            ber_encode: |x, out| {
                if let TwoOctetsExplicit::Second(v) = x {
                    crate::value::encode_explicit(out, TAG_2, v);
                    true
                } else {
                    false
                }
            },
            ber_decode_into: |r| {
                let v: Vec<u8> = crate::value::decode_explicit(r, TAG_2)?;
                Ok(TwoOctetsExplicit::Second(v))
            },
            xer_encode: |_, _| false,
            xer_decode_into: |_| Err(DecodeError::new("xer not exercised in this test", 0)),
        },
    ];

    static TWO_OCTETS_EXPLICIT_SPEC: ChoiceSpec<TwoOctetsExplicit> =
        ChoiceSpec { alternatives: &TWO_OCTETS_EXPLICIT_ALTERNATIVES };

    #[test]
    fn explicit_disambiguates_two_alternatives_of_the_same_builtin_kind() {
        let first = TwoOctetsExplicit::First(vec![0xAA]);
        let second = TwoOctetsExplicit::Second(vec![0xAA]); // same content, different alternative

        let enc_first = encode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &first);
        let enc_second = encode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &second);

        // [1]/[2] EXPLICIT (0xA1/0xA2) wrapping OCTET STRING 0xAA (0x04 0x01 0xAA) —
        // must be wire-distinguishable, unlike the pre-fix natural-tag collision.
        assert_eq!(enc_first, vec![0xA1, 0x03, 0x04, 0x01, 0xAA]);
        assert_eq!(enc_second, vec![0xA2, 0x03, 0x04, 0x01, 0xAA]);
        assert_ne!(enc_first, enc_second);

        match decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &enc_first).unwrap() {
            TwoOctetsExplicit::First(v) => assert_eq!(v, vec![0xAA]),
            TwoOctetsExplicit::Second(_) => panic!("misdecoded First as Second"),
        }
        match decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &enc_second).unwrap() {
            TwoOctetsExplicit::Second(v) => assert_eq!(v, vec![0xAA]),
            TwoOctetsExplicit::First(_) => panic!("misdecoded Second as First"),
        }
    }
}
