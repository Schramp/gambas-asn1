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
//! `Choice` (in `tests` below) is both the worked example and this module's
//! own test subject (dogfooding, same role `Point` plays for `sequence.rs`)
//! — real table-driven code, generated for real ASN.1 schemas by
//! `RustBackend`. Test-only (`#[cfg(test)]`, not part of this crate's
//! public API) — a worked example doesn't need to be a permanent public
//! type just to be readable as one.

use crate::reader::{DecodeError, Reader};
use crate::tag::Tag;
use crate::writer::write_primitive;
use crate::xer::{write_close_tag, write_open_tag, XerReader};

/// One CHOICE alternative — mirrors `ChoiceAlternativeSpec`
/// (`compiler/src/codegen/Backend.hpp`), minus the PER/tag-index
/// dispatch-optimization fields (see `ChoiceSpec`'s own doc below) — a
/// real gap, codegen simply doesn't emit alternatives needing it yet. A
/// schema-declared extension alternative (after `...`) is *not* a gap
/// here — it gets a normal `AlternativeSpec` row like any root
/// alternative, same tag-based dispatch either way (BER doesn't
/// distinguish root from extension the way PER's bitmap does). What's
/// genuinely uncovered is an alternative some *future* schema revision
/// might add that this compiler run was never told about — see
/// `ChoiceSpec::unknown_extension`.
///
/// EXPLICIT/IMPLICIT tag override *is* covered: `tag` already
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
    /// `depth` — see `encode_choice_xer_into`'s own doc for what it means here.
    pub xer_encode: fn(&T, &mut String, usize) -> bool,
    pub xer_decode_into: fn(&mut XerReader) -> Result<T, DecodeError>,
}

/// Construct/extract a value for the not-yet-defined "unknown extension"
/// case (X.680 §29.6 extensibility — a `...`-marked CHOICE promises a
/// *future* schema revision may add alternatives this compiler run never
/// saw). Captures the raw tag and value bytes of whatever TLV didn't match
/// any known `AlternativeSpec`, so decode->re-encode round-trips
/// byte-identically even for content this crate can't interpret — `Tag`
/// alone already carries the primitive/constructed bit `write_primitive`
/// needs, so one write path covers both encoding forms (see
/// `writer::write_primitive`'s own body: primitive and constructed TLVs
/// are written identically, the distinction is purely which helper the
/// *caller* reaches for elsewhere).
///
/// BER/decode-side only. XER has no raw-bytes escape hatch the way BER's
/// self-delimiting TLV framing does (X.693 needs to know an element's
/// structure to parse it at all) — `encode_choice_xer`/`decode_choice_xer`
/// don't consult this; a value holding captured unknown-extension content
/// can't be XER-encoded (panics, same as the "no alternative matched"
/// codegen-bug backstop, since from XER's perspective there genuinely is
/// no matching alternative).
pub struct UnknownExtensionOps<T: 'static> {
    pub construct: fn(Tag, Vec<u8>) -> T,
    pub extract: fn(&T) -> Option<(Tag, &[u8])>,
}

/// CHOICE alternative table — mirrors `ChoiceSpec` (`Backend.hpp`), minus
/// `name` (see module doc) and the PER/tag-index dispatch-optimization
/// fields (`tag_index_table`/`ber_tags` — follow-on work, not needed for
/// correctness; a linear tag scan is this crate's first cut, same choice
/// `sequence.rs`'s scope note makes for its own follow-on optimizations).
pub struct ChoiceSpec<T: 'static> {
    pub alternatives: &'static [AlternativeSpec<T>],
    /// `Some` when the schema has a `...` extension marker (X.680 §29.6),
    /// regardless of how many real extension alternatives are declared
    /// after it — `None` for a fully closed CHOICE, where an unrecognized
    /// tag is (correctly) a genuine decode error, not a forward-compat gap.
    pub unknown_extension: Option<UnknownExtensionOps<T>>,
}

/// Generic CHOICE encoder — the Rust analogue of `ChoiceBerHandler::encode`.
/// Tries each alternative's `ber_encode` in table order; the first one that
/// reports a match wins. Falls back to `unknown_extension` (if present) for
/// a value holding captured not-yet-defined-extension content — writes the
/// raw captured tag+bytes back out unchanged. Panics if neither matches:
/// cannot happen for a real generated `T` (every variant of a codegen'd
/// CHOICE enum is either a known alternative's row or, when the schema is
/// extensible, the `unknown_extension` variant, by construction), so this
/// is a codegen-bug backstop, not a reachable runtime error path.
pub fn encode_choice<T>(spec: &ChoiceSpec<T>, value: &T) -> Vec<u8> {
    for alt in spec.alternatives {
        let mut out = Vec::new();
        if (alt.ber_encode)(value, &mut out) {
            return out;
        }
    }
    if let Some(ops) = &spec.unknown_extension {
        if let Some((tag, bytes)) = (ops.extract)(value) {
            let mut out = Vec::new();
            write_primitive(&mut out, tag, bytes);
            return out;
        }
    }
    panic!("encode_choice: no alternative matched — codegen/table mismatch");
}

/// Appends a CHOICE's encoding (whichever alternative's own tag+content —
/// CHOICE has no outer wrapper, see module doc) to an existing buffer — the
/// shape `Asn1Value::ber_encode` needs, so a generated CHOICE type can
/// implement that trait and become usable as a nested composite member.
pub fn encode_choice_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut Vec<u8>) {
    out.extend_from_slice(&encode_choice(spec, value));
}

/// Generic CHOICE decoder — the Rust analogue of `ChoiceBerHandler::decode`.
/// CHOICE has no outer tag of its own (see module doc): peek the wire tag,
/// linear-scan `spec.alternatives` for the row whose `tag` matches, and
/// delegate to that row's `ber_decode_into`. Falls back to
/// `unknown_extension` (if present) when no known alternative's tag
/// matches — captures the whole TLV (tag + value bytes) rather than
/// erroring, honoring the schema's own `...` forward-compatibility promise
/// instead of failing to decode a message using an alternative added in a
/// schema revision newer than whatever this compiler run knew about.
pub fn decode_choice<T>(spec: &ChoiceSpec<T>, data: &[u8]) -> Result<T, DecodeError> {
    let mut r = Reader::new(data);
    decode_choice_from(spec, &mut r)
}

/// Reads a CHOICE from the caller's current stream position — the shape
/// `Asn1Value::ber_decode_into` needs (reads the next TLV from a shared
/// `Reader`, not a standalone buffer) so a generated CHOICE type can
/// implement that trait and become usable as a nested composite member.
pub fn decode_choice_from<T>(spec: &ChoiceSpec<T>, r: &mut Reader) -> Result<T, DecodeError> {
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    for alt in spec.alternatives {
        if alt.tag.matches_identifier(&tag) {
            return (alt.ber_decode_into)(r);
        }
    }
    if let Some(ops) = &spec.unknown_extension {
        let tlv = r.read_tlv()?;
        return Ok((ops.construct)(tlv.tag, tlv.value.to_vec()));
    }
    if crate::debug::debug_flags() & crate::debug::DBG_BER_CHOICE != 0 {
        let alt_tags: Vec<Tag> = spec.alternatives.iter().map(|a| a.tag).collect();
        eprintln!(
            "[DBG_BER_CHOICE] {}: no alternative matches peek tag {tag:?} — known tags: {alt_tags:?}",
            std::any::type_name::<T>()
        );
    }
    Err(DecodeError::new(
        format!("unrecognized CHOICE alternative tag {tag:?} for {}", std::any::type_name::<T>()),
        0,
    ))
}

/// Generic CHOICE XER encoder — the Rust analogue of
/// `ChoiceXerHandler::encode`, top-level entry point (a generated CHOICE
/// type's own `.encode_xer()`). Just `encode_choice_xer_into` at depth 0 —
/// matches the C++ side's exact non-nested-alternative output shape:
/// `\n    <name>value</name>` (leading newline + one indent level, no
/// trailing newline) — verified against the real C++ runtime, not derived
/// from reading the handler alone.
pub fn encode_choice_xer<T>(spec: &ChoiceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    encode_choice_xer_into(spec, value, &mut out, 0);
    out
}

/// Appends a CHOICE's XER content (whichever alternative's own
/// `<name>value</name>` — CHOICE has no outer wrapper, see module doc) to
/// an existing buffer — the shape `Asn1Value::xer_encode` needs (content
/// only, the *member's* own wrapper tag — if any; CHOICE itself needs
/// none — is the caller's job) so a generated CHOICE type can implement
/// that trait leg and become usable as a nested composite member.
///
/// `depth` is *this CHOICE's own* depth — same "argument = my position"
/// convention `Asn1Value::xer_encode` uses everywhere else (see
/// `encode_sequence_xer_content`'s own doc, `xer.rs`, for the fullest
/// explanation). The chosen alternative's own wrapper tag is written one
/// level deeper (`depth + 1`), its inner content one level deeper again
/// (`depth + 2`, passed as `depth + 1` to the alternative's own
/// `xer_encode` closure — consistent since that closure's own `depth`
/// argument means "my position", same as everywhere else).
///
/// Deliberately no trailing `\n` + `indent(depth)` here — unlike every
/// other composite's own content function (`encode_sequence_xer_content`,
/// `encode_seq_of_xer_named`), matching `ChoiceXerHandler::encode`
/// (`runtime/src/XerCodec.cpp`) exactly: it ends right after the chosen
/// alternative's own `</altname>\n`, nothing more — a CHOICE genuinely has
/// no wrapper of its own (module doc) for anything to trail. The generated
/// CHOICE type's own `Asn1Value::xer_encode` impl (`RustBackend.cpp`) adds
/// that trailing bit itself, exactly the way `SequenceXerHandler`'s own
/// CHOICE-typed-member special case does in C++ (writes the *member's*
/// `s.indent(1) << "</" << mbr.name` closing line itself, external to
/// `ChoiceXerHandler`) — necessary there since a `<mname>` wrapper
/// (written by the enclosing SEQUENCE) does follow immediately. A SEQUENCE
/// OF/SET OF element has no such per-element wrapper to position for
/// (`Asn1Value::xer_encode_seqof_element`'s CHOICE override, `value.rs`,
/// calls this function directly, bypassing `xer_encode`'s extra trailing
/// bit) — confirmed against a real schema (`Messaging-Property ::= CHOICE`
/// used as a `SET OF` element): including it there produced a spurious
/// blank line between/after consecutive CHOICE elements.
pub fn encode_choice_xer_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut String, depth: usize) {
    for alt in spec.alternatives {
        let mut inner = String::new();
        if (alt.xer_encode)(value, &mut inner, depth + 1) {
            // Always paired, never self-closing, regardless of content —
            // matches `NullXerHandler::encode`'s literal-name special case
            // (`def.name == "NULL"`): a CHOICE alternative's wrapper name
            // is the alt's own declared identifier (e.g. `"a"`), never
            // literally `"NULL"`, so a NULL alternative encodes as
            // `<a></a>` here, same as asn1c's own reference output.
            // `decode_choice_xer_from` still *accepts* a self-closing
            // `<a/>` on the way in (asn1c's own decoder is lenient there
            // too) — the asymmetry is real, not a bug: round-tripping a
            // self-closing input through this encoder legitimately
            // produces different (but equivalent) output.
            out.push('\n');
            out.push_str(&crate::xer::indent(depth + 1));
            write_open_tag(out, alt.name);
            out.push_str(&inner);
            write_close_tag(out, alt.name);
            return;
        }
    }
    panic!("encode_choice_xer_into: no alternative matched — codegen/table mismatch");
}

/// Generic CHOICE XER decoder — the Rust analogue of
/// `ChoiceXerHandler::decode`. Unlike BER (dispatches by wire tag), XER
/// dispatches by *element name* — peek the next tag's name, linear-scan
/// `spec.alternatives` for the matching row, consume that alternative's
/// open/close tags around its `xer_decode_into`.
pub fn decode_choice_xer<T>(spec: &ChoiceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new(xml);
    decode_choice_xer_from(spec, &mut r)
}

/// Reads a CHOICE from the caller's current XER reader position — the
/// shape `Asn1Value::xer_decode_into` needs, so a generated CHOICE type
/// can implement that trait leg and become usable as a nested composite
/// member, same role `choice::decode_choice_from` plays for the BER leg.
pub fn decode_choice_xer_from<T>(spec: &ChoiceSpec<T>, r: &mut XerReader) -> Result<T, DecodeError> {
    let ti = r.peek_tag();
    for alt in spec.alternatives {
        if ti.name == alt.name {
            // Tolerate a self-closing alternative tag (`<name/>`) the same
            // way `encode_choice_xer_into` produces one for empty content —
            // matches every C++ XER handler's `self_closing` tolerance
            // (e.g. `NullXerHandler::decode`), applied here at the CHOICE
            // wrap level since `alt.xer_decode_into` is content-only.
            let open = r.consume_tag();
            if open.name != alt.name || open.closing {
                return Err(DecodeError::new(format!("XER: expected <{}>", alt.name), 0));
            }
            let result = (alt.xer_decode_into)(r)?;
            if !open.self_closing {
                r.consume_close_tag(alt.name)?;
            }
            return Ok(result);
        }
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative element <{}>", ti.name), 0))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Asn1Value;

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
        xer_encode: |x, out, depth| {
            if let Choice::Num(v) = x {
                v.xer_encode(out, depth);
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
        xer_encode: |x, out, depth| {
            if let Choice::Data(v) = x {
                v.xer_encode(out, depth);
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

static CHOICE_SPEC: ChoiceSpec<Choice> = ChoiceSpec { alternatives: &CHOICE_ALTERNATIVES, unknown_extension: None };

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
            xer_encode: |_, _, _| false,
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
            xer_encode: |_, _, _| false,
            xer_decode_into: |_| Err(DecodeError::new("xer not exercised in this test", 0)),
        },
    ];

    static TWO_OCTETS_EXPLICIT_SPEC: ChoiceSpec<TwoOctetsExplicit> =
        ChoiceSpec { alternatives: &TWO_OCTETS_EXPLICIT_ALTERNATIVES, unknown_extension: None };

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

    // ---- unknown_extension ---------------------------------------------

    /// `ExtChoice ::= CHOICE { num INTEGER, ... }` — mirrors a real schema
    /// pattern (e.g. the ETSI LI PS-PDU schema's `AdditionalSignalling`/
    /// `PstnIsdnIRIContents`, both `CHOICE { <one alternative>, ... }` with
    /// nothing declared after the marker yet): today's compiler run only
    /// knows about `Num`, but the `...` promises a future revision may add
    /// more.
    #[derive(Debug, Clone, PartialEq)]
    enum ExtChoice {
        Num(i64),
        UnknownExtension(Tag, Vec<u8>),
    }

    const NUM_TAG: Tag = Tag::context(0, false);

    static EXT_CHOICE_ALTERNATIVES: [AlternativeSpec<ExtChoice>; 1] = [AlternativeSpec {
        name: "num",
        tag: NUM_TAG,
        ber_encode: |x, out| {
            if let ExtChoice::Num(v) = x {
                crate::integer::write_integer_tagged(out, NUM_TAG, *v);
                true
            } else {
                false
            }
        },
        ber_decode_into: |r| {
            let v = crate::integer::read_integer_tagged(r, NUM_TAG)?;
            Ok(ExtChoice::Num(v))
        },
        xer_encode: |_, _, _| false,
        xer_decode_into: |_| Err(DecodeError::new("xer not exercised in this test", 0)),
    }];

    static EXT_CHOICE_SPEC: ChoiceSpec<ExtChoice> = ChoiceSpec {
        alternatives: &EXT_CHOICE_ALTERNATIVES,
        unknown_extension: Some(UnknownExtensionOps {
            construct: |tag, bytes| ExtChoice::UnknownExtension(tag, bytes),
            extract: |x| match x {
                ExtChoice::UnknownExtension(tag, bytes) => Some((*tag, bytes.as_slice())),
                _ => None,
            },
        }),
    };

    #[test]
    fn known_alternative_still_decodes_normally() {
        let v = ExtChoice::Num(42);
        let enc = encode_choice(&EXT_CHOICE_SPEC, &v);
        assert_eq!(decode_choice(&EXT_CHOICE_SPEC, &enc).unwrap(), v);
    }

    #[test]
    fn unrecognized_tag_captured_instead_of_erroring() {
        // A hypothetical future alternative, tag [1], that EXT_CHOICE_SPEC's
        // table has never heard of.
        let future_tag = Tag::context(1, false);
        let mut wire = Vec::new();
        write_primitive(&mut wire, future_tag, &[0xDE, 0xAD, 0xBE, 0xEF]);

        let decoded = decode_choice(&EXT_CHOICE_SPEC, &wire).unwrap();
        assert_eq!(decoded, ExtChoice::UnknownExtension(future_tag, vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn unrecognized_tag_round_trips_byte_identically() {
        let future_tag = Tag::context(5, true); // constructed, to prove the tag's own bit round-trips too
        let mut wire = Vec::new();
        write_primitive(&mut wire, future_tag, &[0x01, 0x02, 0x03]);

        let decoded = decode_choice(&EXT_CHOICE_SPEC, &wire).unwrap();
        let re_encoded = encode_choice(&EXT_CHOICE_SPEC, &decoded);
        assert_eq!(re_encoded, wire);
    }

    #[test]
    fn closed_choice_without_unknown_extension_still_errors_on_unrecognized_tag() {
        // TWO_OCTETS_EXPLICIT_SPEC has unknown_extension: None — confirms the
        // fallback is opt-in, not a silent behavior change for every CHOICE.
        let data = [0x85, 0x01, 0x00]; // context primitive 5, matches neither TAG_1 nor TAG_2
        assert!(decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &data).is_err());
    }

    // ---- untagged CHOICE-of-CHOICE alternative (flattened dispatch) ------

    /// `Inner ::= CHOICE { a [1] INTEGER, b [2] INTEGER }` — the type an
    /// untagged CHOICE-of-CHOICE alternative (`Outer::Wrapped` below)
    /// delegates to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Inner {
        A(i64),
        B(i64),
    }

    impl Default for Inner {
        fn default() -> Self { Inner::A(0) }
    }

    const INNER_A_TAG: Tag = Tag::context(1, false);
    const INNER_B_TAG: Tag = Tag::context(2, false);

    static INNER_ALTERNATIVES: [AlternativeSpec<Inner>; 2] = [
        AlternativeSpec {
            name: "a",
            tag: INNER_A_TAG,
            ber_encode: |x, out| if let Inner::A(v) = x {
                Asn1Value::ber_encode_tagged(v, INNER_A_TAG, out);
                true
            } else { false },
            ber_decode_into: |r| {
                let mut v: i64 = Default::default();
                Asn1Value::ber_decode_into_tagged(&mut v, r, INNER_A_TAG)?;
                Ok(Inner::A(v))
            },
            xer_encode: |x, out, depth| if let Inner::A(v) = x { v.xer_encode(out, depth); true } else { false },
            xer_decode_into: |r| {
                let mut v: i64 = Default::default();
                v.xer_decode_into(r)?;
                Ok(Inner::A(v))
            },
        },
        AlternativeSpec {
            name: "b",
            tag: INNER_B_TAG,
            ber_encode: |x, out| if let Inner::B(v) = x {
                Asn1Value::ber_encode_tagged(v, INNER_B_TAG, out);
                true
            } else { false },
            ber_decode_into: |r| {
                let mut v: i64 = Default::default();
                Asn1Value::ber_decode_into_tagged(&mut v, r, INNER_B_TAG)?;
                Ok(Inner::B(v))
            },
            xer_encode: |x, out, depth| if let Inner::B(v) = x { v.xer_encode(out, depth); true } else { false },
            xer_decode_into: |r| {
                let mut v: i64 = Default::default();
                v.xer_decode_into(r)?;
                Ok(Inner::B(v))
            },
        },
    ];

    static INNER_SPEC: ChoiceSpec<Inner> = ChoiceSpec { alternatives: &INNER_ALTERNATIVES, unknown_extension: None };

    impl Asn1Value for Inner {
        fn ber_natural_tag(&self) -> Tag { unreachable!("CHOICE has no natural tag") }
        fn xer_element_name(&self) -> &'static str { "Inner" }
        fn ber_encode_content(&self, _out: &mut Vec<u8>) { unreachable!() }
        fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), DecodeError> { unreachable!() }
        fn ber_encode(&self, out: &mut Vec<u8>) { encode_choice_into(&INNER_SPEC, self, out); }
        fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
            *self = decode_choice_from(&INNER_SPEC, r)?;
            Ok(())
        }
        fn xer_encode(&self, out: &mut String, depth: usize) {
            encode_choice_xer_into(&INNER_SPEC, self, out, depth);
            out.push('\n');
            out.push_str(&crate::xer::indent(depth));
        }
        fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
            *self = decode_choice_xer_from(&INNER_SPEC, r)?;
            Ok(())
        }
    }

    /// `Outer ::= CHOICE { inner Inner, direct [9] OCTET STRING }` — `inner`
    /// carries no tag of its own and resolves to a CHOICE (`Inner`), so its
    /// real BER dispatch tags are the union of `Inner`'s own alternative
    /// tags (X.680 §28 — CHOICE has no universal tag; X.690 §8.13
    /// dispatches straight through to whichever alternative the value
    /// actually is). Mirrors the real gap found on the ETSI LI PS-PDU
    /// schema (`GcseIRIsContent`, whose `gcseiRIContent` alternative
    /// resolves to a 4-alternative CHOICE the same way): `RustBackend`
    /// emits one `AlternativeSpec` row per flattened inner tag, both
    /// delegating to the same `Outer::Wrapped` variant via `Inner`'s own
    /// (non-tag-substituting) `Asn1Value::ber_encode`/`ber_decode_into` —
    /// the value already carries its own real tag, whichever of `Inner`'s
    /// alternatives it turns out to be.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Outer {
        Wrapped(Inner),
        Direct(Vec<u8>),
    }

    impl Default for Outer {
        fn default() -> Self { Outer::Wrapped(Inner::default()) }
    }

    const OUTER_DIRECT_TAG: Tag = Tag::context(9, false);

    static OUTER_ALTERNATIVES: [AlternativeSpec<Outer>; 3] = [
        AlternativeSpec {
            name: "inner",
            tag: INNER_A_TAG,
            ber_encode: |x, out| if let Outer::Wrapped(v) = x { Asn1Value::ber_encode(v, out); true } else { false },
            ber_decode_into: |r| {
                let mut v = Inner::default();
                Asn1Value::ber_decode_into(&mut v, r)?;
                Ok(Outer::Wrapped(v))
            },
            xer_encode: |x, out, depth| if let Outer::Wrapped(v) = x { Asn1Value::xer_encode(v, out, depth); true } else { false },
            xer_decode_into: |r| {
                let mut v = Inner::default();
                Asn1Value::xer_decode_into(&mut v, r)?;
                Ok(Outer::Wrapped(v))
            },
        },
        AlternativeSpec {
            name: "inner",
            tag: INNER_B_TAG,
            ber_encode: |x, out| if let Outer::Wrapped(v) = x { Asn1Value::ber_encode(v, out); true } else { false },
            ber_decode_into: |r| {
                let mut v = Inner::default();
                Asn1Value::ber_decode_into(&mut v, r)?;
                Ok(Outer::Wrapped(v))
            },
            xer_encode: |x, out, depth| if let Outer::Wrapped(v) = x { Asn1Value::xer_encode(v, out, depth); true } else { false },
            xer_decode_into: |r| {
                let mut v = Inner::default();
                Asn1Value::xer_decode_into(&mut v, r)?;
                Ok(Outer::Wrapped(v))
            },
        },
        AlternativeSpec {
            name: "direct",
            tag: OUTER_DIRECT_TAG,
            ber_encode: |x, out| if let Outer::Direct(v) = x {
                Asn1Value::ber_encode_tagged(v, OUTER_DIRECT_TAG, out);
                true
            } else { false },
            ber_decode_into: |r| {
                let mut v: Vec<u8> = Default::default();
                Asn1Value::ber_decode_into_tagged(&mut v, r, OUTER_DIRECT_TAG)?;
                Ok(Outer::Direct(v))
            },
            xer_encode: |x, out, depth| if let Outer::Direct(v) = x { v.xer_encode(out, depth); true } else { false },
            xer_decode_into: |r| {
                let mut v: Vec<u8> = Default::default();
                v.xer_decode_into(r)?;
                Ok(Outer::Direct(v))
            },
        },
    ];

    static OUTER_SPEC: ChoiceSpec<Outer> = ChoiceSpec { alternatives: &OUTER_ALTERNATIVES, unknown_extension: None };

    impl Outer {
        fn encode(&self) -> Vec<u8> { encode_choice(&OUTER_SPEC, self) }
        fn decode(data: &[u8]) -> Result<Outer, DecodeError> { decode_choice(&OUTER_SPEC, data) }
    }

    #[test]
    fn untagged_choice_of_choice_alternative_round_trips_every_flattened_tag() {
        for v in [Outer::Wrapped(Inner::A(5)), Outer::Wrapped(Inner::B(-3)), Outer::Direct(vec![1, 2, 3])] {
            let bytes = v.encode();
            assert_eq!(Outer::decode(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn untagged_choice_of_choice_alternative_wire_tag_is_the_inner_alternatives_own_tag() {
        // No extra wrapper is written for the untagged `inner` alternative —
        // the wire tag is directly Inner::A's own tag (context, primitive,
        // number 1 = 0x81), not some synthetic outer tag.
        let bytes = Outer::Wrapped(Inner::A(5)).encode();
        assert_eq!(bytes[0], 0x81);
    }

    #[test]
    fn decode_choice_from_matches_a_row_even_when_its_stored_constructed_bit_is_wrong() {
        // Isolates exactly what `Tag::matches_identifier` (vs plain `==`)
        // buys `decode_choice_from`: a row's table tag disagreeing with the
        // wire's real constructed bit still dispatches correctly. This is
        // the real shape of the bug found on the ETSI LI PS-PDU schema — a
        // flattened dispatch entry (`Generator::collect_ber_tags_for`,
        // reached through a `TypeRef`) can't always resolve the correct
        // constructed bit, but C++'s own `BerCodec.cpp` dispatch never
        // checks it either (every site there compares `cls`/`number` only).
        enum Solo {
            V(u8),
        }
        static ROW: [AlternativeSpec<Solo>; 1] = [AlternativeSpec {
            name: "v",
            tag: Tag::context(1, false), // deliberately the wrong constructed bit
            ber_encode: |x, out| {
                let Solo::V(v) = x;
                write_primitive(out, Tag::context(1, false), &[*v]);
                true
            },
            ber_decode_into: |r| {
                let tlv = r.read_tlv()?;
                Ok(Solo::V(tlv.value[0]))
            },
            xer_encode: |_, _, _| false,
            xer_decode_into: |_| Err(DecodeError::new("not exercised in this test", 0)),
        }];
        static SPEC: ChoiceSpec<Solo> = ChoiceSpec { alternatives: &ROW, unknown_extension: None };

        let mut wire = Vec::new();
        write_primitive(&mut wire, Tag::context(1, true), &[0x05]); // constructed=true on the wire
        match decode_choice(&SPEC, &wire).unwrap() {
            Solo::V(v) => assert_eq!(v, 5),
        }
    }
}
