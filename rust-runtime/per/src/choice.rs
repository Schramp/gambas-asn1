//! Generic table-driven CHOICE PER encode/decode. Mirrors `ChoicePerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly: constrained index into the
//! alternatives table (X.691 §22.6 — root alternatives are already stored
//! in canonical tag-ascending order by the caller/codegen, this crate's
//! functions dispatch purely positionally and don't re-sort), extension
//! alternatives as a `normally small non-negative whole number` index
//! (X.691 §10.6) plus open-type wrapping.
//!
//! `own_tag` (a CHOICE type's own top-level `[n]` override, X.680 §30.6)
//! has no PER equivalent, unlike `asn1cpp_ber::choice::ChoiceSpec` — UPER
//! has no tags at all, so this genuinely doesn't apply, not an omission.
//!
//! `unknown_extension` capture (an extension alternative index the decoder
//! doesn't recognize) is a follow-up: for now `decode_choice_content`
//! returns a decode error for that case, same limitation semantics
//! `asn1cpp_ber`'s own CHOICE decode has for a closed (non-extensible)
//! CHOICE with no capture mechanism.

use crate::length::{get_length, get_nsnn, put_length, put_nsnn};
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

/// One alternative row — mirrors `asn1cpp_ber::choice::AlternativeSpec`'s
/// `ber_encode`/`ber_decode_into` shape exactly: `per_encode` tries `value`
/// as this alternative, writing content and returning `true` only on a
/// match (nothing written otherwise, since a non-matching closure body is
/// just a failed pattern match); `per_decode_into` decodes this
/// alternative's content and constructs the whole enum value.
pub struct AlternativeSpec<T: 'static> {
    pub name: &'static str,
    pub per_encode: fn(&T, &mut Writer) -> bool,
    pub per_decode_into: fn(&mut Reader) -> Result<T, DecodeError>,
}

pub struct ChoiceSpec<T: 'static> {
    pub alternatives: &'static [AlternativeSpec<T>],
    /// `>= 0` when the schema has a `...` extension marker (X.680 §29.6) —
    /// the index of the first extension alternative, matching `ChoiceSpec`
    /// (`Backend.hpp`)/`sequence::SequenceSpec::ext_at`'s own convention.
    pub ext_at: i32,
}

/// X.691 §10.5.6 unaligned variant: minimum bit width to represent values
/// in `0..range`. Mirrors the file-local `range_bits` helper in
/// `runtime/src/PerCodec.cpp`.
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

fn root_count<T>(spec: &ChoiceSpec<T>) -> usize {
    if spec.ext_at >= 0 {
        spec.ext_at as usize
    } else {
        spec.alternatives.len()
    }
}

pub fn encode_choice_content<T>(spec: &ChoiceSpec<T>, w: &mut Writer, value: &T) {
    // Probe each alternative's closure against a throwaway buffer to find
    // which one matches `value` — same "try each in table order" cost
    // model `asn1cpp_ber::choice::encode_choice_dispatch` already accepts,
    // needed here because (unlike BER) the matched *index* itself has to
    // be written to the stream before that alternative's own content.
    let def_idx = match spec.alternatives.iter().position(|alt| {
        let mut probe = Writer::new();
        (alt.per_encode)(value, &mut probe)
    }) {
        Some(i) => i,
        None => return, // codegen-bug backstop: no alternative matched a real generated enum.
    };

    let root_count = root_count(spec);
    let in_ext = spec.ext_at >= 0 && def_idx >= root_count;
    if spec.ext_at >= 0 {
        w.put_bits(in_ext as u64, 1);
    }
    if !in_ext {
        let bits = range_bits(root_count);
        if bits > 0 {
            w.put_bits(def_idx as u64, bits);
        }
        (spec.alternatives[def_idx].per_encode)(value, w);
    } else {
        put_nsnn(w, (def_idx - root_count) as i64);
        let mut tmp = Writer::new();
        (spec.alternatives[def_idx].per_encode)(value, &mut tmp);
        tmp.flush();
        let bytes = tmp.into_bytes();
        put_length(w, bytes.len());
        for b in bytes {
            w.put_bits(b as u64, 8);
        }
    }
}

pub fn decode_choice_content<T>(spec: &ChoiceSpec<T>, r: &mut Reader) -> Result<T, DecodeError> {
    let root_count = root_count(spec);
    let mut in_ext = false;
    if spec.ext_at >= 0 {
        in_ext = r.get_bits(1)? != 0;
    }
    if !in_ext {
        let bits = range_bits(root_count);
        let def_idx = if bits > 0 { r.get_bits(bits)? as usize } else { 0 };
        if def_idx >= root_count {
            return Err(DecodeError::new("PER: CHOICE index out of range", r.bit_pos()));
        }
        (spec.alternatives[def_idx].per_decode_into)(r)
    } else {
        let ext_idx = get_nsnn(r)?;
        let def_idx = root_count + ext_idx as usize;
        if def_idx >= spec.alternatives.len() {
            let len = get_length(r)?;
            for _ in 0..len {
                r.get_bits(8)?;
            }
            return Err(DecodeError::new(
                "PER: CHOICE extension alternative unknown to this schema (no capture mechanism yet)",
                r.bit_pos(),
            ));
        }
        let len = get_length(r)?;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(r.get_bits(8)? as u8);
        }
        let mut inner = Reader::new(&bytes);
        (spec.alternatives[def_idx].per_decode_into)(&mut inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::{decode_unconstrained_int, encode_unconstrained_int};

    // Dogfood-only fixture (#[cfg(test)]-gated, never public API).
    #[derive(Debug, PartialEq)]
    enum Dogfood {
        A(i64),
        B(i64),
        ExtC(i64),
    }

    const SPEC: ChoiceSpec<Dogfood> = ChoiceSpec {
        alternatives: &[
            AlternativeSpec {
                name: "a",
                per_encode: |v, w| {
                    if let Dogfood::A(x) = v {
                        encode_unconstrained_int(w, *x);
                        true
                    } else {
                        false
                    }
                },
                per_decode_into: |r| Ok(Dogfood::A(decode_unconstrained_int(r)?)),
            },
            AlternativeSpec {
                name: "b",
                per_encode: |v, w| {
                    if let Dogfood::B(x) = v {
                        encode_unconstrained_int(w, *x);
                        true
                    } else {
                        false
                    }
                },
                per_decode_into: |r| Ok(Dogfood::B(decode_unconstrained_int(r)?)),
            },
        ],
        ext_at: -1,
    };

    fn roundtrip(v: &Dogfood) -> Dogfood {
        let mut w = Writer::new();
        encode_choice_content(&SPEC, &mut w, v);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_choice_content(&SPEC, &mut r).unwrap()
    }

    #[test]
    fn root_alternative_a() {
        assert_eq!(roundtrip(&Dogfood::A(5)), Dogfood::A(5));
    }

    #[test]
    fn root_alternative_b() {
        assert_eq!(roundtrip(&Dogfood::B(7)), Dogfood::B(7));
    }

    const EXT_SPEC: ChoiceSpec<Dogfood> = ChoiceSpec {
        alternatives: &[
            AlternativeSpec {
                name: "a",
                per_encode: |v, w| {
                    if let Dogfood::A(x) = v {
                        encode_unconstrained_int(w, *x);
                        true
                    } else {
                        false
                    }
                },
                per_decode_into: |r| Ok(Dogfood::A(decode_unconstrained_int(r)?)),
            },
            AlternativeSpec {
                name: "extC",
                per_encode: |v, w| {
                    if let Dogfood::ExtC(x) = v {
                        encode_unconstrained_int(w, *x);
                        true
                    } else {
                        false
                    }
                },
                per_decode_into: |r| Ok(Dogfood::ExtC(decode_unconstrained_int(r)?)),
            },
        ],
        ext_at: 1,
    };

    fn roundtrip_ext(v: &Dogfood) -> Dogfood {
        let mut w = Writer::new();
        encode_choice_content(&EXT_SPEC, &mut w, v);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_choice_content(&EXT_SPEC, &mut r).unwrap()
    }

    #[test]
    fn root_alternative_with_extension_marker_present() {
        assert_eq!(roundtrip_ext(&Dogfood::A(9)), Dogfood::A(9));
    }

    #[test]
    fn extension_alternative() {
        assert_eq!(roundtrip_ext(&Dogfood::ExtC(123)), Dogfood::ExtC(123));
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real compiler-generated CHOICE (compiled a throwaway
    // schema through asn1cpp itself: `Test ::= CHOICE { a [0] INTEGER,
    // b [1] INTEGER }`) with the identical alternative shape and values.
    #[test]
    fn matches_cpp_ground_truth() {
        let mut w = Writer::new();
        encode_choice_content(&SPEC, &mut w, &Dogfood::A(5));
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x00, 0x82, 0x80]);

        let mut w2 = Writer::new();
        encode_choice_content(&SPEC, &mut w2, &Dogfood::B(7));
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x80, 0x83, 0x80]);
    }
}
