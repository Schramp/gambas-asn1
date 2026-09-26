//! Generic table-driven CHOICE PER encode/decode. Mirrors `ChoicePerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly: constrained index into the
//! alternatives table (X.691 §22.6 — root alternatives are already stored
//! in canonical tag-ascending order by the caller/codegen, this crate's
//! functions dispatch purely positionally and don't re-sort), extension
//! alternatives as a `normally small non-negative whole number` index
//! (X.691 §10.6) plus open-type wrapping.
//!
//! Reads the same `choice::ChoiceSpec` table BER and XER use. `own_tag`,
//! `ber_tags` and each alternative's `ber` framing are BER-only: UPER has
//! no tags at all, the alternative's position is its identity.
//!
//! `unknown_extension` capture (an extension alternative index the decoder
//! doesn't recognize) is a follow-up: for now `decode_choice_content`
//! returns a decode error for that case, same limitation semantics
//! `asn1cpp_ber`'s own CHOICE decode has for a closed (non-extensible)
//! CHOICE with no capture mechanism.

use crate::choice::{Alternative, ChoiceSpec};
use crate::per::length::{get_length, get_nsnn, put_length, put_nsnn};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

fn per_unsupported<T>(alt: &Alternative<T>) {
    if let Some(reason) = alt.per_unsupported {
        panic!("alternative '{}' not supported: {}", alt.name, reason);
    }
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
    let Some((def_idx, alt, payload)) = crate::choice::active_alt(spec, value) else {
        return; // codegen-bug backstop: no alternative matched a real generated enum.
    };
    per_unsupported(alt);

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
        payload.per_encode(w, alt.constraints);
    } else {
        put_nsnn(w, (def_idx - root_count) as i64);
        let mut tmp = Writer::new();
        payload.per_encode(&mut tmp, alt.constraints);
        tmp.flush();
        let bytes = tmp.into_bytes();
        put_length(w, bytes.len());
        for b in bytes {
            w.put_bits(b as u64, 8);
        }
    }
}

pub fn decode_choice_content_into<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
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
        let alt = &spec.alternatives[def_idx];
        per_unsupported(alt);
        (alt.emplace)(value).per_decode_into(r, alt.constraints)
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
        let alt = &spec.alternatives[def_idx];
        per_unsupported(alt);
        (alt.emplace)(value).per_decode_into(&mut inner, alt.constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::choice::{Alternative, BerTagging};
    use crate::constraints::UNCONSTRAINED;
    use crate::integer::Integer;

    // Dogfood-only fixture (#[cfg(test)]-gated, never public API).
    #[derive(Debug, PartialEq)]
    enum Dogfood {
        A(Integer),
        B(Integer),
        ExtC(Integer),
    }

    impl Default for Dogfood {
        fn default() -> Self {
            Dogfood::A(Integer(0))
        }
    }

    const ALT_A: Alternative<Dogfood> = Alternative {
        name: "a",
        ber: BerTagging::Delegate,
        active: |v| match v {
            Dogfood::A(x) => Some(x),
            _ => None,
        },
        emplace: |v| {
            *v = Dogfood::A(Default::default());
            match v {
                Dogfood::A(x) => x,
                _ => unreachable!(),
            }
        },
        constraints: &UNCONSTRAINED,
        per_unsupported: None,
    };
    const ALT_B: Alternative<Dogfood> = Alternative {
        name: "b",
        ber: BerTagging::Delegate,
        active: |v| match v {
            Dogfood::B(x) => Some(x),
            _ => None,
        },
        emplace: |v| {
            *v = Dogfood::B(Default::default());
            match v {
                Dogfood::B(x) => x,
                _ => unreachable!(),
            }
        },
        constraints: &UNCONSTRAINED,
        per_unsupported: None,
    };
    const ALT_EXT_C: Alternative<Dogfood> = Alternative {
        name: "extC",
        ber: BerTagging::Delegate,
        active: |v| match v {
            Dogfood::ExtC(x) => Some(x),
            _ => None,
        },
        emplace: |v| {
            *v = Dogfood::ExtC(Default::default());
            match v {
                Dogfood::ExtC(x) => x,
                _ => unreachable!(),
            }
        },
        constraints: &UNCONSTRAINED,
        per_unsupported: None,
    };

    const SPEC: ChoiceSpec<Dogfood> = ChoiceSpec {
        name: "Dogfood",
        alternatives: &[ALT_A, ALT_B],
        ber_tags: &[],
        unknown_extension: None,
        own_tag: None,
        ext_at: -1,
    };

    fn roundtrip_with(spec: &ChoiceSpec<Dogfood>, v: &Dogfood) -> Dogfood {
        let mut w = Writer::new();
        encode_choice_content(spec, &mut w, v);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let mut out = Dogfood::default();
        decode_choice_content_into(spec, &mut out, &mut r).unwrap();
        out
    }

    #[test]
    fn root_alternative_a() {
        assert_eq!(roundtrip_with(&SPEC, &Dogfood::A(Integer(5))), Dogfood::A(Integer(5)));
    }

    #[test]
    fn root_alternative_b() {
        assert_eq!(roundtrip_with(&SPEC, &Dogfood::B(Integer(7))), Dogfood::B(Integer(7)));
    }

    const EXT_SPEC: ChoiceSpec<Dogfood> = ChoiceSpec {
        name: "Dogfood",
        alternatives: &[ALT_A, ALT_EXT_C],
        ber_tags: &[],
        unknown_extension: None,
        own_tag: None,
        ext_at: 1,
    };

    #[test]
    fn root_alternative_with_extension_marker_present() {
        assert_eq!(roundtrip_with(&EXT_SPEC, &Dogfood::A(Integer(9))), Dogfood::A(Integer(9)));
    }

    #[test]
    fn extension_alternative() {
        assert_eq!(roundtrip_with(&EXT_SPEC, &Dogfood::ExtC(Integer(123))), Dogfood::ExtC(Integer(123)));
    }

    #[test]
    fn unsupported_alternative_panics_only_when_reached() {
        const STUB: Alternative<Dogfood> = Alternative { per_unsupported: Some("test stub"), ..ALT_B };
        let spec: ChoiceSpec<Dogfood> = ChoiceSpec {
            name: "Dogfood",
            alternatives: &[ALT_A, STUB],
            ber_tags: &[],
            unknown_extension: None,
            own_tag: None,
            ext_at: -1,
        };
        assert_eq!(roundtrip_with(&spec, &Dogfood::A(Integer(1))), Dogfood::A(Integer(1)));
        let r = std::panic::catch_unwind(|| {
            let mut w = Writer::new();
            encode_choice_content(&spec, &mut w, &Dogfood::B(Integer(2)));
        });
        assert!(r.is_err());
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real compiler-generated CHOICE (compiled a throwaway
    // schema through asn1cpp itself: `Test ::= CHOICE { a [0] INTEGER,
    // b [1] INTEGER }`) with the identical alternative shape and values.
    #[test]
    fn matches_cpp_ground_truth() {
        let mut w = Writer::new();
        encode_choice_content(&SPEC, &mut w, &Dogfood::A(Integer(5)));
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x00, 0x82, 0x80]);

        let mut w2 = Writer::new();
        encode_choice_content(&SPEC, &mut w2, &Dogfood::B(Integer(7)));
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x80, 0x83, 0x80]);
    }
}
