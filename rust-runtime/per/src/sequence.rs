//! Generic table-driven SEQUENCE/SET PER encode/decode. Mirrors
//! `SequencePerHandler` (`runtime/src/PerCodec.cpp`) exactly: preamble
//! bitmap for root OPTIONAL/DEFAULT members (X.691 §18.1), extension bit +
//! count + bitmap + open-type wrapping for extension-addition members
//! (X.691 §18.8).
//!
//! No tag-based member-access variants (unlike `asn1cpp_ber`'s
//! `MemberAccess::{Scalar, TaggedScalar, ExplicitScalar, ...}`) — see
//! `value` module doc for why PER never needs more than one shape.

use crate::length::{get_length, get_nslength, put_length, put_nslength};
use crate::reader::{DecodeError, Reader};
use crate::value::PerValue;
use crate::writer::Writer;

/// How a member's value is reached and (de)serialized.
///
/// `Scalar` works for a member whose own concrete type genuinely owns a
/// `PerValue` impl — SEQUENCE/CHOICE/SEQUENCE OF newtypes, ENUMERATED (a
/// real, distinct Rust enum per ASN.1 type), or any hand-written newtype.
///
/// `Constrained` is for a member whose Rust field type is a *shared*
/// native type (`i64`/`u64`/`Vec<u8>`/`String`/`bool`) rather than a
/// per-declaration newtype — INTEGER (`pub type X = i64;`, a plain alias:
/// `X` and `i64` are literally the same type) is the clearest case, but
/// OCTET STRING (`Vec<u8>`) and most character-string kinds share the same
/// shape. Unlike BER, where a shared native type's wire encoding never
/// varies by declared constraint (2's-complement TLV either way — the
/// declared range only matters for `Asn1Value::validate()`, a separate
/// post-decode check), PER's wire shape *is* the constraint (constrained
/// → fixed-width field, semi-constrained → offset encoding, unconstrained
/// → variable-length) — so a single `impl PerValue for i64` can't be
/// correct for two differently-constrained INTEGER declarations that both
/// happen to alias `i64`. `Constrained`'s closures are supplied by codegen
/// with this member's own `Constraints` already baked in (calling
/// `integer::encode_int`/`decode_int` or similar internally) — no trait
/// needed for this case at all, mirroring how the C++ side carries
/// `Constraints` in the per-usage `TypeDescriptor`, never in the type itself.
#[derive(Clone, Copy)]
pub enum MemberAccess<T: 'static> {
    Scalar {
        get: fn(&T) -> &dyn PerValue,
        get_mut: fn(&mut T) -> &mut dyn PerValue,
    },
    Constrained {
        encode: fn(&T, &mut Writer),
        decode: fn(&mut T, &mut Reader) -> Result<(), DecodeError>,
    },
}

/// One row in a `SequenceSpec<T>` table — mirrors `MemberDescriptor`
/// (`TypeDescriptor.hpp`)/`asn1cpp_ber::sequence::MemberDescriptor`, minus
/// the tag-related fields neither PER nor this crate need (see module doc).
pub struct MemberDescriptor<T: 'static> {
    pub name: &'static str,
    pub optional: bool,
    /// Presence check — kept as its own closure rather than reusing
    /// `PerValue::is_present` (which only exists for `Scalar` members
    /// anyway) so both `access` variants share one uniform mechanism,
    /// mirroring how `optional_ops.is_present(src)` is already a genuinely
    /// separate concern from a member's own type on the C++ side.
    pub is_present: fn(&T) -> bool,
    /// `Some` for a DEFAULT-valued member (X.680 §25.1) — called when the
    /// member is absent from the wire, filling the schema default instead
    /// of leaving the field however `T::default()` left it. Same shape and
    /// role as `asn1cpp_ber::sequence::MemberDescriptor::set_default`.
    pub set_default: Option<fn(&mut T)>,
    /// PER encode gate (X.691 skips a DEFAULT-valued member equal to its
    /// schema default, same as BER — X.680 §25.1 is encoding-agnostic):
    /// `Some`, returning `true`, for exactly the members `set_default` is
    /// `Some` for. Mirrors `is_default_equal`'s exact role in the BER crate.
    pub is_default_equal: Option<fn(&T) -> bool>,
    pub access: MemberAccess<T>,
}

/// Backend-agnostic decision for one SEQUENCE/SET type — mirrors
/// `asn1cpp_ber::sequence::SequenceSpec<T>`. `ext_at < 0` means no
/// extension marker (X.680 §25.4's `...`); otherwise it's the index of the
/// first extension-addition member, matching `SequenceSpec::ext_at`
/// (`TypeDescriptor.hpp`) exactly.
pub struct SequenceSpec<T: 'static> {
    pub members: &'static [MemberDescriptor<T>],
    pub ext_at: i32,
}

fn root_end<T>(spec: &SequenceSpec<T>) -> usize {
    if spec.ext_at >= 0 {
        spec.ext_at as usize
    } else {
        spec.members.len()
    }
}

fn access_encode<T>(m: &MemberDescriptor<T>, value: &T, w: &mut Writer) {
    match m.access {
        MemberAccess::Scalar { get, .. } => get(value).per_encode(w),
        MemberAccess::Constrained { encode, .. } => encode(value, w),
    }
}

fn access_decode<T>(m: &MemberDescriptor<T>, result: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    match m.access {
        MemberAccess::Scalar { get_mut, .. } => get_mut(result).per_decode_into(r),
        MemberAccess::Constrained { decode, .. } => decode(result, r),
    }
}

/// X.691 §10.2 "Open type fields" — encode this member's value to a
/// temporary buffer, prepend a length determinant. Mirrors
/// `encode_open_type` (`runtime/src/PerCodec.cpp`) exactly.
fn encode_open_type<T>(m: &MemberDescriptor<T>, value: &T, w: &mut Writer) {
    let mut tmp = Writer::new();
    access_encode(m, value, &mut tmp);
    tmp.flush();
    let bytes = tmp.into_bytes();
    put_length(w, bytes.len());
    for b in bytes {
        w.put_bits(b as u64, 8);
    }
}

/// Decode counterpart of [`encode_open_type`].
fn decode_open_type<T>(m: &MemberDescriptor<T>, result: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    let len = get_length(r)?;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(r.get_bits(8)? as u8);
    }
    let mut inner = Reader::new(&bytes);
    access_decode(m, result, &mut inner)
}

/// Skip one unrecognized extension-addition value (X.691 §18.8, a schema
/// version this decoder doesn't know about) — same length-prefixed
/// open-type shape as a known one, contents discarded.
fn skip_open_type(r: &mut Reader) -> Result<(), DecodeError> {
    let len = get_length(r)?;
    for _ in 0..len {
        r.get_bits(8)?;
    }
    Ok(())
}

pub fn encode_sequence_content<T>(spec: &SequenceSpec<T>, w: &mut Writer, value: &T) {
    let root_end = root_end(spec);
    let mut has_ext = false;
    if spec.ext_at >= 0 {
        has_ext = spec.members[root_end..].iter().any(|m| (m.is_present)(value));
        w.put_bits(has_ext as u64, 1);
    }
    for m in &spec.members[..root_end] {
        if !m.optional {
            continue;
        }
        let suppress = m.is_default_equal.map_or(false, |f| f(value));
        let present = (m.is_present)(value) && !suppress;
        w.put_bits(present as u64, 1);
    }
    for m in &spec.members[..root_end] {
        if m.optional && !(m.is_present)(value) {
            continue;
        }
        if let Some(f) = m.is_default_equal {
            if f(value) {
                continue;
            }
        }
        access_encode(m, value, w);
    }
    if has_ext {
        let n_ext = spec.members.len() - root_end;
        put_nslength(w, n_ext);
        for m in &spec.members[root_end..] {
            w.put_bits((m.is_present)(value) as u64, 1);
        }
        for m in &spec.members[root_end..] {
            if !(m.is_present)(value) {
                continue;
            }
            encode_open_type(m, value, w);
        }
    }
}

pub fn decode_sequence_content<T: Default>(
    spec: &SequenceSpec<T>,
    r: &mut Reader,
) -> Result<T, DecodeError> {
    let mut result = T::default();
    let root_end_idx = root_end(spec);

    let mut ext_flag = false;
    if spec.ext_at >= 0 {
        ext_flag = r.get_bits(1)? != 0;
    }

    let roms = spec.members[..root_end_idx].iter().filter(|m| m.optional).count();
    // 64-member cap on the root-level presence bitmap matches
    // SequencePerHandler::decode's own fixed-size `bitmap[64]` — real
    // schemas stay well under this (see that handler's own comment).
    let mut bitmap = [false; 64];
    for slot in bitmap.iter_mut().take(roms.min(64)) {
        *slot = r.get_bits(1)? != 0;
    }

    let mut opt_idx = 0;
    for m in &spec.members[..root_end_idx] {
        if m.optional {
            let present = bitmap[opt_idx];
            opt_idx += 1;
            if !present {
                if let Some(set_default) = m.set_default {
                    set_default(&mut result);
                }
                continue;
            }
        }
        access_decode(m, &mut result, r)?;
    }

    if spec.ext_at >= 0 {
        let known_ext = spec.members.len() - root_end_idx;
        if ext_flag {
            let n_ext = get_nslength(r)?;
            let mut ext_bitmap = [false; 64];
            for slot in ext_bitmap.iter_mut().take(n_ext.min(64)) {
                *slot = r.get_bits(1)? != 0;
            }
            for i in 0..n_ext {
                if !ext_bitmap[i.min(63)] {
                    continue;
                }
                if i < known_ext {
                    decode_open_type(&spec.members[root_end_idx + i], &mut result, r)?;
                } else {
                    skip_open_type(r)?;
                }
            }
        }
        // ext_flag false: every extension member simply keeps whatever
        // T::default() already left it (matches SequencePerHandler::decode
        // calling optional_ops.set_present(dest, false) for each — this
        // crate's Option<V> fields already default to None).
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::{decode_int, encode_int};
    use crate::integer::{decode_unconstrained_int, encode_unconstrained_int};
    use crate::Constraints;

    // Dogfood-only fixtures (#[cfg(test)]-gated, never public API — mirrors
    // asn1cpp_ber's own no-public-test-fixtures convention).
    //
    // `a` is a bare `i64` (Constrained access — the shape a real
    // codegen'd INTEGER alias needs, see MemberAccess's own doc);
    // `b`/`ext1` are `Option<DogfoodInt>`, a real newtype with its own
    // PerValue impl (Scalar access) — together these exercise both
    // MemberAccess variants in the same table.
    #[derive(Debug, Default, PartialEq)]
    struct DogfoodInt(i64);
    impl PerValue for DogfoodInt {
        fn per_encode(&self, w: &mut Writer) {
            encode_unconstrained_int(w, self.0);
        }
        fn per_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
            self.0 = decode_unconstrained_int(r)?;
            Ok(())
        }
    }

    const DOGFOOD_CONSTRAINED: Constraints = Constraints {
        flags: crate::constraints::CONSTRAINED,
        range_bits: 4,
        lower_bound: 0,
        upper_bound: 15,
        lower_u64: 0,
        upper_u64: 0,
        size_range_bits: 0,
        size_lower: 0,
        size_upper: 0,
    };

    #[derive(Debug, Default, PartialEq)]
    struct Simple {
        a: i64,
        b: Option<DogfoodInt>,
    }

    const SIMPLE_SPEC: SequenceSpec<Simple> = SequenceSpec {
        members: &[
            MemberDescriptor {
                name: "a",
                optional: false,
                is_present: |_| true,
                set_default: None,
                is_default_equal: None,
                access: MemberAccess::Constrained {
                    encode: |t, w| encode_int(w, &DOGFOOD_CONSTRAINED, t.a),
                    decode: |t, r| {
                        t.a = decode_int(r, &DOGFOOD_CONSTRAINED)?;
                        Ok(())
                    },
                },
            },
            MemberDescriptor {
                name: "b",
                optional: true,
                is_present: |t| t.b.is_some(),
                set_default: None,
                is_default_equal: None,
                access: MemberAccess::Scalar { get: |t| &t.b, get_mut: |t| &mut t.b },
            },
        ],
        ext_at: -1,
    };

    fn roundtrip(value: &Simple) -> Simple {
        let mut w = Writer::new();
        encode_sequence_content(&SIMPLE_SPEC, &mut w, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_sequence_content(&SIMPLE_SPEC, &mut r).unwrap()
    }

    #[test]
    fn mandatory_and_absent_optional() {
        let v = Simple { a: 5, b: None };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn mandatory_and_present_optional() {
        let v = Simple { a: 5, b: Some(DogfoodInt(99)) };
        assert_eq!(roundtrip(&v), v);
    }

    #[derive(Debug, Default, PartialEq)]
    struct WithExtension {
        a: i64,
        ext1: Option<DogfoodInt>,
    }

    const EXT_SPEC: SequenceSpec<WithExtension> = SequenceSpec {
        members: &[
            MemberDescriptor {
                name: "a",
                optional: false,
                is_present: |_| true,
                set_default: None,
                is_default_equal: None,
                access: MemberAccess::Constrained {
                    encode: |t, w| encode_int(w, &DOGFOOD_CONSTRAINED, t.a),
                    decode: |t, r| {
                        t.a = decode_int(r, &DOGFOOD_CONSTRAINED)?;
                        Ok(())
                    },
                },
            },
            MemberDescriptor {
                name: "ext1",
                optional: true,
                is_present: |t| t.ext1.is_some(),
                set_default: None,
                is_default_equal: None,
                access: MemberAccess::Scalar { get: |t| &t.ext1, get_mut: |t| &mut t.ext1 },
            },
        ],
        ext_at: 1,
    };

    fn roundtrip_ext(value: &WithExtension) -> WithExtension {
        let mut w = Writer::new();
        encode_sequence_content(&EXT_SPEC, &mut w, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_sequence_content(&EXT_SPEC, &mut r).unwrap()
    }

    #[test]
    fn extension_absent() {
        let v = WithExtension { a: 3, ext1: None };
        assert_eq!(roundtrip_ext(&v), v);
    }

    #[test]
    fn extension_present() {
        let v = WithExtension { a: 3, ext1: Some(DogfoodInt(123)) };
        assert_eq!(roundtrip_ext(&v), v);
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real SEQUENCE TypeDescriptor with the identical member
    // shape (one mandatory INTEGER(0..15), one OPTIONAL unconstrained
    // INTEGER) and values.
    #[test]
    fn matches_cpp_ground_truth() {
        let v = Simple { a: 5, b: Some(DogfoodInt(99)) };
        let mut w = Writer::new();
        encode_sequence_content(&SIMPLE_SPEC, &mut w, &v);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0xa8, 0x0b, 0x18]);

        let v2 = Simple { a: 5, b: None };
        let mut w2 = Writer::new();
        encode_sequence_content(&SIMPLE_SPEC, &mut w2, &v2);
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x28]);
    }
}
