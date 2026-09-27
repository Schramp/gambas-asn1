//! Generic table-driven SEQUENCE/SET PER encode/decode. Mirrors
//! `SequencePerHandler` (`runtime/src/PerCodec.cpp`) exactly: preamble
//! bitmap for root OPTIONAL/DEFAULT members (X.691 §18.1), extension bit +
//! count + bitmap + open-type wrapping for extension-addition members
//! (X.691 §18.8).
//!
//! Reads the same `sequence::SequenceSpec`/`MemberDescriptor` table BER and
//! XER walk. PER has no tags, so every retag flavour of `MemberAccess`
//! reads the field the same way (`MemberAccess::accessors`), and a member
//! PER cannot encode yet carries `per_unsupported`.

use crate::constraints::{Constraints, UNCONSTRAINED};
use crate::per::length::{get_length, get_nslength, put_length, put_nslength};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::spec::sequence::{MemberDescriptor, SequenceSpec};

fn root_end<T>(spec: &SequenceSpec<T>) -> usize {
    if spec.ext_at >= 0 {
        spec.ext_at as usize
    } else {
        spec.members.len()
    }
}

fn member_constraints<T>(m: &MemberDescriptor<T>) -> &'static Constraints {
    m.constraints.unwrap_or(&UNCONSTRAINED)
}

/// Presence of an OPTIONAL/DEFAULT member through its `Asn1Value` accessor
/// (`Option<V>` reports `is_some`, every other type `true`); a member with
/// no accessor (ANY) is treated as present, its own `per_unsupported`
/// stub decides what happens next.
fn is_present<T>(m: &MemberDescriptor<T>, value: &T) -> bool {
    m.access.accessors().map_or(true, |(get, _)| get(value).is_present())
}

fn access_encode<T>(m: &MemberDescriptor<T>, value: &T, w: &mut Writer) {
    if let Some(reason) = m.per_unsupported {
        panic!("member '{}' not supported: {}", m.name, reason);
    }
    let (get, _) = m.access.accessors().expect("PER-covered member has an accessor");
    get(value).per_encode(w, member_constraints(m));
}

fn access_decode<T>(m: &MemberDescriptor<T>, result: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    if let Some(reason) = m.per_unsupported {
        panic!("member '{}' not supported: {}", m.name, reason);
    }
    let (_, get_mut) = m.access.accessors().expect("PER-covered member has an accessor");
    get_mut(result).per_decode_into(r, member_constraints(m))
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
        has_ext = spec.members[root_end..].iter().any(|m| is_present(m, value));
        w.put_bits(has_ext as u64, 1);
    }
    for m in &spec.members[..root_end] {
        if !m.optional {
            continue;
        }
        let suppress = m.is_default_equal.map_or(false, |f| f(value));
        let present = is_present(m, value) && !suppress;
        w.put_bits(present as u64, 1);
    }
    for m in &spec.members[..root_end] {
        if m.optional && !is_present(m, value) {
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
            w.put_bits(is_present(m, value) as u64, 1);
        }
        for m in &spec.members[root_end..] {
            if !is_present(m, value) {
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
    use crate::spec::sequence::{MemberAccess, SEQUENCE_TAG};
    use crate::value::Asn1Value;
    use crate::per::integer::{decode_unconstrained_int, encode_unconstrained_int};
    use crate::constraints::Constraints;

    // Dogfood-only fixtures (#[cfg(test)]-gated, never public API — mirrors
    // asn1cpp_ber's own no-public-test-fixtures convention).
    //
    // `a` is a bare `i64` reached through a `Scalar` row whose `constraints`
    // carry its declared range; `b`/`ext1` are `Option<DogfoodInt>`, a real
    // newtype with its own Asn1Value impl that ignores the row's constraints.
    #[derive(Debug, Default, PartialEq)]
    struct DogfoodInt(i64);
    impl Asn1Value for DogfoodInt {
        fn ber_natural_tag(&self) -> crate::ber::tag::Tag { unimplemented!() }
        fn ber_encode_content(&self, _out: &mut Vec<u8>) { unimplemented!() }
        fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), crate::ber::reader::DecodeError> { unimplemented!() }
        fn per_encode(&self, w: &mut Writer, _c: &Constraints) {
            encode_unconstrained_int(w, self.0);
        }
        fn per_decode_into(&mut self, r: &mut Reader, _c: &Constraints) -> Result<(), DecodeError> {
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
        encode_table: None, element: None,
    };

    #[derive(Debug, Default, PartialEq)]
    struct Simple {
        a: crate::integer::Integer,
        b: Option<DogfoodInt>,
    }

    const SIMPLE_SPEC: SequenceSpec<Simple> = SequenceSpec {
        name: "T",
        tag: SEQUENCE_TAG,
        members: &[
            MemberDescriptor {
                name: "a",
                tag: SEQUENCE_TAG,
                optional: false,
                set_default: None,
                is_default_equal: None,
                constraints: Some(&DOGFOOD_CONSTRAINED),
                per_unsupported: None,
                access: MemberAccess::Scalar { get: |t| &t.a, get_mut: |t| &mut t.a },
            },
            MemberDescriptor {
                name: "b",
                tag: SEQUENCE_TAG,
                optional: true,
                set_default: None,
                is_default_equal: None,
                constraints: Some(&crate::constraints::UNCONSTRAINED),
                per_unsupported: None,
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
        let v = Simple { a: crate::integer::Integer(5), b: None };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn mandatory_and_present_optional() {
        let v = Simple { a: crate::integer::Integer(5), b: Some(DogfoodInt(99)) };
        assert_eq!(roundtrip(&v), v);
    }

    #[derive(Debug, Default, PartialEq)]
    struct WithExtension {
        a: crate::integer::Integer,
        ext1: Option<DogfoodInt>,
    }

    const EXT_SPEC: SequenceSpec<WithExtension> = SequenceSpec {
        name: "T",
        tag: SEQUENCE_TAG,
        members: &[
            MemberDescriptor {
                name: "a",
                tag: SEQUENCE_TAG,
                optional: false,
                set_default: None,
                is_default_equal: None,
                constraints: Some(&DOGFOOD_CONSTRAINED),
                per_unsupported: None,
                access: MemberAccess::Scalar { get: |t| &t.a, get_mut: |t| &mut t.a },
            },
            MemberDescriptor {
                name: "ext1",
                tag: SEQUENCE_TAG,
                optional: true,
                set_default: None,
                is_default_equal: None,
                constraints: Some(&crate::constraints::UNCONSTRAINED),
                per_unsupported: None,
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
        let v = WithExtension { a: crate::integer::Integer(3), ext1: None };
        assert_eq!(roundtrip_ext(&v), v);
    }

    #[test]
    fn extension_present() {
        let v = WithExtension { a: crate::integer::Integer(3), ext1: Some(DogfoodInt(123)) };
        assert_eq!(roundtrip_ext(&v), v);
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through a real SEQUENCE TypeDescriptor with the identical member
    // shape (one mandatory INTEGER(0..15), one OPTIONAL unconstrained
    // INTEGER) and values.
    #[test]
    fn matches_cpp_ground_truth() {
        let v = Simple { a: crate::integer::Integer(5), b: Some(DogfoodInt(99)) };
        let mut w = Writer::new();
        encode_sequence_content(&SIMPLE_SPEC, &mut w, &v);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0xa8, 0x0b, 0x18]);

        let v2 = Simple { a: crate::integer::Integer(5), b: None };
        let mut w2 = Writer::new();
        encode_sequence_content(&SIMPLE_SPEC, &mut w2, &v2);
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x28]);
    }

    #[derive(Debug, Default, PartialEq)]
    struct WithUnsupported {
        a: crate::integer::Integer,
        skip: crate::integer::Integer,
    }

    const UNSUPPORTED_SPEC: SequenceSpec<WithUnsupported> = SequenceSpec {
        name: "T",
        tag: SEQUENCE_TAG,
        members: &[
            MemberDescriptor {
                name: "a",
                tag: SEQUENCE_TAG,
                optional: false,
                set_default: None,
                is_default_equal: None,
                constraints: Some(&DOGFOOD_CONSTRAINED),
                per_unsupported: None,
                access: MemberAccess::Scalar { get: |t| &t.a, get_mut: |t| &mut t.a },
            },
            MemberDescriptor {
                name: "skip",
                tag: SEQUENCE_TAG,
                optional: false,
                set_default: None,
                is_default_equal: None,
                constraints: None,
                per_unsupported: Some("test stub"),
                access: MemberAccess::Scalar { get: |t| &t.skip, get_mut: |t| &mut t.skip },
            },
        ],
        ext_at: -1,
    };

    // A real member alongside an `Unsupported` one — mirrors what
    // RustBackend now emits unconditionally for every SEQUENCE (real rows
    // for covered members, `Unsupported` for the rest), rather than
    // withholding the whole type's PER support when any one member isn't
    // covered yet.
    #[test]
    fn unsupported_member_does_not_affect_other_members() {
        let mut w = Writer::new();
        // Only the covered member is ever accessed here — the point is
        // that a table containing an Unsupported row still compiles and
        // that row simply isn't reached unless something tries to
        // encode/decode it specifically.
        access_encode(&UNSUPPORTED_SPEC.members[0], &WithUnsupported { a: crate::integer::Integer(5), skip: crate::integer::Integer(0) }, &mut w);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x50]);
    }

    #[test]
    #[should_panic(expected = "member 'skip' not supported: test stub")]
    fn unsupported_member_panics_if_actually_reached() {
        let mut w = Writer::new();
        access_encode(&UNSUPPORTED_SPEC.members[1], &WithUnsupported { a: crate::integer::Integer(5), skip: crate::integer::Integer(0) }, &mut w);
    }

    // A bare `i64` reached through a plain `Scalar` accessor, with its
    // declared range carried by the row's `constraints` — the encoding is
    // identical to the row in `SIMPLE_SPEC` above.
    #[derive(Debug, Default, PartialEq)]
    struct ScalarInt {
        a: crate::integer::Integer,
    }

    const SCALAR_INT_SPEC: SequenceSpec<ScalarInt> = SequenceSpec {
        name: "T",
        tag: SEQUENCE_TAG,
        ext_at: -1,
        members: &[MemberDescriptor {
            name: "a",
            tag: SEQUENCE_TAG,
            optional: false,
            set_default: None,
            is_default_equal: None,
            access: MemberAccess::Scalar { get: |t| &t.a, get_mut: |t| &mut t.a },
            constraints: Some(&DOGFOOD_CONSTRAINED),
            per_unsupported: None,
        }],
    };

    #[test]
    fn scalar_row_with_constraints_matches_constrained_row() {
        let mut w = Writer::new();
        encode_sequence_content(&SCALAR_INT_SPEC, &mut w, &ScalarInt { a: crate::integer::Integer(9) });
        w.flush();
        let bytes = w.into_bytes();
        let mut direct = Writer::new();
        crate::per::integer::encode_int(&mut direct, &DOGFOOD_CONSTRAINED, 9);
        direct.flush();
        assert_eq!(bytes, direct.into_bytes());
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_sequence_content(&SCALAR_INT_SPEC, &mut r).unwrap(), ScalarInt { a: crate::integer::Integer(9) });
    }
}
