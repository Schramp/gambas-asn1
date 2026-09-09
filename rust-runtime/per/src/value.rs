//! `PerValue` — the per-type PER encode/decode trait every generated type
//! implements, parallel to `asn1cpp_ber::value::Asn1Value` but with no
//! shared code (separate crate, no cross-crate dependency — see this
//! crate's own top-level doc for why).
//!
//! No tag-based variants (unlike `Asn1Value`'s `MemberAccess::{Scalar,
//! TaggedScalar, ExplicitScalar, ...}` split): X.691 unaligned PER has no
//! tags at all, so a member's `[n]` IMPLICIT/EXPLICIT override — which only
//! ever changes *tag* bytes — has zero effect on its UPER encoding. Every
//! member needs exactly one shape (see [`crate::sequence::MemberDescriptor`]).
//!
//! Per-member/per-type constraint data (`Constraints` — range bounds, SIZE,
//! FROM alphabet) is *not* a parameter on this trait: by the time generated
//! code implements `PerValue` for a concrete type, its `Constraints` are
//! already known at codegen time and captured directly in the generated
//! `per_encode`/`per_decode_into` body (mirroring how `RustBackend` already
//! emits a `{TYPE}_CONSTRAINTS` static table per BER-validated type) — the
//! generic SEQUENCE/CHOICE walkers below never need to thread one through.

use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

pub trait PerValue {
    fn per_encode(&self, w: &mut Writer);
    fn per_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError>;

    /// Whether this value should appear on the wire at all — always `true`
    /// except for `Option<V>::None`. Lets the generic SEQUENCE walker
    /// (`sequence::encode_sequence_content`) decide whether an OPTIONAL
    /// member is present without downcasting out of the trait object —
    /// same role `Asn1Value::is_present` plays for BER/XER.
    fn is_present(&self) -> bool {
        true
    }
}

/// OPTIONAL member support. An `Option<V>` field (what codegen emits for an
/// OPTIONAL member, matching `asn1cpp_ber`'s own convention so a struct's
/// fields serve both BER and PER encoding without a second parallel
/// representation) becomes wire-absent exactly when `None`.
impl<V: PerValue + Default> PerValue for Option<V> {
    fn is_present(&self) -> bool {
        self.is_some()
    }

    fn per_encode(&self, w: &mut Writer) {
        if let Some(v) = self {
            v.per_encode(w);
        }
    }

    fn per_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        let mut v = V::default();
        v.per_decode_into(r)?;
        *self = Some(v);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default, PartialEq)]
    struct DogfoodInt(i64);

    impl PerValue for DogfoodInt {
        fn per_encode(&self, w: &mut Writer) {
            crate::integer::encode_unconstrained_int(w, self.0);
        }
        fn per_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
            self.0 = crate::integer::decode_unconstrained_int(r)?;
            Ok(())
        }
    }

    #[test]
    fn option_none_writes_nothing() {
        let v: Option<DogfoodInt> = None;
        assert!(!v.is_present());
        let mut w = Writer::new();
        v.per_encode(&mut w);
        assert_eq!(w.bit_pos(), 0);
    }

    #[test]
    fn option_some_roundtrips() {
        let v = Some(DogfoodInt(42));
        assert!(v.is_present());
        let mut w = Writer::new();
        v.per_encode(&mut w);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let mut back: Option<DogfoodInt> = None;
        back.per_decode_into(&mut r).unwrap();
        assert_eq!(back, Some(DogfoodInt(42)));
    }
}
