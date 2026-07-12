//! Type-erasure trait for table-driven member access (gambas-asn1#278).
//!
//! C++'s generic `SequenceBerHandler` (`runtime/src/BerCodec.cpp`) reaches
//! a member two ways: `offsetof` pointer arithmetic for required members,
//! `UniquePtrOps` function pointers for optional ones (see
//! `TypeDescriptor.hpp`'s `OptionalOps::member_ptr` — the offset path exists
//! *because* C++ has `offsetof`; Rust has no safe/stable equivalent for
//! non-`#[repr(C)]` structs, so there's no reason to special-case the
//! "required member" path the way C++ does. Every member, required or not,
//! goes through the same accessor-function shape:
//! `fn(&T) -> &dyn Asn1Value` / `fn(&mut T) -> &mut dyn Asn1Value`,
//! stored directly in `MemberDescriptor` (see `sequence.rs`) — no offsets
//! anywhere in this crate.
//!
//! Every BER-primitive field type (`i64` today; more as codegen grows to
//! cover them) implements this trait so a `MemberDescriptor<T>` table can be
//! homogeneous (`&dyn Asn1Value`) despite each member having a different
//! concrete Rust type — the same role `Asn1Object` (the common base class
//! every generated C++ type inherits from) plays in `TypeDescriptor.hpp`,
//! done via a trait object instead of inheritance.

use crate::reader::{DecodeError, Reader};

/// A BER/XER-encodable/decodable value reachable through a
/// `MemberDescriptor` accessor function. `*_decode_into` (not a
/// `Self`-returning `decode`) keeps this object-safe (`&mut dyn Asn1Value`
/// needs no `Self` in its signature) — the field already exists (struct
/// built via `Default`), decode overwrites it in place.
///
/// `xer_encode`/`xer_decode_into` write/read only the element's *text
/// content* (e.g. `3`, not `<x>3</x>`) — XER element tags are field-name-
/// derived (`MemberDescriptor::name`), not type-derived like BER tags, so
/// tag wrapping is the table-driven walker's job (gambas-asn1#281), not
/// `Asn1Value`'s. See `xer.rs`'s module doc for the full split rationale.
pub trait Asn1Value {
    fn ber_encode(&self, out: &mut Vec<u8>);
    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError>;

    fn xer_encode(&self, out: &mut String);
    fn xer_decode_into(&mut self, text: &str) -> Result<(), DecodeError>;
}

impl Asn1Value for i64 {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::integer::write_integer(out, *self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::integer::read_integer(r)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        out.push_str(&self.to_string());
    }

    fn xer_decode_into(&mut self, text: &str) -> Result<(), DecodeError> {
        *self = text.trim().parse::<i64>().map_err(|_| {
            DecodeError::new(format!("XER: invalid INTEGER value: {text}"), 0)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i64_round_trips_through_the_trait() {
        let mut out = Vec::new();
        300i64.ber_encode(&mut out);
        assert_eq!(out, vec![0x02, 0x02, 0x01, 0x2C]);

        let mut r = Reader::new(&out);
        let mut got: i64 = 0;
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, 300);
    }

    #[test]
    fn i64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag, XerReader};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        1i64.xer_encode(&mut out);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let text = r.read_text_content();
        let mut got: i64 = 0;
        got.xer_decode_into(text).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1);
    }

    #[test]
    fn i64_xer_negative_and_whitespace() {
        let mut out = String::new();
        (-42i64).xer_encode(&mut out);
        assert_eq!(out, "-42");

        let mut got: i64 = 0;
        got.xer_decode_into("  -42  ").unwrap();
        assert_eq!(got, -42);
    }

    #[test]
    fn i64_xer_invalid_text_is_error() {
        let mut got: i64 = 0;
        assert!(got.xer_decode_into("not-a-number").is_err());
    }
}
