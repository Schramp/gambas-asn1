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
///
/// `xer_encode`/`xer_decode_into` have default bodies (panic / "not yet
/// implemented" error) so a type can get its BER leg wired (gambas-asn1#282)
/// without being forced to add a real XER leg in the same change — the
/// paired follow-up issue (#283) removes the default by adding a real
/// override, same BER-then-XER pairing every step in this baby-step
/// sequence (#214) uses. `i64` overrides both (its XER leg landed in #280);
/// `bool`/`Vec<u8>`/`String` (added in #282) only override the BER leg for
/// now.
pub trait Asn1Value {
    fn ber_encode(&self, out: &mut Vec<u8>);
    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError>;

    fn xer_encode(&self, _out: &mut String) {
        unimplemented!("XER leg not yet wired for this type (see gambas-asn1#283)")
    }

    fn xer_decode_into(&mut self, _text: &str) -> Result<(), DecodeError> {
        Err(DecodeError::new(
            "XER leg not yet wired for this type (see gambas-asn1#283)".to_string(),
            0,
        ))
    }
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

/// BER leg only (gambas-asn1#282) — XER leg is #283, uses the trait default
/// (`unimplemented!`/error) until then.
impl Asn1Value for bool {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::boolean::write_boolean(out, *self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::boolean::read_boolean(r)?;
        Ok(())
    }
}

/// BER leg only (gambas-asn1#282) — XER leg is #283. Maps ASN.1 OCTET
/// STRING (`native_builtin_type`'s `Vec<u8>` choice, `RustBackend.cpp`).
impl Asn1Value for Vec<u8> {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::octet_string::write_octet_string(out, self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::octet_string::read_octet_string(r)?.to_vec();
        Ok(())
    }
}

/// BER leg only (gambas-asn1#282) — XER leg is #283. Maps `IA5String`
/// (`native_builtin_type`'s `String` choice covers all 12 string kinds;
/// this impl is scoped to IA5String's wire tag specifically, see
/// `strings.rs`'s module doc on widening to the others).
impl Asn1Value for String {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::strings::write_ia5_string(out, self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::strings::read_ia5_string(r)?;
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

    #[test]
    fn bool_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        true.ber_encode(&mut out);
        assert_eq!(out, vec![0x01, 0x01, 0xFF]);

        let mut r = Reader::new(&out);
        let mut got = false;
        got.ber_decode_into(&mut r).unwrap();
        assert!(got);
    }

    #[test]
    fn bool_xer_leg_is_not_yet_implemented() {
        let mut got = false;
        assert!(got.xer_decode_into("true").is_err());
    }

    #[test]
    fn vec_u8_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        vec![0x68u8, 0x69].ber_encode(&mut out);
        assert_eq!(out, vec![0x04, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got: Vec<u8> = Vec::new();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, vec![0x68, 0x69]);
    }

    #[test]
    fn string_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        "hi".to_string().ber_encode(&mut out);
        assert_eq!(out, vec![0x16, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = String::new();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, "hi");
    }
}
