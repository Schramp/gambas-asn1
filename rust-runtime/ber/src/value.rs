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
use crate::xer::XerReader;

/// A BER/XER-encodable/decodable value reachable through a
/// `MemberDescriptor` accessor function. `*_decode_into` (not a
/// `Self`-returning `decode`) keeps this object-safe (`&mut dyn Asn1Value`
/// needs no `Self` in its signature) — the field already exists (struct
/// built via `Default`), decode overwrites it in place.
///
/// `xer_encode` writes only the element's *inner content* (e.g. `3` for
/// `<x>3</x>`, but also `<true/>` for `<flag><true/></flag>` — BOOLEAN's
/// BASIC-XER form is itself a nested tag, not plain text, see the `bool`
/// impl below) — XER element tags are field-name-derived
/// (`MemberDescriptor::name`), not type-derived like BER tags, so the
/// *outer* tag wrapping is the table-driven walker's job (gambas-asn1#281),
/// not `Asn1Value`'s.
///
/// `xer_decode_into` takes a `&mut XerReader` positioned right after the
/// member's open tag, not a pre-extracted `&str` (revised in gambas-asn1#283
/// from #280/#281's original `&str` signature) — discovered necessary
/// because `bool`'s content isn't text at all, it's a nested `<true/>`/
/// `<false/>` tag, which `XerReader::read_text_content` (stops at the next
/// `<`) can't hand back as a string. Giving every impl the reader directly
/// lets each type consume exactly the inner grammar BASIC-XER defines for
/// it (plain escaped text for INTEGER/OCTET-STRING/IA5String, a nested tag
/// for BOOLEAN) and leaves the reader positioned at the member's close tag,
/// which the walker consumes afterward.
///
/// `xer_encode`/`xer_decode_into` have default bodies (panic / "not yet
/// implemented" error) so a type can get its BER leg wired without being
/// forced to add a real XER leg in the same change (gambas-asn1#282 landed
/// BER-only for `bool`/`Vec<u8>`/`String`; gambas-asn1#283 removes the
/// default here by adding real overrides) — same BER-then-XER pairing every
/// step in this baby-step sequence (#214) uses.
pub trait Asn1Value {
    fn ber_encode(&self, out: &mut Vec<u8>);
    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError>;

    fn xer_encode(&self, _out: &mut String) {
        unimplemented!("XER leg not yet wired for this type")
    }

    fn xer_decode_into(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        Err(DecodeError::new("XER leg not yet wired for this type".to_string(), 0))
    }

    /// Whether this value should appear on the wire at all — always `true`
    /// except for `Option<V>::None` (see the blanket impl below). Lets the
    /// generic SEQUENCE walkers (`encode_sequence_xer`'s outer-tag wrapping;
    /// `encode_sequence`'s BER leg needs no equivalent check, since
    /// `Option<V>::ber_encode` already writes nothing for `None`) decide
    /// whether to emit an OPTIONAL member without downcasting out of the
    /// trait object.
    fn is_present(&self) -> bool {
        true
    }
}

/// gambas-asn1#346: EXPLICIT tagging (X.690 §8.14.3), generic over any
/// `Asn1Value` — wraps the value's own natural encoding in an outer TLV via
/// `writer::write_explicit`/`reader::read_explicit`. The generic
/// counterpart to each type's own `*_tagged` functions (IMPLICIT —
/// `boolean::write_boolean_tagged`, `integer::write_integer_tagged`, etc.):
/// those substitute the tag and need a per-kind primitive because the wire
/// *shape* differs per kind; EXPLICIT only ever adds one outer wrapper
/// around whatever the natural encoding already is, so one generic pair
/// covers every `Asn1Value` impl instead of needing one per kind.
pub fn encode_explicit<T: Asn1Value>(out: &mut Vec<u8>, tag: crate::tag::Tag, value: &T) {
    crate::writer::write_explicit(out, tag, |inner| value.ber_encode(inner));
}

pub fn decode_explicit<T: Asn1Value + Default>(r: &mut Reader, tag: crate::tag::Tag) -> Result<T, DecodeError> {
    crate::reader::read_explicit(r, tag, |inner| {
        let mut tmp = T::default();
        tmp.ber_decode_into(inner)?;
        Ok(tmp)
    })
}

/// gambas-asn1#326: OPTIONAL member support. An `Option<V>` field (what
/// `RustBackend` emits for an OPTIONAL member, mirroring C++'s
/// `std::optional<T>`/`unique_ptr<T>`) becomes wire-absent exactly when
/// `None` — encoding is `if let Some(v) = self { v.ber_encode/xer_encode }`,
/// nothing otherwise. Decoding always assumes presence (`ber_decode_into`/
/// `xer_decode_into` unconditionally produce `Some`): the *decision* of
/// whether to call it at all belongs to the generic walker
/// (`decode_sequence`/`decode_sequence_xer`), which peeks the member's tag
/// first and only invokes this impl when the tag/element actually matches —
/// same tag-presence-detection model `asn1cpp/CLAUDE.md`'s PER table
/// documents for BER (bitmap in PER; tag-present-or-absent in BER).
impl<V: Asn1Value + Default> Asn1Value for Option<V> {
    fn is_present(&self) -> bool {
        self.is_some()
    }

    fn ber_encode(&self, out: &mut Vec<u8>) {
        if let Some(v) = self {
            v.ber_encode(out);
        }
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        let mut v = V::default();
        v.ber_decode_into(r)?;
        *self = Some(v);
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        if let Some(v) = self {
            v.xer_encode(out);
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let mut v = V::default();
        v.xer_decode_into(r)?;
        *self = Some(v);
        Ok(())
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

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        *self = text.trim().parse::<i64>().map_err(|_| {
            DecodeError::new(format!("XER: invalid INTEGER value: {text}"), 0)
        })?;
        Ok(())
    }
}

/// Mirrors `BooleanXerHandler` (`runtime/src/XerCodec.cpp`) — BASIC-XER's
/// `EmptyElementBoolean` form: content is a nested self-closing `<true/>`/
/// `<false/>` tag, not text (X.693 §8.2's default form; the lenient
/// text-content alternative `XerDecodeMode::Lenient` allows on the C++ side
/// isn't implemented here, matching this crate's strict-by-default scope
/// elsewhere).
impl Asn1Value for bool {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::boolean::write_boolean(out, *self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::boolean::read_boolean(r)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        out.push_str(if *self { "<true/>" } else { "<false/>" });
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let ti = r.consume_tag();
        if ti.self_closing && ti.name == "true" {
            *self = true;
            Ok(())
        } else if ti.self_closing && ti.name == "false" {
            *self = false;
            Ok(())
        } else {
            Err(DecodeError::new("XER BOOLEAN: expected <true/> or <false/>".to_string(), 0))
        }
    }
}

/// Maps ASN.1 NULL (gambas-asn1#349) — `native_builtin_type`'s `()` choice,
/// `RustBackend.cpp`. Mirrors `NullXerHandler`'s named-wrapper form
/// (`runtime/src/XerCodec.cpp`): empty content inside the member's own
/// `<name></name>` tag, e.g. `<flag></flag>` — the self-closing `<NULL/>`
/// form that same handler emits only applies when the *type's own name* is
/// literally "NULL" (a raw top-level/SEQUENCE-OF-element descriptor, an
/// asn1c-compat quirk), never a member's field-name-derived tag, so
/// `Asn1Value` (member-embedded content only, per this trait's own doc
/// comment) never needs that branch.
impl Asn1Value for () {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::null::write_null(out);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        crate::null::read_null(r)
    }

    fn xer_encode(&self, _out: &mut String) {
        // Empty content — nothing to write.
    }

    fn xer_decode_into(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        // Empty content — nothing to consume.
        Ok(())
    }
}

/// Maps ASN.1 OCTET STRING (`native_builtin_type`'s `Vec<u8>` choice,
/// `RustBackend.cpp`). Mirrors `OctetStringXerHandler`'s default (non-Base64)
/// encoding: unspaced uppercase hex pairs (`write_hex_bytes`,
/// `runtime/src/HexEncoder.hpp`) — distinct from BIT STRING/hex-string
/// types' *spaced* hex (`format_hex_bytes`), not implemented by this crate.
impl Asn1Value for Vec<u8> {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::octet_string::write_octet_string(out, self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::octet_string::read_octet_string(r)?.to_vec();
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        for b in self {
            out.push_str(&format!("{b:02X}"));
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        // Mirrors parse_hex_bytes (runtime/src/XerCodec.cpp): skip
        // whitespace between pairs, stop silently (not an error) at the
        // first non-hex-pair remainder — lenient by design on the C++ side,
        // matched here rather than diverging into stricter validation.
        let mut bytes = Vec::new();
        let trimmed = text.trim();
        let mut chars = trimmed.chars().filter(|c| !c.is_whitespace()).peekable();
        while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
            let byte_str: String = [hi, lo].iter().collect();
            match u8::from_str_radix(&byte_str, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => break,
            }
        }
        *self = bytes;
        Ok(())
    }
}

/// Maps `IA5String` (`native_builtin_type`'s `String` choice covers all 12
/// string kinds; this impl is scoped to IA5String's wire tag specifically,
/// see `strings.rs`'s module doc on widening to the others). Mirrors
/// `XerStringHandler`: escaped text content, via the same `xer::escape`/
/// `xer::unescape` gambas-asn1#280 already built.
impl Asn1Value for String {
    fn ber_encode(&self, out: &mut Vec<u8>) {
        crate::strings::write_ia5_string(out, self);
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        *self = crate::strings::read_ia5_string(r)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        crate::xer::escape(self, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        *self = crate::xer::unescape(text);
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
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        1i64.xer_encode(&mut out);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got: i64 = 0;
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1);
    }

    #[test]
    fn i64_xer_negative_and_whitespace() {
        let mut out = String::new();
        (-42i64).xer_encode(&mut out);
        assert_eq!(out, "-42");

        let mut r = XerReader::new("  -42  ");
        let mut got: i64 = 0;
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, -42);
    }

    #[test]
    fn i64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got: i64 = 0;
        assert!(got.xer_decode_into(&mut r).is_err());
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
    fn unit_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        ().ber_encode(&mut out);
        assert_eq!(out, vec![0x05, 0x00]);

        let mut r = Reader::new(&out);
        let mut got = ();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, ());
    }

    #[test]
    fn unit_xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        ().xer_encode(&mut out);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = ();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert_eq!(got, ());
    }

    #[test]
    fn bool_xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        true.xer_encode(&mut out);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag><true/></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = false;
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert!(got);
    }

    #[test]
    fn bool_xer_false_round_trips() {
        let mut out = String::new();
        false.xer_encode(&mut out);
        assert_eq!(out, "<false/>");

        let mut r = XerReader::new("<false/>");
        let mut got = true;
        got.xer_decode_into(&mut r).unwrap();
        assert!(!got);
    }

    #[test]
    fn bool_xer_rejects_non_empty_element_form() {
        let mut r = XerReader::new("true");
        let mut got = false;
        assert!(got.xer_decode_into(&mut r).is_err());
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

    #[test]
    fn vec_u8_xer_encodes_unspaced_uppercase_hex() {
        let mut out = String::new();
        vec![0x68u8, 0x69].xer_encode(&mut out);
        assert_eq!(out, "6869");
    }

    #[test]
    fn vec_u8_xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        vec![0x68u8, 0x69].xer_encode(&mut out);
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>6869</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got: Vec<u8> = Vec::new();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("data").unwrap();
        assert_eq!(got, vec![0x68, 0x69]);
    }

    #[test]
    fn vec_u8_xer_empty_round_trips() {
        let mut r = XerReader::new("");
        let mut got: Vec<u8> = Vec::new();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, Vec::<u8>::new());
    }

    #[test]
    fn vec_u8_xer_odd_trailing_nibble_is_dropped_leniently() {
        // Matches parse_hex_bytes's lenient truncation, not an error.
        let mut r = XerReader::new("686");
        let mut got: Vec<u8> = Vec::new();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, vec![0x68]);
    }

    #[test]
    fn string_xer_escapes_and_round_trips() {
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "label");
        "a<b>&c".to_string().xer_encode(&mut out);
        write_close_tag(&mut out, "label");
        assert_eq!(out, "<label>a&lt;b&gt;&amp;c</label>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("label").unwrap();
        let mut got = String::new();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("label").unwrap();
        assert_eq!(got, "a<b>&c");
    }

    #[test]
    fn explicit_generic_wraps_and_round_trips_any_asn1value() {
        let mut buf = Vec::new();
        encode_explicit(&mut buf, crate::tag::Tag::context(7, true), &42i64);
        // [7] EXPLICIT (0xA7), wrapping the natural INTEGER encoding
        // (0x02 0x01 0x2A) unchanged — not a tag substitution.
        assert_eq!(buf, vec![0xA7, 0x03, 0x02, 0x01, 0x2A]);

        let mut r = Reader::new(&buf);
        let got: i64 = decode_explicit(&mut r, crate::tag::Tag::context(7, true)).unwrap();
        assert_eq!(got, 42);
    }
}
