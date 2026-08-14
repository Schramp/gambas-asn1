//! OCTET STRING encode/decode — X.680 §22, X.690 §8.7.
//!
//! The value octets *are* the encoding — no length/sign massaging like
//! INTEGER needs.
//!
//! `OctetString` is its own newtype (`pub struct OctetString(pub Vec<u8>)`),
//! not a direct `Asn1Value` impl on bare `Vec<u8>` — mirrors the C++
//! runtime's own `asn1::OctetString` (never raw `std::string`/
//! `std::vector<uint8_t>`) and this crate's existing `BitString`/
//! `ObjectIdentifier`/`RelativeOid`/the 11 restricted-character-string
//! newtypes (`strings.rs`). A bare `Vec<u8>` impl would also permanently
//! block any generic `impl<V: Asn1Value> Asn1Value for Vec<V>` (Rust allows
//! only one trait impl per concrete type) — every SEQUENCE OF/SET OF
//! member needs its own `SeqOf<T>`/`SetOf<T>` wrapper type specifically
//! because of this (`rust-runtime/ber/src/sequence.rs`), and codegen has to
//! special-case "is this an unusable bare `Vec<T>`" at several call sites
//! (`RustBackend.cpp`'s `rust_mtype_is_unusable_vec`) as a direct
//! consequence.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::writer::write_primitive;
use crate::xer::XerReader;

pub const OCTET_STRING_TAG: Tag = Tag::universal(universal::OCTET_STRING, false);

/// An OCTET STRING value — X.680 §22. Plain byte payload, no framing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OctetString(pub Vec<u8>);

/// `Deref`/`DerefMut` to the underlying `Vec<u8>` — same ergonomic pattern
/// `RustBackend::emit_seq_of_declaration`'s generated wrapper structs
/// already use (`impl Deref for {SeqOfAlias} { type Target = Vec<T>; ... }`)
/// so `.len()`/slicing/iteration keep working transparently through the
/// newtype (e.g. a generated `*_size_ok` bounds-check function), without
/// every caller needing an explicit `.0`.
impl std::ops::Deref for OctetString {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::DerefMut for OctetString {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

/// Mirrors `OctetStringXerHandler`'s default (non-Base64) encoding: unspaced
/// uppercase hex pairs (`write_hex_bytes`, `runtime/src/HexEncoder.hpp`) —
/// distinct from BIT STRING/hex-string types' *spaced* hex
/// (`format_hex_bytes`), not implemented by this crate.
impl Asn1Value for OctetString {
    fn ber_natural_tag(&self) -> Tag {
        OCTET_STRING_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "OCTET_STRING"
    }

    // OCTET STRING content octets *are* the value bytes — no encoding step.
    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = content.to_vec();
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        for b in &self.0 {
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
        self.0 = bytes;
        Ok(())
    }
}

pub fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    write_octet_string_tagged(out, OCTET_STRING_TAG, value);
}

pub fn read_octet_string<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    read_octet_string_tagged(r, OCTET_STRING_TAG)
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc for the general rationale (X.690 §8.14). Same raw value octets,
/// different tag octets.
pub fn write_octet_string_tagged(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    write_primitive(out, tag, value);
}

pub fn read_octet_string_tagged<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<&'a [u8], DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(
            format!("expected OCTET STRING tag, got {:?}", tlv.tag),
            r.pos(),
        ));
    }
    Ok(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, &[]);
        assert_eq!(buf, vec![0x04, 0x00]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, b"hi");
        assert_eq!(buf, vec![0x04, 0x02, 0x68, 0x69]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string(&mut r).unwrap(), b"hi");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not OCTET STRING
        let mut r = Reader::new(&data);
        assert!(read_octet_string(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_2 = Tag::context(2, false);
        let mut buf = Vec::new();
        write_octet_string_tagged(&mut buf, context_2, b"hi");
        assert_eq!(buf, vec![0x82, 0x02, 0x68, 0x69]); // context primitive 2, not 0x04
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string_tagged(&mut r, context_2).unwrap(), b"hi");
    }

    // ---- Asn1Value trait leg (moved from value.rs's own test module —
    // was Vec<u8>-as-Asn1Value, now OctetString-as-Asn1Value) -------------

    #[test]
    fn ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        OctetString(vec![0x68, 0x69]).ber_encode(&mut out);
        assert_eq!(out, vec![0x04, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = OctetString::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_encodes_unspaced_uppercase_hex() {
        let mut out = String::new();
        OctetString(vec![0x68, 0x69]).xer_encode(&mut out, 0);
        assert_eq!(out, "6869");
    }

    #[test]
    fn xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag, XerReader};

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        OctetString(vec![0x68, 0x69]).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>6869</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("data").unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_empty_round_trips() {
        let mut r = XerReader::new("");
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, Vec::<u8>::new());
    }

    #[test]
    fn xer_odd_trailing_nibble_is_dropped_leniently() {
        // Matches parse_hex_bytes's lenient truncation, not an error.
        let mut r = XerReader::new("686");
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, vec![0x68]);
    }
}
