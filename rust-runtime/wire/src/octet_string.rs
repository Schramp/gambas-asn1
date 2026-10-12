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
//!
//! **Backed by plain `Vec<u8>`, not a small-string-optimized inline
//! buffer (`SmallVec`/similar) — tried twice, measured, abandoned both
//! times.** C++'s `OctetString` gets SSO for free via `std::string`'s own
//! layout; mirroring that with `SmallVec<[u8; N]>` was tried at N=23
//! (matches `std::string`'s 32-byte footprint exactly) and N=8 (zero
//! struct-size cost — `size_of::<SmallVec<[u8;8]>>() ==
//! size_of::<Vec<u8>>()`). Both cut allocation *count* genuinely (N=8:
//! 89 → 48 allocs/record on the real ETSI-LI-PS-PDU schema's decode path,
//! counting-allocator-verified) but produced **zero measured improvement**
//! in real accumulate-phase throughput or LL-cache-miss count — the
//! allocation-count win didn't translate to less actual cache-miss cost,
//! because this schema's dominant byte volume lives in fields larger than
//! any realistic inline threshold (SSO never touches them). N=23
//! additionally regressed BER encode by ~8% (struct grew 24→32 bytes,
//! costing more to move during encode's traversal). Don't re-attempt this
//! without a schema-specific allocation/footprint profile showing a real
//! win first — it isn't a free lunch here the way it is for C++'s
//! `std::string`.

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::ber::writer::write_primitive;
use crate::xer::reader::XerReader;

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

    // OCTET STRING content octets *are* the value bytes — no encoding step.
    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = content.to_vec();
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::octet_string::encode(&self.0, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = crate::xer::octet_string::decode(r)?;
        Ok(())
    }

    fn xer_encode_base64(&self, out: &mut String) {
        out.push_str(&base64_encode(&self.0));
    }

    fn xer_decode_into_base64(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        self.0 = base64_decode(text.trim());
        Ok(())
    }

    /// Counterpart to `xer_encode_base64`/`xer_decode_into_base64` for the
    /// legacy `TypeName OCTET STRING ::= utf8` / X.693 §21 `UTF8
    /// TypeName` ENCODING-CONTROL instruction — see `MemberRef::Utf8`'s
    /// own doc for why this needs its own variant rather than a flag.
    fn xer_encode_utf8(&self, out: &mut String) {
        utf8_encode(&self.0, out);
    }

    fn xer_decode_into_utf8(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = utf8_decode(r)?;
        Ok(())
    }

    /// X.697 §8.9: quoted uppercase hex, no spaces (not base64 -- JER has
    /// no per-member encoding-control override the way XER's `::= base64`
    /// does; see `jer::octet_string`'s own module doc).
    fn jer_encode(&self, out: &mut String) {
        crate::jer::octet_string::encode(&self.0, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::octet_string::decode(r)?;
        Ok(())
    }

    fn per_encode(&self, w: &mut crate::per::writer::Writer, c: &crate::constraints::Constraints) {
        crate::per::octet_string::encode_octet_string(w, c, &self.0);
    }

    fn per_decode_into(&mut self, r: &mut crate::per::reader::Reader, c: &crate::constraints::Constraints) -> Result<(), crate::per::reader::DecodeError> {
        self.0 = crate::per::octet_string::decode_octet_string(r, c)?;
        Ok(())
    }

    fn validate(&self, c: &crate::constraints::Constraints) -> i64 {
        crate::constraints::validate_size(self.0.len(), c)
    }
}

/// BASE64/utf8 XER helpers now live in `xer::octet_string`; re-exported
/// at this original path so a generated builtin-alias type's own
/// `Asn1Value` impl (`RustBackend::emit_builtin_alias_definition`,
/// which names them by this path directly) keeps compiling unchanged.
pub use crate::xer::octet_string::{base64_decode, base64_encode, utf8_decode, utf8_encode};

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
    fn xer_encode_base64_matches_base64_encode() {
        let mut out = String::new();
        OctetString(b"hi".to_vec()).xer_encode_base64(&mut out);
        assert_eq!(out, "aGk=");
    }

    #[test]
    fn xer_decode_into_base64_round_trips() {
        use crate::xer::writer::{write_close_tag, write_open_tag};
        use crate::xer::reader::XerReader;

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        OctetString(b"hi".to_vec()).xer_encode_base64(&mut out);
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>aGk=</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got = OctetString::default();
        got.xer_decode_into_base64(&mut r).unwrap();
        r.consume_close_tag("data").unwrap();
        assert_eq!(got.0, b"hi");
    }

    #[test]
    fn xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};
        use crate::xer::reader::XerReader;

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

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_decode("aGk="), b"hi");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode(""), Vec::<u8>::new());
        assert_eq!(base64_encode(b"any carnal pleasure"), "YW55IGNhcm5hbCBwbGVhc3VyZQ==");
        assert_eq!(base64_decode("YW55IGNhcm5hbCBwbGVhc3VyZQ=="), b"any carnal pleasure");
    }
}

impl crate::type_tag::TypeTag for OctetString {
    const TAG: Option<Tag> = Some(OCTET_STRING_TAG);
}
