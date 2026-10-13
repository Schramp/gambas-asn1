//! OCTET STRING encode/decode — X.680 §22, X.690 §8.7.
//!
//! The value octets *are* the encoding — no length/sign massaging like
//! INTEGER needs.
//!
//! `OctetString` is its own newtype (`pub struct OctetString(pub Vec<u8>)`),
//! not bare `Vec<u8>` — mirrors the C++
//! runtime's own `asn1::OctetString` (never raw `std::string`/
//! `std::vector<uint8_t>`) and this crate's existing `BitString`/
//! `ObjectIdentifier`/`RelativeOid`/the 11 restricted-character-string
//! newtypes (`strings.rs`). Each ASN.1 kind needs its own concrete type
//! for its own `TypeTag`/`AsMemberRef` impl (Rust allows only one trait
//! impl per concrete type) — every SEQUENCE OF/SET OF
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
use crate::ber::writer::write_primitive;

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

/// BASE64/UTF8 XER helpers (`xer::octet_string`), re-exported at this
/// path for callers that reach OCTET STRING helpers through this module.
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
    use crate::xer::reader::XerReader;

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

    // ---- Per-codec leg through `spec::primitive`'s dispatch -------------

    #[test]
    fn ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::spec::primitive::test_codec::ber_encode(&OctetString(vec![0x68, 0x69]), &mut out);
        assert_eq!(out, vec![0x04, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = OctetString::default();
        crate::spec::primitive::test_codec::ber_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_encodes_unspaced_uppercase_hex() {
        let mut out = String::new();
        crate::spec::primitive::test_codec::xer_encode(&OctetString(vec![0x68, 0x69]), &mut out, 0);
        assert_eq!(out, "6869");
    }

    #[test]
    fn xer_encode_base64_matches_base64_encode() {
        let mut out = String::new();
        out.push_str(&base64_encode(b"hi"));
        assert_eq!(out, "aGk=");
    }

    #[test]
    fn xer_decode_into_base64_round_trips() {
        use crate::xer::writer::{write_close_tag, write_open_tag};
        use crate::xer::reader::XerReader;

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        out.push_str(&base64_encode(b"hi"));
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>aGk=</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got = OctetString::default();
        got.0 = base64_decode(r.read_text_content().trim());
        r.consume_close_tag("data").unwrap();
        assert_eq!(got.0, b"hi");
    }

    #[test]
    fn xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};
        use crate::xer::reader::XerReader;

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        crate::spec::primitive::test_codec::xer_encode(&OctetString(vec![0x68, 0x69]), &mut out, 0);
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>6869</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got = OctetString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("data").unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_empty_round_trips() {
        let mut r = XerReader::new("");
        let mut got = OctetString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
        assert_eq!(got.0, Vec::<u8>::new());
    }

    #[test]
    fn xer_odd_trailing_nibble_is_dropped_leniently() {
        // Matches parse_hex_bytes's lenient truncation, not an error.
        let mut r = XerReader::new("686");
        let mut got = OctetString::default();
        crate::spec::primitive::test_codec::xer_decode_into(&mut got, &mut r).unwrap();
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
