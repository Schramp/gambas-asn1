//! Character-string type encode/decode — X.680 §41, X.690 §8.7 (same
//! primitive-octet-string shape OCTET STRING uses, just under each string
//! type's own universal tag).
//!
//! Mirrors `AsnStringBerHandler` (`runtime/src/BerCodec.cpp`): value octets
//! are the raw string bytes, no escaping at the BER layer (escaping is an
//! XER-only concern, see `xer.rs`).
//!
//! **`IA5String` is `String` itself** (`Asn1Value for String`, `value.rs`) —
//! kept as the one exception, because a
//! generated field's Rust type must stay a plain `String` for the earliest,
//! most common case (ergonomics: no `.0` unwrapping, matches every already-
//! generated/tested `IA5String` member). **The other 11 string kinds
//! are newtype wrappers** (`NumericString(pub String)`
//! etc., via the `char_string_type!` macro below) — a plain `String` can't
//! carry more than one `Asn1Value` impl (Rust allows only one trait impl per
//! concrete type), so `NumericString`'s member can't reuse `IA5String`'s
//! `String` impl even though the wire shape is identical; they'd fight over
//! which tag to check/write. This mirrors the C++ runtime's own solution to
//! the same problem — `AsnString<N>` (`asn1cpp/CLAUDE.md`'s "tag-indexed
//! dispatch tables carry type information" decision record): a distinct
//! type per string *kind*, sharing one non-virtual base for the common
//! bytes-in/bytes-out logic. `char_string_type!` is that shared logic here;
//! each generated newtype is the Rust analogue of one `AsnString<N>`
//! instantiation.
//!
//! **Known divergence from ground truth:**
//! `AsnStringBerHandler::decode` copies value octets into `std::string`
//! unconditionally — no charset validation at all, C++ accepts *any* byte
//! sequence as string content, for every kind. Every impl here (including
//! the newtypes) requires valid UTF-8 (`String::from_utf8`), because the
//! underlying storage is `String`, which can't hold arbitrary bytes. A
//! malformed/fuzzed string member (e.g. raw high bytes that aren't valid
//! UTF-8) that C++ decodes successfully will be *rejected* here. Left as-is
//! for this issue's scope — flagging so it isn't rediscovered as a surprise
//! during #286 (randgen cross-validation against asn1c), where such inputs
//! are exactly what a corruption-mode fuzz run would produce.
//!
//! **UtcTime/GeneralizedTime also live here**, via the
//! same `char_string_type!` macro, even though they're semantically time
//! values, not character strings — X.691 §23's own definition of
//! "character string types" explicitly includes them (same raw-bytes BER
//! shape, `runtime/include/asn1cpp/types/Time.hpp`'s `BerTraits<UtcTime>`/
//! `BerTraits<GeneralizedTime>` are byte-for-byte identical to
//! `AsnStringBerHandler`, and their XER handlers use the same escaped-text
//! form as every other string kind — `runtime/include/asn1cpp/codec/
//! XerCodec.hpp`'s `decode_time_string`/`encode_text_element`). No
//! separate `time.rs` module or macro duplication for what the standard
//! itself already classifies as the same kind of thing.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::writer::write_primitive;
use crate::xer::XerReader;

pub const IA5_STRING_TAG: Tag = Tag::universal(universal::IA5_STRING, false);

pub fn write_ia5_string(out: &mut Vec<u8>, value: &str) {
    write_primitive(out, IA5_STRING_TAG, value.as_bytes());
}

pub fn read_ia5_string(r: &mut Reader) -> Result<String, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != IA5_STRING_TAG {
        return Err(DecodeError::new(format!("expected IA5String tag, got {:?}", tlv.tag), r.pos()));
    }
    String::from_utf8(tlv.value.to_vec())
        .map_err(|_| DecodeError::new("IA5String: invalid UTF-8".to_string(), r.pos()))
}

/// Shared bytes-in/bytes-out logic for every character string kind — the
/// analogue of `AsnStringBerHandler`'s single runtime singleton,
/// parameterized by `tag` instead of dispatched on it. Used both for each
/// `char_string_type!`-generated newtype's own natural tag, and (`pub`)
/// directly by codegen for a member whose real resolved
/// tag differs from its natural one (IMPLICIT tagging, X.690 §8.14) —
/// same shape `boolean`/`integer`/`octet_string`'s `*_tagged` functions
/// give those kinds.
pub fn write_char_string(out: &mut Vec<u8>, tag: Tag, value: &str) {
    write_primitive(out, tag, value.as_bytes());
}

pub fn read_char_string(r: &mut Reader, tag: Tag, kind: &str) -> Result<String, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected {kind} tag, got {:?}", tlv.tag), r.pos()));
    }
    String::from_utf8(tlv.value.to_vec())
        .map_err(|_| DecodeError::new(format!("{kind}: invalid UTF-8"), r.pos()))
}

/// Define one restricted-character-string newtype: its tag constant, the
/// struct itself (`Debug`/`Clone`/`Default`/`PartialEq`/`Eq`, same derives
/// `Point`'s own fields get), its `Asn1Value` impl (BER via
/// `write_char_string`/`read_char_string`; XER: escaped text content, same
/// as `String`'s own impl — X.693 doesn't distinguish string kinds in
/// BASIC-XER form), and `Deref`/`DerefMut` to `String` — so a member of this
/// type still supports every `String` method call site already generated
/// for plain-`String` members (e.g. `.len()` in a SIZE-constraint check
/// function, `emit_string_definition`) without each of those call sites
/// needing to know or care that the value is wrapped.
macro_rules! char_string_type {
    ($name:ident, $tag_const:ident, $tag_num:expr, $asn1_name:expr) => {
        #[doc = concat!("`", $asn1_name, "` — X.680 §41. Newtype over `String`; see the module doc for why.")]
        pub const $tag_const: Tag = Tag::universal($tag_num, false);

        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $name(pub String);

        impl std::ops::Deref for $name {
            type Target = String;
            fn deref(&self) -> &String {
                &self.0
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut String {
                &mut self.0
            }
        }

        impl Asn1Value for $name {
            fn ber_encode(&self, out: &mut Vec<u8>) {
                write_char_string(out, $tag_const, &self.0);
            }

            fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
                self.0 = read_char_string(r, $tag_const, $asn1_name)?;
                Ok(())
            }

            fn xer_encode(&self, out: &mut String) {
                crate::xer::escape(&self.0, out);
            }

            fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
                let text = r.read_text_content();
                self.0 = crate::xer::unescape(text);
                Ok(())
            }
        }
    };
}

char_string_type!(Utf8String, UTF8_STRING_TAG, universal::UTF8_STRING, "UTF8String");
char_string_type!(NumericString, NUMERIC_STRING_TAG, universal::NUMERIC_STRING, "NumericString");
char_string_type!(PrintableString, PRINTABLE_STRING_TAG, universal::PRINTABLE_STRING, "PrintableString");
char_string_type!(T61String, T61_STRING_TAG, universal::T61_STRING, "T61String");
char_string_type!(VideotexString, VIDEOTEX_STRING_TAG, universal::VIDEOTEX_STRING, "VideotexString");
char_string_type!(VisibleString, VISIBLE_STRING_TAG, universal::VISIBLE_STRING, "VisibleString");
char_string_type!(GraphicString, GRAPHIC_STRING_TAG, universal::GRAPHIC_STRING, "GraphicString");
char_string_type!(GeneralString, GENERAL_STRING_TAG, universal::GENERAL_STRING, "GeneralString");
char_string_type!(UniversalString, UNIVERSAL_STRING_TAG, universal::UNIVERSAL_STRING, "UniversalString");
char_string_type!(BmpString, BMP_STRING_TAG, universal::BMP_STRING, "BMPString");
char_string_type!(ObjectDescriptor, OBJECT_DESCRIPTOR_TAG, universal::OBJECT_DESCRIPTOR, "ObjectDescriptor");
char_string_type!(UtcTime, UTC_TIME_TAG, universal::UTC_TIME, "UTCTime");
char_string_type!(GeneralizedTime, GENERALIZED_TIME_TAG, universal::GENERALIZED_TIME, "GeneralizedTime");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ascii() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hi");
        assert_eq!(buf, vec![0x16, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn empty_string_round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "");
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hello");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "hello");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x04, 0x02, 0x68, 0x69]; // OCTET STRING tag, not IA5String
        let mut r = Reader::new(&data);
        assert!(read_ia5_string(&mut r).is_err());
    }

    #[test]
    fn non_utf8_bytes_are_rejected_unlike_the_cpp_runtime() {
        // See the module doc's "known divergence" note: AsnStringBerHandler
        // (C++) copies these bytes into std::string unvalidated and would
        // decode this successfully. 0xFF is not a valid UTF-8 lead byte.
        let data = [0x16, 0x01, 0xFF];
        let mut r = Reader::new(&data);
        assert!(read_ia5_string(&mut r).is_err());
    }

    // ---- restricted-string newtypes -----------------------

    #[test]
    fn numeric_string_ber_round_trips_and_uses_its_own_tag() {
        let mut buf = Vec::new();
        NumericString("12345".to_string()).ber_encode(&mut buf);
        // NUMERIC_STRING tag (0x12), not IA5String's (0x16).
        assert_eq!(buf, vec![0x12, 0x05, b'1', b'2', b'3', b'4', b'5']);

        let mut r = Reader::new(&buf);
        let mut got = NumericString::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, NumericString("12345".to_string()));
    }

    #[test]
    fn numeric_string_rejects_ia5_string_tag() {
        // A member typed NumericString must not silently accept an
        // IA5String-tagged TLV, even though both store a String underneath.
        let data = [0x16, 0x02, b'h', b'i'];
        let mut r = Reader::new(&data);
        let mut got = NumericString::default();
        assert!(got.ber_decode_into(&mut r).is_err());
    }

    #[test]
    fn printable_string_xer_round_trips() {
        let mut out = String::new();
        PrintableString("a<b".to_string()).xer_encode(&mut out);
        assert_eq!(out, "a&lt;b");

        let mut r = XerReader::new(&out);
        let mut got = PrintableString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, PrintableString("a<b".to_string()));
    }

    // ---- UtcTime/GeneralizedTime --------------------------

    #[test]
    fn utc_time_ber_round_trips_and_uses_its_own_tag() {
        let mut buf = Vec::new();
        UtcTime("240115143000Z".to_string()).ber_encode(&mut buf);
        // UTCTime tag (0x17), not IA5String's (0x16) or GeneralizedTime's (0x18).
        assert_eq!(buf[0], 0x17);
        assert_eq!(buf.len(), 2 + "240115143000Z".len());

        let mut r = Reader::new(&buf);
        let mut got = UtcTime::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, UtcTime("240115143000Z".to_string()));
    }

    #[test]
    fn generalized_time_ber_round_trips_and_uses_its_own_tag() {
        let mut buf = Vec::new();
        GeneralizedTime("20240115143000Z".to_string()).ber_encode(&mut buf);
        assert_eq!(buf[0], 0x18);

        let mut r = Reader::new(&buf);
        let mut got = GeneralizedTime::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, GeneralizedTime("20240115143000Z".to_string()));
    }

    #[test]
    fn utc_time_rejects_generalized_time_tag() {
        // A member typed UtcTime must not silently accept a
        // GeneralizedTime-tagged TLV, even though both store a String underneath.
        let data = [0x18, 0x02, b'h', b'i'];
        let mut r = Reader::new(&data);
        let mut got = UtcTime::default();
        assert!(got.ber_decode_into(&mut r).is_err());
    }

    #[test]
    fn utc_time_xer_round_trips() {
        let mut out = String::new();
        UtcTime("240115143000Z".to_string()).xer_encode(&mut out);
        assert_eq!(out, "240115143000Z");

        let mut r = XerReader::new(&out);
        let mut got = UtcTime::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, UtcTime("240115143000Z".to_string()));
    }

    #[test]
    fn generalized_time_xer_round_trips() {
        let mut out = String::new();
        GeneralizedTime("20240115143000Z".to_string()).xer_encode(&mut out);
        assert_eq!(out, "20240115143000Z");

        let mut r = XerReader::new(&out);
        let mut got = GeneralizedTime::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, GeneralizedTime("20240115143000Z".to_string()));
    }
}
