//! ENUMERATED encode/decode — X.680 §20, X.690 §8.4.
//!
//! Same minimal two's-complement value-byte encoding as INTEGER
//! (`integer::encode_integer_bytes`/`decode_integer_bytes` — X.690 §8.4
//! defers to §8.3's INTEGER rules directly), only the tag differs
//! (universal 10, not 2). Every generated ENUMERATED type shares this
//! crate's `i64` wire representation regardless of its own Rust
//! `#[repr(i64)]` enum discriminant — `read_enumerated_tagged`/
//! `xer_decode_enum` are generic over `T: TryFrom<i64>` and do the
//! raw-i64-to-variant conversion themselves (via the `TryFrom<i64>` impl
//! `emit_enumerated_definition` generates for every ENUMERATED type), so
//! generated `Asn1Value::ber_decode_into`/`xer_decode_into` bodies stay a
//! single call — the conversion-error-mapping logic lives here once, not
//! copy-pasted at every call site (member decode, IMPLICIT-retag decode,
//! the type's own base impl).

use crate::integer::{decode_integer_bytes, encode_integer_bytes};
use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;
use crate::xer::XerReader;

pub const ENUMERATED_TAG: Tag = Tag::universal(universal::ENUMERATED, false);

pub fn write_enumerated_tagged(out: &mut Vec<u8>, tag: Tag, n: i64) {
    write_primitive(out, tag, &encode_integer_bytes(n));
}

pub fn read_enumerated_tagged<T: TryFrom<i64>>(r: &mut Reader, tag: Tag) -> Result<T, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected ENUMERATED tag, got {:?}", tlv.tag), r.pos()));
    }
    let raw = decode_integer_bytes(tlv.value)?;
    T::try_from(raw).map_err(|_| DecodeError::new(format!("invalid ENUMERATED value: {raw}"), r.pos()))
}

/// Content octets only (X.690 §8.4, same as INTEGER's) — for
/// `Asn1Value::ber_encode_content`/`ber_decode_content`.
pub fn encode_enumerated_content(out: &mut Vec<u8>, n: i64) {
    out.extend_from_slice(&encode_integer_bytes(n));
}

pub fn decode_enumerated_content<T: TryFrom<i64>>(content: &[u8]) -> Result<T, DecodeError> {
    let raw = decode_integer_bytes(content)?;
    T::try_from(raw).map_err(|_| DecodeError::new(format!("invalid ENUMERATED value: {raw}"), 0))
}

/// One value/name pair — mirrors `EnumSpec::entries` (`TypeDescriptor.hpp`)
/// exactly: codegen emits one static table per ENUMERATED type
/// (`{TYPE}_MAP`), this module supplies the one generic name<->value
/// lookup both `Asn1Value::xer_encode`/`xer_decode_into` wrappers call —
/// same table-driven split every other construct in this crate uses (the
/// table is data, the lookup is the one shared piece of logic, not
/// per-type generated code).
pub struct EnumEntry {
    pub value: i64,
    pub name: &'static str,
}

/// BASIC-XER form for ENUMERATED (X.693 §19 — same
/// EmptyElementBoolean-style nested self-closing tag `boolean`'s own
/// `Asn1Value` impl uses, `value.rs`) — mirrors `EnumeratedXerHandler`'s
/// member-embedded encoding (`runtime/src/XerCodec.cpp`): the tag name is
/// the ASN.1 enumeration identifier itself, not a Rust-cased variant name.
/// Falls back to the raw integer (matching the C++ handler's own
/// `else os << v;` branch) if `value` isn't in `entries` — defensive, not
/// reachable for a value that actually came from the enum's own valid
/// range.
pub fn xer_encode_enum(out: &mut String, entries: &[EnumEntry], value: i64) {
    match entries.iter().find(|e| e.value == value) {
        Some(e) => {
            out.push('<');
            out.push_str(e.name);
            out.push_str("/>");
        }
        None => out.push_str(&value.to_string()),
    }
}

pub fn xer_decode_enum<T: TryFrom<i64>>(r: &mut XerReader, entries: &[EnumEntry]) -> Result<T, DecodeError> {
    let ti = r.consume_tag();
    if !ti.self_closing {
        return Err(DecodeError::new("XER ENUMERATED: expected self-closing enum value tag".to_string(), 0));
    }
    let raw = entries.iter().find(|e| e.name == ti.name).map(|e| e.value)
        .ok_or_else(|| DecodeError::new(format!("XER ENUMERATED: unknown enum value: {}", ti.name), 0))?;
    T::try_from(raw).map_err(|_| DecodeError::new(format!("invalid ENUMERATED value: {}", ti.name), 0))
}

/// X.680 §20/§51 ENUMERATED validation (gambas-asn1#468) — mirrors
/// `EnumSpec::validate` (`runtime/include/asn1cpp/TypeDescriptor.hpp`)
/// exactly: not a range check like INTEGER/SIZE — `1` when `value` isn't
/// any known root or extension enumeration value, `0` otherwise. No
/// "nearest valid bound" delta concept applies (an unknown ENUMERATED
/// value has no natural distance metric), matching the C++ side's own
/// doc note. `EXTENSIBLE` gets no bypass here either (unlike INTEGER/
/// SIZE) — an extensible ENUMERATED still requires the decoded value to
/// be one of the *known* root/extension values; X.691 §22's own
/// extension-addition mechanism is how a *new* value becomes known, not
/// a blanket "anything goes" escape hatch.
///
/// In practice this can only ever return `0` through the normal decode
/// path: `read_enumerated_tagged`/`decode_enumerated_content` already
/// reject an unrecognized wire value via `T: TryFrom<i64>` before a Rust
/// enum instance can exist at all (`enumerated.rs`'s own module doc) — a
/// stronger, compile-time-enforced guarantee than C++'s runtime-only
/// check. Implemented anyway, reusing the same `{TYPE}_MAP` table BER/XER
/// already emit, for parity with the other constraint kinds and as a
/// defined behavior for the (currently unreachable) case a `T::default()`
/// or other non-decode construction path ever produces an out-of-table
/// discriminant.
pub fn validate_enum(v: i64, entries: &[EnumEntry]) -> i64 {
    if entries.iter().any(|e| e.value == v) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_universal_ten_not_integers_two() {
        assert_eq!(ENUMERATED_TAG.number, 10);
        assert_ne!(ENUMERATED_TAG, crate::integer::INTEGER_TAG);
    }

    #[test]
    fn full_tlv_round_trip() {
        let mut buf = Vec::new();
        write_enumerated_tagged(&mut buf, ENUMERATED_TAG, 2);
        assert_eq!(buf, vec![0x0A, 0x01, 0x02]); // universal primitive 10, len 1, value 2
        let mut r = Reader::new(&buf);
        assert_eq!(read_enumerated_tagged::<i64>(&mut r, ENUMERATED_TAG).unwrap(), 2);
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_0 = Tag::context(0, false);
        let mut buf = Vec::new();
        write_enumerated_tagged(&mut buf, context_0, 1);
        assert_eq!(buf, vec![0x80, 0x01, 0x01]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_enumerated_tagged::<i64>(&mut r, context_0).unwrap(), 1);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x02]; // INTEGER tag, not ENUMERATED
        let mut r = Reader::new(&data);
        assert!(read_enumerated_tagged::<i64>(&mut r, ENUMERATED_TAG).is_err());
    }

    const ENTRIES: [EnumEntry; 2] = [
        EnumEntry { value: 1, name: "resultUnknown" },
        EnumEntry { value: 2, name: "aaaFailed" },
    ];

    #[test]
    fn xer_encodes_value_name() {
        let mut out = String::new();
        xer_encode_enum(&mut out, &ENTRIES, 2);
        assert_eq!(out, "<aaaFailed/>");
    }

    #[test]
    fn xer_round_trips() {
        let mut out = String::new();
        xer_encode_enum(&mut out, &ENTRIES, 1);
        let mut r = XerReader::new(&out);
        assert_eq!(xer_decode_enum::<i64>(&mut r, &ENTRIES).unwrap(), 1);
    }

    #[test]
    fn xer_unknown_name_is_error() {
        let mut r = XerReader::new("<bogus/>");
        assert!(xer_decode_enum::<i64>(&mut r, &ENTRIES).is_err());
    }

    #[test]
    fn xer_non_self_closing_is_error() {
        let mut r = XerReader::new("<aaaFailed></aaaFailed>");
        assert!(xer_decode_enum::<i64>(&mut r, &ENTRIES).is_err());
    }

    #[test]
    fn validate_enum_known_value_is_zero() {
        assert_eq!(validate_enum(1, &ENTRIES), 0);
        assert_eq!(validate_enum(2, &ENTRIES), 0);
    }

    #[test]
    fn validate_enum_unknown_value_is_one() {
        assert_eq!(validate_enum(3, &ENTRIES), 1);
        assert_eq!(validate_enum(-1, &ENTRIES), 1);
    }
}
