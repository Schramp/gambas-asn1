//! The closed set of ASN.1 builtin leaf types (X.680 §18-19/§41, no
//! recursion) — "codec uses type", not "type has a codec": a
//! `MemberRef`/`MemberRefMut` for one of these types stores *one*
//! accessor (`get`/`get_mut`, below) rather than 8 separate per-codec
//! closures. That accessor's own address is all any static table ever
//! takes — its body never names a specific codec's encode/decode
//! function, so building the table does not, by itself, force every
//! codec's machinery for that member's type to be compiled in. Each
//! codec module provides its own small, hand-written, non-generated
//! `match` over this enum (`ber_encode_primitive` etc., below) —
//! reused by every generated type alike, exactly mirroring the C++
//! side's `prim_dispatch_[32]` (one shared array, indexed by tag, read
//! by `BerCodec`/`JerCodec`/...) versus a per-type generated switch.
//! A composite member (SEQUENCE/SET/CHOICE/SEQUENCE OF/SET OF/
//! ENUMERATED — unbounded, per-schema) can't join this closed enum;
//! it instead reaches its own static table through the fully
//! reflective `Asn1Seq`/`Asn1Choice`/`Asn1SeqOf`/`EnumSlot` traits
//! (`spec::object`) — never a stored per-codec closure, so no inner
//! type's codec machinery is force-linked just by appearing in a
//! containing type's member table.
//!
//! Every function below calls each type's own free codec function
//! directly (`crate::boolean::encode_boolean_content`,
//! `crate::xer::real::encode`, ...). `PrimitiveRef`/`PrimitiveRefMut` is
//! a closed enum, so matching on it needs no per-type codec trait at all.
//!
//! An application that only calls `ber::object::encode_pdu`/`decode_pdu` never
//! calls `xer_encode_primitive`/`jer_encode_primitive`/
//! `per_encode_primitive` — and nothing else references them either,
//! since no table stores their address — so rustc's own reachability-
//! based dead code elimination removes them, and everything they
//! called (string escaping, JSON writing, PER bit-packing...).

use crate::any::Any;
use crate::bit_string::BitString;
use crate::boolean::Boolean;
use crate::integer::{ArbitraryInteger, BigInteger, Integer, UInteger};
use crate::null::Null;
use crate::octet_string::OctetString;
use crate::oid::ObjectIdentifier;
use crate::real::Real;
use crate::relative_oid::RelativeOid;
use crate::strings::{
    BmpString, GeneralString, GeneralizedTime, GraphicString, Ia5String, NumericString,
    ObjectDescriptor, PrintableString, T61String, UniversalString, UtcTime, VideotexString,
    Utf8String, VisibleString,
};

use crate::ber::reader::{DecodeError as BerDecodeError, Reader as BerReader};
use crate::ber::tag::Tag;
use crate::jer::reader::Reader as JerReader;
use crate::per::reader::{DecodeError as PerDecodeError, Reader as PerReader};
use crate::per::writer::Writer as PerWriter;
use crate::xer::reader::XerReader;
use crate::spec::choice::BerTagging;
use crate::encode_error::EncodeError;

/// Invokes `$m!` once per builtin leaf kind with `(Variant, Type)` pairs —
/// the single source of truth for `PrimitiveRef`/`PrimitiveRefMut` and
/// `define_as_member_ref!` below. Adding a 27th builtin means adding one
/// line here plus one arm in each hand-written match in this file (the
/// dispatch functions themselves are no longer macro-generated from this
/// table — see this module's own doc on why).
macro_rules! for_each_primitive {
    ($m:ident) => {
        $m! {
            Boolean => Boolean,
            Integer => Integer,
            UInteger => UInteger,
            BigInteger => BigInteger,
            ArbitraryInteger => ArbitraryInteger,
            Real => Real,
            Null => Null,
            OctetString => OctetString,
            BitString => BitString,
            ObjectIdentifier => ObjectIdentifier,
            RelativeOid => RelativeOid,
            Any => Any,
            Utf8String => Utf8String,
            NumericString => NumericString,
            PrintableString => PrintableString,
            T61String => T61String,
            Ia5String => Ia5String,
            VisibleString => VisibleString,
            GeneralString => GeneralString,
            GraphicString => GraphicString,
            UniversalString => UniversalString,
            BmpString => BmpString,
            VideotexString => VideotexString,
            ObjectDescriptor => ObjectDescriptor,
            UtcTime => UtcTime,
            GeneralizedTime => GeneralizedTime,
        }
    };
}

macro_rules! define_ref_enum {
    ($($variant:ident => $ty:ident,)+) => {
        /// A borrowed reference to one builtin leaf value, tagged by
        /// kind — codegen picks the variant for a given member/
        /// alternative at compile time (`RustBackend::emit_...`), so
        /// this enum only exists for the *codec* side's own generic
        /// `match`, never for runtime type discovery.
        #[derive(Clone, Copy)]
        pub enum PrimitiveRef<'a> {
            $($variant(&'a $ty),)+
        }

        /// Mutable counterpart, used by every codec's decode leg.
        pub enum PrimitiveRefMut<'a> {
            $($variant(&'a mut $ty),)+
        }
    };
}
for_each_primitive!(define_ref_enum);

// ---------------------------------------------------------------------
// BER (X.690)
// ---------------------------------------------------------------------

/// Shared BER encode composition: writes one TLV under `tag` (natural or
/// an X.690 §8.14 override) with `content` as the value octets (X.690
/// §8.1). Constraint validation is not done here: a primitive carries no
/// constraint of its own, so the SEQUENCE/SET walker
/// (`ber::object::encode_seq_content`) checks each member against its
/// table-driven `Asn1Seq::validate` row instead.
fn ber_write_tlv(out: &mut Vec<u8>, tag: Tag, content: impl FnOnce(&mut Vec<u8>)) {
    crate::ber::writer::write_tagged(out, tag, content);
}

/// Decode counterpart of [`ber_write_tlv`]: reads one TLV, checks its tag
/// against `tag` (X.690 §8.1.2), and hands the value octets to
/// `decode_content`, which writes the decoded value into the target.
fn ber_read_tlv(
    r: &mut BerReader,
    tag: Tag,
    decode_content: impl FnOnce(&[u8]) -> Result<(), BerDecodeError>,
) -> Result<(), BerDecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(BerDecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    decode_content(tlv.value)
}

/// This primitive's own natural BER tag (X.690 §8.1.2) — `ANY` has none
/// of its own (its wire form is a full TLV of whatever type was actually
/// present, replayed verbatim), so it panics here; the BER dispatch
/// special-cases `Any` before ever asking.
fn natural_tag_of(p: PrimitiveRef) -> Tag {
    match p {
        PrimitiveRef::Boolean(_) => crate::boolean::BOOLEAN_TAG,
        PrimitiveRef::Integer(_) | PrimitiveRef::UInteger(_) | PrimitiveRef::BigInteger(_) | PrimitiveRef::ArbitraryInteger(_) => crate::integer::INTEGER_TAG,
        PrimitiveRef::Real(_) => crate::real::REAL_TAG,
        PrimitiveRef::Null(_) => crate::null::NULL_TAG,
        PrimitiveRef::OctetString(_) => crate::octet_string::OCTET_STRING_TAG,
        PrimitiveRef::BitString(_) => crate::bit_string::BIT_STRING_TAG,
        PrimitiveRef::ObjectIdentifier(_) => crate::oid::OBJECT_IDENTIFIER_TAG,
        PrimitiveRef::RelativeOid(_) => crate::relative_oid::RELATIVE_OID_TAG,
        PrimitiveRef::Any(_) => unreachable!("ANY has no natural tag — its wire form is a full TLV of whatever type was actually present"),
        PrimitiveRef::Utf8String(_) => crate::strings::UTF8_STRING_TAG,
        PrimitiveRef::NumericString(_) => crate::strings::NUMERIC_STRING_TAG,
        PrimitiveRef::PrintableString(_) => crate::strings::PRINTABLE_STRING_TAG,
        PrimitiveRef::T61String(_) => crate::strings::T61_STRING_TAG,
        PrimitiveRef::Ia5String(_) => crate::strings::IA5_STRING_TAG,
        PrimitiveRef::VisibleString(_) => crate::strings::VISIBLE_STRING_TAG,
        PrimitiveRef::GeneralString(_) => crate::strings::GENERAL_STRING_TAG,
        PrimitiveRef::GraphicString(_) => crate::strings::GRAPHIC_STRING_TAG,
        PrimitiveRef::UniversalString(_) => crate::strings::UNIVERSAL_STRING_TAG,
        PrimitiveRef::BmpString(_) => crate::strings::BMP_STRING_TAG,
        PrimitiveRef::VideotexString(_) => crate::strings::VIDEOTEX_STRING_TAG,
        PrimitiveRef::ObjectDescriptor(_) => crate::strings::OBJECT_DESCRIPTOR_TAG,
        PrimitiveRef::UtcTime(_) => crate::strings::UTC_TIME_TAG,
        PrimitiveRef::GeneralizedTime(_) => crate::strings::GENERALIZED_TIME_TAG,
    }
}

/// `&PrimitiveRefMut` analogue of [`natural_tag_of`] — borrows rather
/// than consumes, so a caller can look up the tag and still move the
/// original `PrimitiveRefMut` into the decode call that needs it.
fn natural_tag_of_mut(p: &PrimitiveRefMut) -> Tag {
    match p {
        PrimitiveRefMut::Boolean(_) => crate::boolean::BOOLEAN_TAG,
        PrimitiveRefMut::Integer(_) | PrimitiveRefMut::UInteger(_) | PrimitiveRefMut::BigInteger(_) | PrimitiveRefMut::ArbitraryInteger(_) => crate::integer::INTEGER_TAG,
        PrimitiveRefMut::Real(_) => crate::real::REAL_TAG,
        PrimitiveRefMut::Null(_) => crate::null::NULL_TAG,
        PrimitiveRefMut::OctetString(_) => crate::octet_string::OCTET_STRING_TAG,
        PrimitiveRefMut::BitString(_) => crate::bit_string::BIT_STRING_TAG,
        PrimitiveRefMut::ObjectIdentifier(_) => crate::oid::OBJECT_IDENTIFIER_TAG,
        PrimitiveRefMut::RelativeOid(_) => crate::relative_oid::RELATIVE_OID_TAG,
        PrimitiveRefMut::Any(_) => unreachable!("ANY has no natural tag"),
        PrimitiveRefMut::Utf8String(_) => crate::strings::UTF8_STRING_TAG,
        PrimitiveRefMut::NumericString(_) => crate::strings::NUMERIC_STRING_TAG,
        PrimitiveRefMut::PrintableString(_) => crate::strings::PRINTABLE_STRING_TAG,
        PrimitiveRefMut::T61String(_) => crate::strings::T61_STRING_TAG,
        PrimitiveRefMut::Ia5String(_) => crate::strings::IA5_STRING_TAG,
        PrimitiveRefMut::VisibleString(_) => crate::strings::VISIBLE_STRING_TAG,
        PrimitiveRefMut::GeneralString(_) => crate::strings::GENERAL_STRING_TAG,
        PrimitiveRefMut::GraphicString(_) => crate::strings::GRAPHIC_STRING_TAG,
        PrimitiveRefMut::UniversalString(_) => crate::strings::UNIVERSAL_STRING_TAG,
        PrimitiveRefMut::BmpString(_) => crate::strings::BMP_STRING_TAG,
        PrimitiveRefMut::VideotexString(_) => crate::strings::VIDEOTEX_STRING_TAG,
        PrimitiveRefMut::ObjectDescriptor(_) => crate::strings::OBJECT_DESCRIPTOR_TAG,
        PrimitiveRefMut::UtcTime(_) => crate::strings::UTC_TIME_TAG,
        PrimitiveRefMut::GeneralizedTime(_) => crate::strings::GENERALIZED_TIME_TAG,
    }
}

fn ber_encode_tagged_(p: PrimitiveRef, tag: Tag, out: &mut Vec<u8>) {
    match p {
        PrimitiveRef::Boolean(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&crate::boolean::encode_boolean_content(x.0))),
        PrimitiveRef::Integer(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&crate::integer::encode_integer_bytes(x.0))),
        PrimitiveRef::UInteger(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&crate::integer::encode_integer_bytes_u64(x.0))),
        PrimitiveRef::BigInteger(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&crate::integer::encode_integer_bytes_i128(x.0))),
        PrimitiveRef::ArbitraryInteger(x) => ber_write_tlv(out, tag, |buf| crate::integer::encode_arbitrary_integer_content(&x.0, buf)),
        PrimitiveRef::Real(x) => ber_write_tlv(out, tag, |buf| crate::real::encode_real_content(buf, x.0)),
        PrimitiveRef::Null(_) => ber_write_tlv(out, tag, |_buf| {}),
        PrimitiveRef::OctetString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&x.0)),
        PrimitiveRef::BitString(x) => ber_write_tlv(out, tag, |buf| crate::bit_string::encode_bit_string_content(buf, x)),
        PrimitiveRef::ObjectIdentifier(x) => ber_write_tlv(out, tag, |buf| crate::oid::encode_object_identifier_content(buf, x)),
        PrimitiveRef::RelativeOid(x) => ber_write_tlv(out, tag, |buf| crate::relative_oid::encode_relative_oid_content(buf, x)),
        PrimitiveRef::Any(_) => unreachable!("ANY has no content-only BER form — ber_encode is overridden directly, never reaches ber_encode_tagged"),
        PrimitiveRef::Utf8String(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::NumericString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::PrintableString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::T61String(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::Ia5String(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::VisibleString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::GeneralString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::GraphicString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::UniversalString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&x.0)),
        PrimitiveRef::BmpString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(&x.0)),
        PrimitiveRef::VideotexString(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::ObjectDescriptor(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::UtcTime(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
        PrimitiveRef::GeneralizedTime(x) => ber_write_tlv(out, tag, |buf| buf.extend_from_slice(x.0.as_bytes())),
    }
}

fn ber_decode_tagged_(p: PrimitiveRefMut, tag: Tag, r: &mut BerReader) -> Result<(), BerDecodeError> {
    match p {
        PrimitiveRefMut::Boolean(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::boolean::decode_boolean_content(content)?; Ok(()) }),
        PrimitiveRefMut::Integer(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::integer::decode_integer_bytes(content)?; Ok(()) }),
        PrimitiveRefMut::UInteger(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::integer::decode_integer_bytes_u64(content)?; Ok(()) }),
        PrimitiveRefMut::BigInteger(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::integer::decode_integer_bytes_i128(content)?; Ok(()) }),
        PrimitiveRefMut::ArbitraryInteger(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::integer::decode_arbitrary_integer_content(content); Ok(()) }),
        PrimitiveRefMut::Real(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::real::decode_real_value(content, 0)?; Ok(()) }),
        PrimitiveRefMut::Null(_) => ber_read_tlv(r, tag, |content| { crate::null::decode_null_content(content)?; Ok(()) }),
        PrimitiveRefMut::OctetString(x) => ber_read_tlv(r, tag, |content| { x.0 = content.to_vec(); Ok(()) }),
        PrimitiveRefMut::BitString(x) => ber_read_tlv(r, tag, |content| { *x = crate::bit_string::decode_bit_string_content(content)?; Ok(()) }),
        PrimitiveRefMut::ObjectIdentifier(x) => ber_read_tlv(r, tag, |content| { *x = crate::oid::decode_object_identifier_content(content)?; Ok(()) }),
        PrimitiveRefMut::RelativeOid(x) => ber_read_tlv(r, tag, |content| { *x = crate::relative_oid::decode_relative_oid_content(content)?; Ok(()) }),
        PrimitiveRefMut::Any(_) => unreachable!("ANY has no content-only BER form — ber_decode_into is overridden directly, never reaches ber_decode_into_tagged"),
        PrimitiveRefMut::Utf8String(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "UTF8String")?; Ok(()) }),
        PrimitiveRefMut::NumericString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "NumericString")?; Ok(()) }),
        PrimitiveRefMut::PrintableString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "PrintableString")?; Ok(()) }),
        PrimitiveRefMut::T61String(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "T61String")?; Ok(()) }),
        PrimitiveRefMut::Ia5String(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "IA5String")?; Ok(()) }),
        PrimitiveRefMut::VisibleString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "VisibleString")?; Ok(()) }),
        PrimitiveRefMut::GeneralString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "GeneralString")?; Ok(()) }),
        PrimitiveRefMut::GraphicString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "GraphicString")?; Ok(()) }),
        PrimitiveRefMut::UniversalString(x) => ber_read_tlv(r, tag, |content| { x.0 = content.to_vec(); Ok(()) }),
        PrimitiveRefMut::BmpString(x) => ber_read_tlv(r, tag, |content| { x.0 = content.to_vec(); Ok(()) }),
        PrimitiveRefMut::VideotexString(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "VideotexString")?; Ok(()) }),
        PrimitiveRefMut::ObjectDescriptor(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "ObjectDescriptor")?; Ok(()) }),
        PrimitiveRefMut::UtcTime(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "UTCTime")?; Ok(()) }),
        PrimitiveRefMut::GeneralizedTime(x) => ber_read_tlv(r, tag, |content| { x.0 = crate::strings::decode_string_content(content, "GeneralizedTime")?; Ok(()) }),
    }
}

fn ber_encode_plain(p: PrimitiveRef, out: &mut Vec<u8>) {
    let tag = natural_tag_of(p);
    ber_encode_tagged_(p, tag, out)
}

fn ber_decode_plain(p: PrimitiveRefMut, r: &mut BerReader) -> Result<(), BerDecodeError> {
    let tag = natural_tag_of_mut(&p);
    ber_decode_tagged_(p, tag, r)
}

/// EXPLICIT tagging (X.690 §8.14.3): wraps the value's own natural-tag
/// encoding in an outer constructed TLV. `ANY` is the one exception — its
/// "natural" encoding is already a full captured TLV with no tag check of
/// its own, so it's replayed directly inside the wrapper instead of
/// going through [`ber_encode_plain`] (which would hit `natural_tag_of`'s
/// `unreachable!()`).
fn ber_encode_explicit_(p: PrimitiveRef, tag: Tag, out: &mut Vec<u8>) {
    if let PrimitiveRef::Any(x) = p {
        crate::ber::writer::write_explicit(out, tag, |inner| crate::any::encode_any(&x.0, inner));
        return;
    }
    crate::ber::writer::write_explicit(out, tag, |inner| ber_encode_plain(p, inner));
}

/// Decode counterpart of [`ber_encode_explicit_`].
fn ber_decode_explicit_(p: PrimitiveRefMut, tag: Tag, r: &mut BerReader) -> Result<(), BerDecodeError> {
    match p {
        PrimitiveRefMut::Any(x) => crate::ber::reader::read_explicit(r, tag, |inner| {
            x.0 = crate::any::decode_any(inner.remaining());
            Ok(())
        }),
        other => crate::ber::reader::read_explicit(r, tag, |inner| ber_decode_plain(other, inner)),
    }
}

/// BER encode for a primitive member/alternative, honoring its own
/// `BerTagging` (X.690 §8.14) — the one piece of per-row framing a
/// primitive still needs, since `BerTagging::{Implicit,Explicit}` is a
/// codegen-time fact (the `[n]` on *this* member), not a property of
/// the enum variant.
/// @return `Err` for a row codegen marked `BerTagging::Unsupported`.
pub fn ber_encode_primitive(p: PrimitiveRef, framing: BerTagging, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match framing {
        BerTagging::Implicit(tag) => ber_encode_tagged_(p, tag, out),
        BerTagging::Explicit(tag) => ber_encode_explicit_(p, tag, out),
        BerTagging::Delegate => ber_encode_plain(p, out),
        BerTagging::Unsupported(reason) => return Err(EncodeError::new(format!("primitive not supported: {reason}"))),
    }
    Ok(())
}

/// Decode counterpart of [`ber_encode_primitive`].
/// @return `Err` on malformed BER, a tag mismatch, or a row codegen
///         marked `BerTagging::Unsupported`.
pub fn ber_decode_primitive(p: PrimitiveRefMut, framing: BerTagging, r: &mut BerReader) -> Result<(), BerDecodeError> {
    match framing {
        BerTagging::Implicit(tag) => ber_decode_tagged_(p, tag, r),
        BerTagging::Explicit(tag) => ber_decode_explicit_(p, tag, r),
        BerTagging::Delegate => ber_decode_plain(p, r),
        BerTagging::Unsupported(reason) => Err(BerDecodeError::new(format!("primitive not supported: {reason}"), r.pos())),
    }
}

// ---------------------------------------------------------------------
// XER (X.693 BASIC-XER)
// ---------------------------------------------------------------------

/// XER encode — no BER tag concept, so no framing parameter (X.693
/// element names are fixed per type, same for every tagging the BER side
/// might apply to this same member). `ArbitraryInteger`/`Any` have no
/// defined XER form (nothing generates one today), so they panic.
pub fn xer_encode_primitive(p: PrimitiveRef, out: &mut String, depth: usize) -> Result<(), EncodeError> {
    match p {
        PrimitiveRef::Boolean(x) => crate::xer::boolean::encode(x.0, out),
        PrimitiveRef::Integer(x) => crate::xer::integer::encode(x.0, out),
        PrimitiveRef::UInteger(x) => crate::xer::integer::encode(x.0, out),
        PrimitiveRef::BigInteger(x) => crate::xer::integer::encode(x.0, out),
        PrimitiveRef::ArbitraryInteger(_) => unimplemented!("XER leg not yet wired for this type"),
        PrimitiveRef::Real(x) => crate::xer::real::encode(x.0, out),
        PrimitiveRef::Null(_) => {}
        PrimitiveRef::OctetString(x) => crate::xer::octet_string::encode(&x.0, out),
        PrimitiveRef::BitString(x) => crate::xer::bit_string::encode(x, out, depth),
        PrimitiveRef::ObjectIdentifier(x) => crate::xer::oid::encode(x, out),
        PrimitiveRef::RelativeOid(x) => crate::xer::relative_oid::encode(x, out),
        PrimitiveRef::Any(_) => unimplemented!("XER leg not yet wired for this type"),
        PrimitiveRef::Utf8String(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::NumericString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::PrintableString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::T61String(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::Ia5String(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::VisibleString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::GeneralString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::GraphicString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::UniversalString(x) => crate::strings::encode_wide_string_xer(&x.0, 4, out),
        PrimitiveRef::BmpString(x) => crate::strings::encode_wide_string_xer(&x.0, 2, out),
        PrimitiveRef::VideotexString(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::ObjectDescriptor(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::UtcTime(x) => crate::xer::writer::escape(&x.0, out),
        PrimitiveRef::GeneralizedTime(x) => crate::xer::writer::escape(&x.0, out),
    }
    Ok(())
}

pub fn xer_decode_primitive(p: PrimitiveRefMut, r: &mut XerReader) -> Result<(), BerDecodeError> {
    match p {
        PrimitiveRefMut::Boolean(x) => { x.0 = crate::xer::boolean::decode(r)?; Ok(()) }
        PrimitiveRefMut::Integer(x) => { x.0 = crate::xer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::UInteger(x) => { x.0 = crate::xer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::BigInteger(x) => { x.0 = crate::xer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::ArbitraryInteger(_) => Err(BerDecodeError::new("XER leg not yet wired for this type".to_string(), 0)),
        PrimitiveRefMut::Real(x) => { x.0 = crate::xer::real::decode(r)?; Ok(()) }
        PrimitiveRefMut::Null(_) => Ok(()),
        PrimitiveRefMut::OctetString(x) => { x.0 = crate::xer::octet_string::decode(r)?; Ok(()) }
        PrimitiveRefMut::BitString(x) => crate::xer::bit_string::decode_into(x, r),
        PrimitiveRefMut::ObjectIdentifier(x) => crate::xer::oid::decode_into(x, r),
        PrimitiveRefMut::RelativeOid(x) => crate::xer::relative_oid::decode_into(x, r),
        PrimitiveRefMut::Any(_) => Err(BerDecodeError::new("XER leg not yet wired for this type".to_string(), 0)),
        PrimitiveRefMut::Utf8String(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::NumericString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::PrintableString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::T61String(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::Ia5String(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::VisibleString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::GeneralString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::GraphicString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::UniversalString(x) => { let text = r.read_text_content(); x.0 = crate::strings::decode_wide_string_xer(&crate::xer::reader::unescape(text), 4); Ok(()) }
        PrimitiveRefMut::BmpString(x) => { let text = r.read_text_content(); x.0 = crate::strings::decode_wide_string_xer(&crate::xer::reader::unescape(text), 2); Ok(()) }
        PrimitiveRefMut::VideotexString(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::ObjectDescriptor(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::UtcTime(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
        PrimitiveRefMut::GeneralizedTime(x) => { let text = r.read_text_content(); x.0 = crate::xer::reader::unescape(text); Ok(()) }
    }
}

/// This primitive's own natural XER element name (X.693 §8.3.1) — used
/// when wrapping a SEQUENCE OF/SET OF element, which has no field name of
/// its own to wrap with. `ANY` falls back to `"Value"`.
pub fn xer_element_name_of(p: PrimitiveRef) -> &'static str {
    match p {
        PrimitiveRef::Boolean(_) => "BOOLEAN",
        PrimitiveRef::Integer(_) | PrimitiveRef::UInteger(_) | PrimitiveRef::BigInteger(_) | PrimitiveRef::ArbitraryInteger(_) => "INTEGER",
        PrimitiveRef::Real(_) => "REAL",
        PrimitiveRef::Null(_) => "NULL",
        PrimitiveRef::OctetString(_) => "OCTET_STRING",
        PrimitiveRef::BitString(_) => "BIT_STRING",
        PrimitiveRef::ObjectIdentifier(_) => "OBJECT_IDENTIFIER",
        PrimitiveRef::RelativeOid(_) => "RELATIVE_OID",
        PrimitiveRef::Any(_) => "Value",
        PrimitiveRef::Utf8String(_) => "UTF8String",
        PrimitiveRef::NumericString(_) => "NumericString",
        PrimitiveRef::PrintableString(_) => "PrintableString",
        PrimitiveRef::T61String(_) => "T61String",
        PrimitiveRef::Ia5String(_) => "IA5String",
        PrimitiveRef::VisibleString(_) => "VisibleString",
        PrimitiveRef::GeneralString(_) => "GeneralString",
        PrimitiveRef::GraphicString(_) => "GraphicString",
        PrimitiveRef::UniversalString(_) => "UniversalString",
        PrimitiveRef::BmpString(_) => "BMPString",
        PrimitiveRef::VideotexString(_) => "VideotexString",
        PrimitiveRef::ObjectDescriptor(_) => "ObjectDescriptor",
        PrimitiveRef::UtcTime(_) => "UTCTime",
        PrimitiveRef::GeneralizedTime(_) => "GeneralizedTime",
    }
}

// ---------------------------------------------------------------------
// JER (X.697)
// ---------------------------------------------------------------------

pub fn jer_encode_primitive(p: PrimitiveRef, out: &mut String) -> Result<(), EncodeError> {
    match p {
        PrimitiveRef::Boolean(x) => out.push_str(if x.0 { "true" } else { "false" }),
        PrimitiveRef::Integer(x) => crate::jer::integer::encode(x.0, out),
        PrimitiveRef::UInteger(x) => crate::jer::integer::encode(x.0, out),
        PrimitiveRef::BigInteger(x) => crate::jer::integer::encode(x.0, out),
        PrimitiveRef::ArbitraryInteger(_) => unimplemented!("JER leg not yet wired for this type"),
        PrimitiveRef::Real(x) => crate::jer::real::encode(x.0, out),
        PrimitiveRef::Null(_) => crate::jer::null::encode(out),
        PrimitiveRef::OctetString(x) => crate::jer::octet_string::encode(&x.0, out),
        PrimitiveRef::BitString(x) => crate::jer::bit_string::encode(x, out),
        PrimitiveRef::ObjectIdentifier(x) => crate::jer::oid::encode(x, out),
        PrimitiveRef::RelativeOid(x) => crate::jer::relative_oid::encode(x, out),
        PrimitiveRef::Any(x) => crate::jer::octet_string::encode(&x.0, out),
        PrimitiveRef::Utf8String(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::NumericString(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::PrintableString(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::T61String(x) => crate::jer::strings::encode_hex(x.0.as_bytes(), out),
        PrimitiveRef::Ia5String(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::VisibleString(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::GeneralString(x) => crate::jer::strings::encode_hex(x.0.as_bytes(), out),
        PrimitiveRef::GraphicString(x) => crate::jer::strings::encode_hex(x.0.as_bytes(), out),
        PrimitiveRef::UniversalString(x) => crate::jer::strings::encode_wide(&x.0, 4, out),
        PrimitiveRef::BmpString(x) => crate::jer::strings::encode_wide(&x.0, 2, out),
        PrimitiveRef::VideotexString(x) => crate::jer::strings::encode_hex(x.0.as_bytes(), out),
        PrimitiveRef::ObjectDescriptor(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::UtcTime(x) => crate::jer::strings::encode_plain(&x.0, out),
        PrimitiveRef::GeneralizedTime(x) => crate::jer::strings::encode_plain(&x.0, out),
    }
    Ok(())
}

pub fn jer_decode_primitive(p: PrimitiveRefMut, r: &mut JerReader) -> Result<(), BerDecodeError> {
    match p {
        PrimitiveRefMut::Boolean(x) => {
            let tok = r.read_json_token()?;
            match tok.as_str() {
                "true" => { x.0 = true; Ok(()) }
                "false" => { x.0 = false; Ok(()) }
                _ => Err(BerDecodeError::new(format!("JER: BOOLEAN expected true/false, got: {tok}"), r.pos())),
            }
        }
        PrimitiveRefMut::Integer(x) => { x.0 = crate::jer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::UInteger(x) => { x.0 = crate::jer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::BigInteger(x) => { x.0 = crate::jer::integer::decode(r)?; Ok(()) }
        PrimitiveRefMut::ArbitraryInteger(_) => Err(BerDecodeError::new("JER leg not yet wired for this type".to_string(), 0)),
        PrimitiveRefMut::Real(x) => { x.0 = crate::jer::real::decode(r)?; Ok(()) }
        PrimitiveRefMut::Null(_) => crate::jer::null::decode(r),
        PrimitiveRefMut::OctetString(x) => { x.0 = crate::jer::octet_string::decode(r)?; Ok(()) }
        PrimitiveRefMut::BitString(x) => { *x = crate::jer::bit_string::decode(r)?; Ok(()) }
        PrimitiveRefMut::ObjectIdentifier(x) => crate::jer::oid::decode_into(x, r),
        PrimitiveRefMut::RelativeOid(x) => crate::jer::relative_oid::decode_into(x, r),
        PrimitiveRefMut::Any(x) => { x.0 = crate::jer::octet_string::decode(r)?; Ok(()) }
        PrimitiveRefMut::Utf8String(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::NumericString(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::PrintableString(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::T61String(x) => {
            let bytes = crate::jer::strings::decode_hex(r)?;
            x.0 = String::from_utf8(bytes).map_err(|_| BerDecodeError::new("JER: hex string content is not valid UTF-8".to_string(), r.pos()))?;
            Ok(())
        }
        PrimitiveRefMut::Ia5String(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::VisibleString(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::GeneralString(x) => {
            let bytes = crate::jer::strings::decode_hex(r)?;
            x.0 = String::from_utf8(bytes).map_err(|_| BerDecodeError::new("JER: hex string content is not valid UTF-8".to_string(), r.pos()))?;
            Ok(())
        }
        PrimitiveRefMut::GraphicString(x) => {
            let bytes = crate::jer::strings::decode_hex(r)?;
            x.0 = String::from_utf8(bytes).map_err(|_| BerDecodeError::new("JER: hex string content is not valid UTF-8".to_string(), r.pos()))?;
            Ok(())
        }
        PrimitiveRefMut::UniversalString(x) => { x.0 = crate::jer::strings::decode_wide(r, 4)?; Ok(()) }
        PrimitiveRefMut::BmpString(x) => { x.0 = crate::jer::strings::decode_wide(r, 2)?; Ok(()) }
        PrimitiveRefMut::VideotexString(x) => {
            let bytes = crate::jer::strings::decode_hex(r)?;
            x.0 = String::from_utf8(bytes).map_err(|_| BerDecodeError::new("JER: hex string content is not valid UTF-8".to_string(), r.pos()))?;
            Ok(())
        }
        PrimitiveRefMut::ObjectDescriptor(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::UtcTime(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
        PrimitiveRefMut::GeneralizedTime(x) => { x.0 = crate::jer::strings::decode_plain(r)?; Ok(()) }
    }
}

// ---------------------------------------------------------------------
// PER (X.691, unaligned)
// ---------------------------------------------------------------------

/// @brief PER encode for a primitive member/alternative/element.
/// @return `Err` on a SIZE or alphabet violation of a character string
///         (X.691 §30), which PER cannot represent.
pub fn per_encode_primitive(p: PrimitiveRef, w: &mut PerWriter, c: &crate::constraints::Constraints) -> Result<(), EncodeError> {
    use crate::ber::tag::universal as u;
    let s = |w: &mut PerWriter, tag, b: &[u8]| crate::per::strings::encode_string(w, c, tag, b);
    match p {
        PrimitiveRef::Boolean(x) => w.put_bits(x.0 as u64, 1),
        PrimitiveRef::Integer(x) => crate::per::integer::encode_int(w, c, x.0),
        PrimitiveRef::UInteger(x) => crate::per::uinteger::encode_uint(w, c, x.0),
        PrimitiveRef::BigInteger(_) => unimplemented!("PER encode not implemented for this type"),
        PrimitiveRef::ArbitraryInteger(_) => unimplemented!("PER encode not implemented for this type"),
        PrimitiveRef::Real(x) => crate::per::real::encode_real(w, x.0),
        PrimitiveRef::Null(_) => crate::per::null::encode(w),
        PrimitiveRef::OctetString(x) => crate::per::octet_string::encode_octet_string(w, c, &x.0),
        PrimitiveRef::BitString(x) => crate::per::bit_string::encode_bit_string(w, c, &x.bytes, x.bit_count()),
        PrimitiveRef::ObjectIdentifier(x) => crate::per::oid::encode(x, w),
        PrimitiveRef::RelativeOid(x) => crate::per::relative_oid::encode(x, w),
        PrimitiveRef::Any(x) => crate::per::any::encode(&x.0, w),
        PrimitiveRef::Utf8String(x) => return s(w, u::UTF8_STRING, x.0.as_bytes()),
        PrimitiveRef::NumericString(x) => return s(w, u::NUMERIC_STRING, x.0.as_bytes()),
        PrimitiveRef::PrintableString(x) => return s(w, u::PRINTABLE_STRING, x.0.as_bytes()),
        PrimitiveRef::T61String(x) => return s(w, u::T61_STRING, x.0.as_bytes()),
        PrimitiveRef::Ia5String(x) => return s(w, u::IA5_STRING, x.0.as_bytes()),
        PrimitiveRef::VisibleString(x) => return s(w, u::VISIBLE_STRING, x.0.as_bytes()),
        PrimitiveRef::GeneralString(x) => return s(w, u::GENERAL_STRING, x.0.as_bytes()),
        PrimitiveRef::GraphicString(x) => return s(w, u::GRAPHIC_STRING, x.0.as_bytes()),
        PrimitiveRef::UniversalString(x) => return s(w, u::UNIVERSAL_STRING, &x.0),
        PrimitiveRef::BmpString(x) => return s(w, u::BMP_STRING, &x.0),
        PrimitiveRef::VideotexString(x) => return s(w, u::VIDEOTEX_STRING, x.0.as_bytes()),
        PrimitiveRef::ObjectDescriptor(x) => return s(w, u::OBJECT_DESCRIPTOR, x.0.as_bytes()),
        PrimitiveRef::UtcTime(x) => return s(w, u::UTC_TIME, x.0.as_bytes()),
        PrimitiveRef::GeneralizedTime(x) => return s(w, u::GENERALIZED_TIME, x.0.as_bytes()),
    }
    Ok(())
}

pub fn per_decode_primitive(p: PrimitiveRefMut, r: &mut PerReader, c: &crate::constraints::Constraints) -> Result<(), PerDecodeError> {
    match p {
        PrimitiveRefMut::Boolean(x) => { x.0 = r.get_bits(1)? != 0; Ok(()) }
        PrimitiveRefMut::Integer(x) => { x.0 = crate::per::integer::decode_int(r, c)?; Ok(()) }
        PrimitiveRefMut::UInteger(x) => { x.0 = crate::per::uinteger::decode_uint(r, c)?; Ok(()) }
        PrimitiveRefMut::BigInteger(_) => Err(PerDecodeError::new("PER decode not implemented for this type", 0)),
        PrimitiveRefMut::ArbitraryInteger(_) => Err(PerDecodeError::new("PER decode not implemented for this type", 0)),
        PrimitiveRefMut::Real(x) => { x.0 = crate::per::real::decode_real(r)?; Ok(()) }
        PrimitiveRefMut::Null(_) => crate::per::null::decode(r),
        PrimitiveRefMut::OctetString(x) => { x.0 = crate::per::octet_string::decode_octet_string(r, c)?; Ok(()) }
        PrimitiveRefMut::BitString(x) => {
            let (bytes, unused_bits) = crate::per::bit_string::decode_bit_string(r, c)?;
            *x = crate::bit_string::BitString { bytes, unused_bits };
            Ok(())
        }
        PrimitiveRefMut::ObjectIdentifier(x) => crate::per::oid::decode_into(x, r),
        PrimitiveRefMut::RelativeOid(x) => crate::per::relative_oid::decode_into(x, r),
        PrimitiveRefMut::Any(x) => { x.0 = crate::per::any::decode(r)?; Ok(()) }
        PrimitiveRefMut::Utf8String(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::UTF8_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::NumericString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::NUMERIC_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::PrintableString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::PRINTABLE_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::T61String(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::T61_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::Ia5String(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::IA5_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::VisibleString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::VISIBLE_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::GeneralString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::GENERAL_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::GraphicString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::GRAPHIC_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::UniversalString(x) => { x.0 = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::UNIVERSAL_STRING)?; Ok(()) }
        PrimitiveRefMut::BmpString(x) => { x.0 = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::BMP_STRING)?; Ok(()) }
        PrimitiveRefMut::VideotexString(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::VIDEOTEX_STRING)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::ObjectDescriptor(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::OBJECT_DESCRIPTOR)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::UtcTime(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::UTC_TIME)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
        PrimitiveRefMut::GeneralizedTime(x) => { let b = crate::per::strings::decode_string(r, c, crate::ber::tag::universal::GENERALIZED_TIME)?; x.0 = String::from_utf8(b).unwrap_or_default(); Ok(()) }
    }
}

macro_rules! define_as_member_ref {
    ($($variant:ident => $ty:ident,)+) => {
        $(
            impl crate::spec::object::AsMemberRef for $ty {
                fn as_member_ref(&self) -> crate::spec::object::MemberRef<'_> {
                    crate::spec::object::MemberRef::Primitive(PrimitiveRef::$variant(self))
                }
                fn as_member_ref_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
                    crate::spec::object::MemberRefMut::Primitive(PrimitiveRefMut::$variant(self))
                }
                // A bare primitive has no alias identity above it, so
                // this is just its own generic builtin name.
                fn own_element_xer_name(&self) -> &'static str {
                    xer_element_name_of(PrimitiveRef::$variant(self))
                }
            }
        )+
    };
}
for_each_primitive!(define_as_member_ref);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::Integer;
    use crate::bit_string::BitString;
    use crate::any::Any;

    // Regression coverage for IMPLICIT/EXPLICIT BER framing (X.690
    // §8.14) through ber_encode_primitive/ber_decode_primitive, the
    // production entry point for it.

    #[test]
    fn implicit_matching_natural_tag_is_identical_to_plain_encode() {
        let mut a = Vec::new();
        let v = Integer(42);
        ber_encode_primitive(PrimitiveRef::Integer(&v), BerTagging::Delegate, &mut a).unwrap();
        let mut b = Vec::new();
        ber_encode_primitive(PrimitiveRef::Integer(&v), BerTagging::Implicit(crate::integer::INTEGER_TAG), &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn implicit_substitutes_the_tag_for_a_scalar() {
        let context_0 = Tag::context(0, false);
        let mut out = Vec::new();
        ber_encode_primitive(PrimitiveRef::Integer(&Integer(42)), BerTagging::Implicit(context_0), &mut out).unwrap();
        assert_eq!(out, vec![0x80, 0x01, 0x2A]); // context primitive 0, not universal INTEGER (0x02)

        let mut r = BerReader::new(&out);
        let mut got = Integer(0);
        ber_decode_primitive(PrimitiveRefMut::Integer(&mut got), BerTagging::Implicit(context_0), &mut r).unwrap();
        assert_eq!(got, 42);
    }

    #[test]
    fn implicit_substitutes_the_tag_for_a_constructed_value() {
        // BitString isn't constructed, but exercise a real non-trivial
        // multi-byte value to make sure content bytes survive the
        // splice-and-resplice untouched.
        let v = BitString { bytes: vec![0b1010_1000, 0xFF], unused_bits: 2 };
        let context_3 = Tag::context(3, false);
        let mut out = Vec::new();
        ber_encode_primitive(PrimitiveRef::BitString(&v), BerTagging::Implicit(context_3), &mut out).unwrap();
        assert_eq!(out[0], 0x83); // context primitive 3

        let mut r = BerReader::new(&out);
        let mut got = BitString::default();
        ber_decode_primitive(PrimitiveRefMut::BitString(&mut got), BerTagging::Implicit(context_3), &mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn implicit_decode_rejects_wrong_tag() {
        let context_0 = Tag::context(0, false);
        let context_1 = Tag::context(1, false);
        let mut out = Vec::new();
        ber_encode_primitive(PrimitiveRef::Integer(&Integer(42)), BerTagging::Implicit(context_0), &mut out).unwrap();

        let mut r = BerReader::new(&out);
        let mut got = Integer(0);
        assert!(ber_decode_primitive(PrimitiveRefMut::Integer(&mut got), BerTagging::Implicit(context_1), &mut r).is_err());
    }

    #[test]
    fn explicit_any_captures_the_wrapped_bytes_verbatim() {
        // The wrapped "value" here is itself a full INTEGER TLV — ANY's
        // whole point is to capture that unparsed, tag and all.
        let inner_tlv = [0x02u8, 0x01, 0x2A]; // INTEGER 42
        let context_1 = Tag::context(1, true);
        let mut buf = Vec::new();
        ber_encode_primitive(PrimitiveRef::Any(&Any(inner_tlv.to_vec())), BerTagging::Explicit(context_1), &mut buf).unwrap();
        assert_eq!(buf, vec![0xA1, 0x03, 0x02, 0x01, 0x2A]);

        let mut r = BerReader::new(&buf);
        let mut got = Any::default();
        ber_decode_primitive(PrimitiveRefMut::Any(&mut got), BerTagging::Explicit(context_1), &mut r).unwrap();
        assert_eq!(*got, inner_tlv);
    }

    #[test]
    fn unsupported_framing_is_an_error_not_a_panic() {
        let framing = BerTagging::Unsupported("no tag to detect presence");
        let mut out = Vec::new();
        let e = ber_encode_primitive(PrimitiveRef::Integer(&Integer(1)), framing, &mut out).unwrap_err();
        assert_eq!(e.message, "primitive not supported: no tag to detect presence");
        let mut got = Integer(0);
        let e = ber_decode_primitive(PrimitiveRefMut::Integer(&mut got), framing, &mut BerReader::new(&[0x02, 0x01, 0x01])).unwrap_err();
        assert_eq!(e.message, "primitive not supported: no tag to detect presence");
    }

    #[test]
    fn explicit_any_rejects_wrong_wrapper_tag() {
        let context_1 = Tag::context(1, true);
        let context_2 = Tag::context(2, true);
        let mut buf = Vec::new();
        ber_encode_primitive(PrimitiveRef::Any(&Any(vec![0x02, 0x01, 0x2A])), BerTagging::Explicit(context_1), &mut buf).unwrap();

        let mut r = BerReader::new(&buf);
        let mut got = Any::default();
        assert!(ber_decode_primitive(PrimitiveRefMut::Any(&mut got), BerTagging::Explicit(context_2), &mut r).is_err());
    }
}

/// Test-only per-codec entry points for a bare primitive value, routed
/// through the same dispatch functions the codec walkers use
/// (`ber_encode_primitive` with `Delegate` framing, `xer_encode_primitive`,
/// ...). Lets each primitive's own unit tests exercise exactly the
/// production path without a per-type codec method.
#[cfg(test)]
pub(crate) mod test_codec {
    use super::*;
    use crate::spec::object::{AsMemberRef, MemberRef, MemberRefMut};
    use crate::xer::reader::XerReader;

    fn prim<T: AsMemberRef + ?Sized>(v: &T) -> PrimitiveRef<'_> {
        match v.as_member_ref() {
            MemberRef::Primitive(p) => p,
            _ => panic!("test_codec: not a primitive"),
        }
    }

    fn prim_mut<T: AsMemberRef + ?Sized>(v: &mut T) -> PrimitiveRefMut<'_> {
        match v.as_member_ref_mut() {
            MemberRefMut::Primitive(p) => p,
            _ => panic!("test_codec: not a primitive"),
        }
    }

    pub fn ber_encode<T: AsMemberRef + ?Sized>(v: &T, out: &mut Vec<u8>) {
        ber_encode_primitive(prim(v), BerTagging::Delegate, out).unwrap()
    }

    pub fn ber_decode_into<T: AsMemberRef + ?Sized>(v: &mut T, r: &mut BerReader) -> Result<(), BerDecodeError> {
        ber_decode_primitive(prim_mut(v), BerTagging::Delegate, r)
    }

    pub fn xer_encode<T: AsMemberRef + ?Sized>(v: &T, out: &mut String, depth: usize) {
        xer_encode_primitive(prim(v), out, depth).unwrap()
    }

    pub fn xer_decode_into<T: AsMemberRef + ?Sized>(v: &mut T, r: &mut XerReader) -> Result<(), BerDecodeError> {
        xer_decode_primitive(prim_mut(v), r)
    }

    pub fn jer_encode<T: AsMemberRef + ?Sized>(v: &T, out: &mut String) {
        jer_encode_primitive(prim(v), out).unwrap()
    }

    pub fn jer_decode_into<T: AsMemberRef + ?Sized>(v: &mut T, r: &mut JerReader) -> Result<(), BerDecodeError> {
        jer_decode_primitive(prim_mut(v), r)
    }

    pub fn per_encode<T: AsMemberRef + ?Sized>(v: &T, w: &mut PerWriter, c: &crate::constraints::Constraints) {
        per_encode_primitive(prim(v), w, c).unwrap()
    }

    pub fn per_decode_into<T: AsMemberRef + ?Sized>(v: &mut T, r: &mut PerReader, c: &crate::constraints::Constraints) -> Result<(), PerDecodeError> {
        per_decode_primitive(prim_mut(v), r, c)
    }
}
