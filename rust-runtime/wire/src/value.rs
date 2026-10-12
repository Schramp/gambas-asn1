//! Type-erasure trait for table-driven member access.
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

use crate::ber::reader::{DecodeError, Reader};
use crate::xer::reader::XerReader;

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
/// *outer* tag wrapping is the table-driven walker's job, not `Asn1Value`'s.
///
/// `xer_decode_into` takes a `&mut XerReader` positioned right after the
/// member's open tag, not a pre-extracted `&str` — necessary
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
/// forced to add a real XER leg in the same change — same BER-then-XER
/// incremental pairing this crate uses throughout.
pub trait Asn1Value {
    /// This value's own natural BER tag (X.690 §8.1.2). CHOICE has no
    /// natural tag (X.680 §28); a CHOICE member/alternative is always
    /// EXPLICIT-wrapped when tagged (X.680 §30.6), so its generated impl
    /// uses `unreachable!()`.
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag;

    /// Writes just the TLV value octets (X.690 §8.1.3) — no tag, no length.
    fn ber_encode_content(&self, out: &mut Vec<u8>);

    /// Parses value octets already extracted from a TLV (tag/length already
    /// consumed and checked by the caller) into `self`.
    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError>;

    /// Checks `self` against an X.680 §51 SubtypeConstraint (SIZE, value
    /// range, FROM alphabet, ...). `c` is the *declaration's own* constraint
    /// data (a member row's `Constraints`): a shared native type (`i64`,
    /// `String`, ...) has no constraint of its own, so its blanket impl
    /// checks against whatever the caller passes. A named type (a generated
    /// newtype/ENUMERATED/SEQUENCE OF) already owns its constraint in a
    /// static and ignores `c`.
    ///
    /// The Rust analogue of each C++ type's own
    /// `validate(const Constraints&)` (`runtime/include/asn1cpp/types/
    /// Integer.hpp` and siblings), reached generically the same way
    /// (`runtime/include/asn1cpp/Validate.hpp`'s single dispatch point).
    /// Composite types (SEQUENCE/SET/CHOICE) leave this at the default too
    /// — same "0, caller recurses into members" contract the C++ side's
    /// own doc states; each member gets checked individually as the
    /// generic walker (`sequence.rs`/`choice.rs`) reaches it through this
    /// same trait, not by the composite's own `validate()`.
    ///
    /// Not called directly by generated code — `ber_encode_tagged`/
    /// `ber_decode_into_tagged`'s default bodies (below) are the actual
    /// call site (`validate::check`, `validate.rs`), gated by
    /// `debug::debug_flags()`. This method's own default (always 0) is
    /// the whole story for now; every concrete override (INTEGER range,
    /// OCTET/BIT STRING and character string SIZE, FROM alphabet,
    /// SEQUENCE OF/SET OF SIZE, ENUMERATED unknown-value) is separate,
    /// not-yet-implemented follow-on work, one constraint kind at a time.
    ///
    /// # Returns
    /// `0` when valid (or unconstrained), otherwise a signed delta such
    /// that `self` shifted by `delta` would land at the nearest valid
    /// bound (positive: below the lower bound; negative: above the upper
    /// bound) — same convention as the C++ side, so a future
    /// `RandomFiller`-equivalent can reuse the delta to retry a sample
    /// in-bounds rather than merely reporting failure.
    fn validate(&self, _c: &crate::constraints::Constraints) -> i64 {
        0
    }

    /// Writes this value's complete TLV under its own natural tag.
    fn ber_encode(&self, out: &mut Vec<u8>) {
        self.ber_encode_tagged(self.ber_natural_tag(), out);
    }

    /// Reads a complete TLV, checking it carries this value's own natural
    /// tag, then decodes the content into `self`.
    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        self.ber_decode_into_tagged(r, self.ber_natural_tag())
    }

    /// IMPLICIT tag override (X.690 §8.14) — writes this value's content
    /// under `tag` instead of its own natural one.
    ///
    /// This is the one call site every non-composite `Asn1Value` impl
    /// funnels through on encode (`ber_encode`'s own default delegates
    /// here) — so it is also where constraint validation (X.680 §51
    /// SubtypeConstraint) hooks in, gated by `debug::debug_flags()` the
    /// same way every other `ASN1CPP_DEBUG` bit is (`debug.rs`): on by
    /// default, `DBG_NO_VALIDATE` opts out, `DBG_VALIDATE_TRACE`
    /// additionally prints each failure. Overridden directly by a
    /// self-tagged CHOICE (`RustBackend::emit_choice_definition`, when
    /// `spec.tag` is set) — the one remaining override outside this
    /// default and `Box<T>`'s forwarding, since #704 removed the
    /// `ber_encode_explicit`/`ber_decode_into_explicit` pair this used to
    /// sit alongside (confirmed zero codegen references to those two).
    fn ber_encode_tagged(&self, tag: crate::ber::tag::Tag, out: &mut Vec<u8>) {
        crate::validate::check(self, "encode");
        crate::ber::writer::write_tagged(out, tag, |buf| self.ber_encode_content(buf));
    }

    /// Decode counterpart of `ber_encode_tagged` — same `validate()` call
    /// site rationale, checked after a successful decode (mirrors
    /// `BerCodec::decode`'s own `res.has_value() && ...` guard, C++).
    fn ber_decode_into_tagged(&mut self, r: &mut Reader, tag: crate::ber::tag::Tag) -> Result<(), DecodeError> {
        let tlv = r.read_tlv()?;
        if tlv.tag != tag {
            return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
        }
        self.ber_decode_content(tlv.value)?;
        crate::validate::check(self, "decode");
        Ok(())
    }

    fn xer_encode(&self, _out: &mut String, _depth: usize) {
        unimplemented!("XER leg not yet wired for this type")
    }

    fn xer_decode_into(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        Err(DecodeError::new("XER leg not yet wired for this type".to_string(), 0))
    }

    /// X.697 JER encoding of this value, appended to `out` -- the JSON
    /// analogue of `xer_encode`, same "every builtin overrides this,
    /// SEQUENCE/CHOICE/SEQUENCE-OF too" shape. No depth/indentation
    /// parameter: JER output is compact, single-line per record (matches
    /// `JerEncodeStream`'s own convention, `runtime/src/JerCodec.cpp`).
    fn jer_encode(&self, _out: &mut String) {
        unimplemented!("JER leg not yet wired for this type")
    }

    /// Decode counterpart of `jer_encode`.
    fn jer_decode_into(&mut self, _r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        Err(DecodeError::new("JER leg not yet wired for this type".to_string(), 0))
    }

    /// BASE64 XER representation (X.693 §21) for an `ENCODING-CONTROL XER
    /// ... BASE64` (or legacy `::= base64`)-marked OCTET STRING member —
    /// the alternative to `xer_encode`'s own default (unspaced uppercase
    /// hex). Unreachable by default: only `OctetString` overrides it, and
    /// only a `spec::sequence::MemberAccess::Base64Scalar` row (emitted
    /// when `RustBackend` sees the member's own `xer_encoding == Base64`)
    /// ever calls it — every other member/type keeps using plain
    /// `xer_encode`/`xer_decode_into` (`MemberAccess::Scalar` and friends).
    /// Trait-dispatched (not a free function `RustBackend::
    /// emit_builtin_alias_definition` bakes into a lifted alias type's own
    /// method body) so a member can get base64 XER encoding without being
    /// promoted to its own named type first.
    fn xer_encode_base64(&self, _out: &mut String) {
        unreachable!("xer_encode_base64 called on a type with no base64 XER representation")
    }

    /// Decode counterpart of `xer_encode_base64`.
    fn xer_decode_into_base64(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        unreachable!("xer_decode_into_base64 called on a type with no base64 XER representation")
    }

    /// UTF8 XER representation (X.693 §21) for an `ENCODING-CONTROL XER
    /// ... UTF8` (or legacy `::= utf8`)-marked OCTET STRING member — same
    /// rationale as `xer_encode_base64`'s own doc, mirrored for the other
    /// XER-instruction kind `MemberRef::Utf8` carries.
    fn xer_encode_utf8(&self, _out: &mut String) {
        unreachable!("xer_encode_utf8 called on a type with no utf8 XER representation")
    }

    /// Decode counterpart of `xer_encode_utf8`.
    fn xer_decode_into_utf8(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        unreachable!("xer_decode_into_utf8 called on a type with no utf8 XER representation")
    }


    /// The constraint this type itself owns — a generated INTEGER newtype's
    /// range, a builtin-alias newtype's SIZE, a SEQUENCE OF newtype's SIZE.
    /// `UNCONSTRAINED` for every type without one: a shared native type
    /// (`i64`, `String`, ...) takes its constraint from the declaration
    /// that uses it (the member row), and SEQUENCE/CHOICE/ENUMERATED carry
    /// theirs in their own spec tables. A caller with no enclosing member
    /// row (a top-level PDU) passes `value.constraints()` as the `c`
    /// argument of `per_encode`/`per_decode_into`/`validate`.
    fn constraints(&self) -> &'static crate::constraints::Constraints {
        &crate::constraints::UNCONSTRAINED
    }

    /// X.691 unaligned PER encoding of this value. `c` is the declaration's
    /// own `Constraints` (range bits, SIZE, ...): PER's wire shape depends on
    /// the declared constraint, so a shared native type (`i64`, `String`,
    /// ...) encodes against whatever the caller passes. A named type
    /// (SEQUENCE/CHOICE/ENUMERATED/named INTEGER/named builtin-alias) owns
    /// its constraint in a static and ignores `c`. Default panics for a
    /// type PER doesn't cover yet — the same "real-or-panic-stub" policy
    /// `MemberAccess::Unsupported` gives an individual member row, applied
    /// to a whole type.
    fn per_encode(&self, _w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        unimplemented!("PER encode not implemented for this type")
    }

    /// Decode counterpart of `per_encode`.
    fn per_decode_into(
        &mut self,
        _r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        Err(crate::per::reader::DecodeError::new("PER decode not implemented for this type", 0))
    }
}

/// Shared `Asn1Value` shape for `Integer`/`UInteger` (`IntStorageKind::
/// S64`/`U64`): identical structure across signed/unsigned width, only the
/// byte-codec functions (`crate::integer`), PER module (`crate::per`) and
/// `validate` function (`crate::constraints`) differ. `BigInteger`
/// (`I128`) isn't covered — no PER/validate wiring exists for it yet
/// (nothing generates one today; see `integer.rs`'s own doc), so it keeps
/// its own hand-written impl rather than forcing a shape this macro
/// doesn't fit.
macro_rules! fixed_width_integer {
    ($name:ty, $prim:ty, $encode_bytes:ident, $decode_bytes:ident,
     $per_mod:ident, $per_encode_fn:ident, $per_decode_fn:ident, $validate_fn:ident) => {
        impl Asn1Value for $name {
            fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
                crate::integer::INTEGER_TAG
            }

            fn ber_encode_content(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&crate::integer::$encode_bytes(self.0));
            }

            fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
                self.0 = crate::integer::$decode_bytes(content)?;
                Ok(())
            }

            fn xer_encode(&self, out: &mut String, _depth: usize) {
                crate::xer::integer::encode(self.0, out);
            }

            fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
                self.0 = crate::xer::integer::decode(r)?;
                Ok(())
            }

            fn jer_encode(&self, out: &mut String) {
                crate::jer::integer::encode(self.0, out);
            }

            fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
                self.0 = crate::jer::integer::decode(r)?;
                Ok(())
            }

            fn per_encode(&self, w: &mut crate::per::writer::Writer, c: &crate::constraints::Constraints) {
                crate::per::$per_mod::$per_encode_fn(w, c, self.0);
            }

            fn per_decode_into(&mut self, r: &mut crate::per::reader::Reader, c: &crate::constraints::Constraints) -> Result<(), crate::per::reader::DecodeError> {
                self.0 = crate::per::$per_mod::$per_decode_fn(r, c)?;
                Ok(())
            }

            fn validate(&self, c: &crate::constraints::Constraints) -> i64 {
                crate::constraints::$validate_fn(self.0, c)
            }
        }
    };
}

fixed_width_integer!(crate::integer::Integer, i64, encode_integer_bytes, decode_integer_bytes,
    integer, encode_int, decode_int, validate_s64);
// Wide-range INTEGER storage (a constrained range whose bound exceeds
// i64::MAX/MIN — IntStorageKind::U64, RustBackend::native_int_type).
fixed_width_integer!(crate::integer::UInteger, u64, encode_integer_bytes_u64, decode_integer_bytes_u64,
    uinteger, encode_uint, decode_uint, validate_u64);

/// i128 analogue of the `u64` impl above.
impl Asn1Value for crate::integer::BigInteger {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::integer::INTEGER_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::integer::encode_integer_bytes_i128(self.0));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = crate::integer::decode_integer_bytes_i128(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::integer::encode(self.0, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = crate::xer::integer::decode(r)?;
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::integer::encode(self.0, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::integer::decode(r)?;
        Ok(())
    }
}

/// Mirrors `BooleanXerHandler` (`runtime/src/XerCodec.cpp`) — BASIC-XER's
/// `EmptyElementBoolean` form: content is a nested self-closing `<true/>`/
/// `<false/>` tag, not text (X.693 §8.2's default form). `xer_decode_into`
/// also accepts EXTENDED-XER §10 TextBoolean (plain `"true"`/`"false"`
/// content) when `XerReader::lenient()` is set — the non-standard asn1c
/// extension `XerDecodeMode::Lenient` allows on the C++ side.
impl Asn1Value for crate::boolean::Boolean {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::boolean::BOOLEAN_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::boolean::encode_boolean_content(self.0));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = crate::boolean::decode_boolean_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::boolean::encode(self.0, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = crate::xer::boolean::decode(r)?;
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        out.push_str(if self.0 { "true" } else { "false" });
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        let tok = r.read_json_token()?;
        match tok.as_str() {
            "true" => { self.0 = true; Ok(()) }
            "false" => { self.0 = false; Ok(()) }
            _ => Err(DecodeError::new(format!("JER: BOOLEAN expected true/false, got: {tok}"), r.pos())),
        }
    }

    /// X.691 §12: one bit, no alignment — 1 for TRUE, 0 for FALSE. Mirrors
    /// `BooleanPerHandler` (`runtime/src/PerCodec.cpp`) exactly.
    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        w.put_bits(self.0 as u64, 1);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        self.0 = r.get_bits(1)? != 0;
        Ok(())
    }
}

/// Maps ASN.1 NULL — `native_builtin_type`'s `()` choice,
/// `RustBackend.cpp`. Mirrors `NullXerHandler`'s named-wrapper form
/// (`runtime/src/XerCodec.cpp`): empty content inside the member's own
/// `<name></name>` tag, e.g. `<flag></flag>` — the self-closing `<NULL/>`
/// form that same handler emits only applies when the *type's own name* is
/// literally "NULL" (a raw top-level/SEQUENCE-OF-element descriptor, an
/// asn1c-compat quirk), never a member's field-name-derived tag, so
/// `Asn1Value` (member-embedded content only, per this trait's own doc
/// comment) never needs that branch.
impl Asn1Value for crate::null::Null {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::null::NULL_TAG
    }

    fn ber_encode_content(&self, _out: &mut Vec<u8>) {
        // Empty content — nothing to write.
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        crate::null::decode_null_content(content)
    }

    fn xer_encode(&self, _out: &mut String, _depth: usize) {
        // Empty content — nothing to write.
    }

    fn xer_decode_into(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        // Empty content — nothing to consume.
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::null::encode(out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        crate::jer::null::decode(r)
    }

    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        crate::per::null::encode(w);
    }
    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        crate::per::null::decode(r)
    }
}

/// Maps ASN.1 BIT STRING — `native_builtin_type`'s
/// `bit_string::BitString` choice, `RustBackend.cpp` (not `Vec<u8>`: see
/// that struct's own module doc for why it can't be a plain-`Vec<u8>`
/// newtype like OCTET STRING). Mirrors `BitStringXerHandler`'s content
/// model (`runtime/src/XerCodec.cpp`): a string of '0'/'1' characters, one
/// per bit, MSB first within each byte (X.680 §21's XMLBitStringValue
/// grammar) — C++'s writer additionally pretty-prints this across
/// indented 64-character lines, which is cosmetic only (its own decoder
/// skips whitespace), so this impl emits the same bit sequence unspaced,
/// on one line, and accepts (skips) any whitespace on decode. Decode also
/// accepts the non-standard lenient hex-pairs form
/// (`BitStringXerHandler::decode`) when `XerReader::lenient()` is set — a
/// pure `0`/`1` string is decoded as binary either way (indistinguishable
/// from hex, matches the C++ heuristic); any `2`-`9`/`A`-`F`/`a`-`f`
/// character makes it unambiguous and requires lenient mode.
impl Asn1Value for crate::bit_string::BitString {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::bit_string::BIT_STRING_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::bit_string::encode_bit_string_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::bit_string::decode_bit_string_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, depth: usize) {
        crate::xer::bit_string::encode(self, out, depth);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        crate::xer::bit_string::decode_into(self, r)
    }

    fn per_encode(&self, w: &mut crate::per::writer::Writer, c: &crate::constraints::Constraints) {
        crate::per::bit_string::encode_bit_string(w, c, &self.bytes, self.bit_count());
    }

    fn per_decode_into(&mut self, r: &mut crate::per::reader::Reader, c: &crate::constraints::Constraints) -> Result<(), crate::per::reader::DecodeError> {
        let (bytes, unused_bits) = crate::per::bit_string::decode_bit_string(r, c)?;
        *self = crate::bit_string::BitString { bytes, unused_bits };
        Ok(())
    }

    fn validate(&self, c: &crate::constraints::Constraints) -> i64 {
        crate::constraints::validate_size(self.bit_count(), c)
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::bit_string::encode(self, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        *self = crate::jer::bit_string::decode(r)?;
        Ok(())
    }
}

/// Maps ASN.1 OBJECT IDENTIFIER — `native_builtin_type`'s
/// `oid::ObjectIdentifier` choice, `RustBackend.cpp` (not plain `Vec<u64>`:
/// see that struct's own module doc on the OID/RELATIVE-OID single-impl
/// conflict). Mirrors `OidXerHandler`'s content model
/// (`runtime/include/asn1cpp/codec/XerCodec.hpp`'s `format_arcs`/
/// `parse_arcs`): dotted-decimal arcs, e.g. `2.5.4.3`.
impl Asn1Value for crate::oid::ObjectIdentifier {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::oid::OBJECT_IDENTIFIER_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::oid::encode_object_identifier_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::oid::decode_object_identifier_content(content)?;
        Ok(())
    }

    /// X.691 §23/§10.2 "Open type fields": length-prefixed raw BER
    /// content bytes, no bit-packing — mirrors `OidPerHandler`
    /// (`runtime/src/PerCodec.cpp`, `per_detail::encode_ber_content<Oid>`)
    /// exactly.
    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        crate::per::oid::encode(self, w);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        crate::per::oid::decode_into(self, r)
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::oid::encode(self, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        crate::xer::oid::decode_into(self, r)
    }

    /// X.697 §8.14: quoted dotted-decimal string, same arc formatting
    /// XER's own `xer_encode` above uses -- JER has no separate OID
    /// grammar, just JSON-quotes the identical text.
    fn jer_encode(&self, out: &mut String) {
        crate::jer::oid::encode(self, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        crate::jer::oid::decode_into(self, r)
    }
}

/// Maps ASN.1 RELATIVE-OID — `native_builtin_type`'s
/// `relative_oid::RelativeOid` choice, `RustBackend.cpp`. Mirrors
/// `RelOidXerHandler`'s content model (same `format_arcs`/`parse_arcs` OID
/// itself uses — X.680 §33's XML grammar for RELATIVE-OID is the same
/// dotted-decimal-arcs shape, just without OID's first-two-arc rule, which
/// is purely a BER encoding concern anyway): dotted-decimal arcs, e.g.
/// `8571.1`.
impl Asn1Value for crate::relative_oid::RelativeOid {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::relative_oid::RELATIVE_OID_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::relative_oid::encode_relative_oid_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::relative_oid::decode_relative_oid_content(content)?;
        Ok(())
    }

    /// X.691 §24/§10.2 "Open type fields": length-prefixed raw BER content
    /// bytes, no bit-packing — mirrors `RelOidPerHandler`
    /// (`runtime/src/PerCodec.cpp`, `per_detail::encode_ber_content<
    /// RelativeOid>`) exactly.
    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        crate::per::relative_oid::encode(self, w);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        crate::per::relative_oid::decode_into(self, r)
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::relative_oid::encode(self, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        crate::xer::relative_oid::decode_into(self, r)
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::relative_oid::encode(self, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        crate::jer::relative_oid::decode_into(self, r)
    }
}

/// Maps ASN.1 REAL — `native_builtin_type`'s `f64`
/// choice, `RustBackend.cpp`. Mirrors `RealXerHandler`'s content model
/// (`runtime/src/XerCodec.cpp`): special values as nested self-closing
/// tags (`<PLUS-INFINITY/>`/`<MINUS-INFINITY/>`/`<NOT-A-NUMBER/>` — same
/// shape as `bool`'s `<true/>`/`<false/>`), `0`/`-0` as the literal text
/// `"0"`, everything else as `%.15f` with trailing zeros trimmed (keeping
/// at least one digit after the decimal point).
impl Asn1Value for crate::real::Real {
    fn ber_natural_tag(&self) -> crate::ber::tag::Tag {
        crate::real::REAL_TAG
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::real::encode_real_content(out, self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = crate::real::decode_real_value(content, 0)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        crate::xer::real::encode(self.0, out);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = crate::xer::real::decode(r)?;
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::real::encode(self.0, out);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::real::decode(r)?;
        Ok(())
    }

    /// X.691 §16: not bit-packed like INTEGER/ENUMERATED — the value's own
    /// BER content bytes, length-prefixed (mirrors `RealPerHandler`,
    /// `runtime/src/PerCodec.cpp`, exactly). No `Constraints` apply to REAL.
    fn per_encode(&self, w: &mut crate::per::writer::Writer, _c: &crate::constraints::Constraints) {
        crate::per::real::encode_real(w, self.0);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        _c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        self.0 = crate::per::real::decode_real(r)?;
        Ok(())
    }
}

/// Maps `IA5String` (`native_builtin_type`'s `String` choice covers all 12
/// string kinds; this impl is scoped to IA5String's wire tag specifically,
/// see `strings.rs`'s module doc on widening to the others). Mirrors
/// `XerStringHandler`: escaped text content, via `xer::escape`/`xer::unescape`.


#[cfg(test)]
mod per_blanket_tests {
    use super::*;
    use crate::integer::Integer;
    use crate::constraints::Constraints;
    use crate::per::{reader::Reader, writer::Writer};

    fn ranged(lo: i64, hi: i64) -> Constraints {
        Constraints {
            flags: Constraints::CONSTRAINED,
            range_bits: (64 - ((hi - lo) as u64).leading_zeros()),
            lower_bound: lo,
            upper_bound: hi,
            ..Default::default()
        }
    }

    fn bytes_of(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.flush();
        w.into_bytes()
    }

    #[test]
    fn i64_trait_path_matches_free_function_and_roundtrips() {
        let c = ranged(0, 15);
        let via_trait = bytes_of(|w| Integer(9).per_encode(w, &c));
        let direct = bytes_of(|w| crate::per::integer::encode_int(w, &c, 9));
        assert_eq!(via_trait, direct);
        let mut back = Integer(0);
        back.per_decode_into(&mut Reader::new(&via_trait), &c).unwrap();
        assert_eq!(back, 9);
    }

    #[test]
    fn a_type_without_its_own_constraint_reports_unconstrained() {
        assert_eq!(Integer(5).constraints(), &crate::constraints::UNCONSTRAINED);
    }

    #[test]
    fn i64_validate_uses_the_passed_constraints() {
        let c = ranged(0, 15);
        assert_eq!(Integer(20).validate(&c), -5);
        assert_eq!(Integer(5).validate(&c), 0);
        assert_eq!(Integer(20).validate(&crate::constraints::UNCONSTRAINED), 0);
    }

    #[test]
    fn octet_string_trait_path_roundtrips_and_validates_size() {
        let c = Constraints { flags: Constraints::SIZE_CONSTRAINED, size_range_bits: 2, size_lower: 1, size_upper: 3, ..Default::default() };
        let v = crate::octet_string::OctetString(vec![1, 2]);
        let enc = bytes_of(|w| v.per_encode(w, &c));
        let mut back = crate::octet_string::OctetString::default();
        back.per_decode_into(&mut Reader::new(&enc), &c).unwrap();
        assert_eq!(back, v);
        assert_eq!(crate::octet_string::OctetString(vec![0; 5]).validate(&c), -2);
    }

    #[test]
    fn string_kinds_use_their_own_tag_for_the_alphabet_width() {
        let c = crate::constraints::UNCONSTRAINED;
        let num = crate::strings::NumericString("12345".to_string());
        let ia5 = crate::strings::Ia5String("12345".to_string());
        // NumericString packs 4 bits/char, IA5String 7 — different lengths on the wire.
        assert_ne!(bytes_of(|w| num.per_encode(w, &c)), bytes_of(|w| ia5.per_encode(w, &c)));
        let mut back = crate::strings::NumericString::default();
        back.per_decode_into(&mut Reader::new(&bytes_of(|w| num.per_encode(w, &c))), &c).unwrap();
        assert_eq!(back, num);
    }

    #[test]
    fn seq_of_integer_via_trait_matches_size_field_plus_element_loop() {
        static ELEM: Constraints = Constraints {
            flags: Constraints::CONSTRAINED, range_bits: 4, lower_bound: 0, upper_bound: 15,
            lower_u64: 0, upper_u64: 0, size_range_bits: 0, size_lower: 0, size_upper: 0,
            encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,
        };
        let coll = Constraints {
            flags: Constraints::SIZE_CONSTRAINED, size_range_bits: 3, size_lower: 0, size_upper: 7,
            element: Some(&ELEM), ..Default::default()
        };
        let v = crate::ber::sequence::SeqOf(vec![Integer(1), Integer(9), Integer(15)]);
        let via_trait = bytes_of(|w| v.per_encode(w, &coll));
        let manual = bytes_of(|w| {
            crate::per::length::encode_size_field(w, &coll, 3);
            for x in [1i64, 9, 15] {
                crate::per::integer::encode_int(w, &ELEM, x);
            }
        });
        assert_eq!(via_trait, manual);
        let mut back = crate::ber::sequence::SeqOf::<Integer>(vec![]);
        back.per_decode_into(&mut Reader::new(&via_trait), &coll).unwrap();
        assert_eq!(back.0, vec![Integer(1), Integer(9), Integer(15)]);
    }

    #[test]
    fn wide_string_trait_path_roundtrips_raw_bytes() {
        let c = crate::constraints::UNCONSTRAINED;
        let v = crate::strings::BmpString(vec![0x00, 0x41, 0x00, 0x42]);
        let enc = bytes_of(|w| v.per_encode(w, &c));
        let mut back = crate::strings::BmpString::default();
        back.per_decode_into(&mut Reader::new(&enc), &c).unwrap();
        assert_eq!(back, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boolean::Boolean;
    use crate::integer::Integer;
    use crate::null::Null;
    use crate::real::Real;

    #[test]
    fn i64_round_trips_through_the_trait() {
        let mut out = Vec::new();
        Integer(300).ber_encode(&mut out);
        assert_eq!(out, vec![0x02, 0x02, 0x01, 0x2C]);

        let mut r = Reader::new(&out);
        let mut got = Integer(0);
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, 300);
    }

    #[test]
    fn i64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        Integer(1).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got = Integer(0);
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1);
    }

    #[test]
    fn i64_xer_negative_and_whitespace() {
        let mut out = String::new();
        Integer(-42).xer_encode(&mut out, 0);
        assert_eq!(out, "-42");

        let mut r = XerReader::new("  -42  ");
        let mut got = Integer(0);
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, -42);
    }

    #[test]
    fn i64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got = Integer(0);
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn bool_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        Boolean(true).ber_encode(&mut out);
        assert_eq!(out, vec![0x01, 0x01, 0xFF]);

        let mut r = Reader::new(&out);
        let mut got = Boolean(false);
        got.ber_decode_into(&mut r).unwrap();
        assert!(got.0);
    }

    #[test]
    fn unit_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        Null.ber_encode(&mut out);
        assert_eq!(out, vec![0x05, 0x00]);

        let mut r = Reader::new(&out);
        let mut got = Null;
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, Null);
    }

    #[test]
    fn unit_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        Null.xer_encode(&mut out, 0);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = Null;
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert_eq!(got, Null);
    }

    #[test]
    fn bit_string_ber_round_trips_through_the_trait() {
        use crate::bit_string::BitString;

        let v = BitString { bytes: vec![0b1010_1000], unused_bits: 4 };
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        assert_eq!(out, vec![0x03, 0x02, 0x04, 0b1010_1000]);

        let mut r = Reader::new(&out);
        let mut got = BitString::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_xer_round_trips_wrapped_by_hand() {
        use crate::bit_string::BitString;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        // 1010 0000, 4 unused bits -> logical bits "1010" (bit_count=4).
        // Padding bits are zero here deliberately: XER only carries the
        // logical bit sequence (bit_count), zero-filling padding on decode
        // (X.680's XMLBitStringValue captures no padding-bit-value
        // information) — a fixture with *non-zero* padding wouldn't
        // round-trip byte-for-byte through XER, which is expected, not a bug.
        let v = BitString { bytes: vec![0b1010_0000], unused_bits: 4 };
        let mut out = String::new();
        write_open_tag(&mut out, "flags");
        v.xer_encode(&mut out, 0);
        write_close_tag(&mut out, "flags");
        assert_eq!(out, "<flags>\n    1010\n</flags>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flags").unwrap();
        let mut got = BitString::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("flags").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_xer_empty_round_trips() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("");
        let mut got = BitString { bytes: vec![0xFF], unused_bits: 0 };
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, BitString::default());
    }

    #[test]
    fn bit_string_xer_rejects_invalid_character() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("10G");
        let mut got = BitString::default();
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn bit_string_xer_strict_rejects_hex() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new("04AA");
        let mut got = BitString::default();
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn bit_string_xer_lenient_accepts_hex_pairs() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new_lenient("04AABB");
        let mut got = BitString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, BitString { bytes: vec![0x04, 0xAA, 0xBB], unused_bits: 0 });
    }

    #[test]
    fn bit_string_xer_lenient_pure_binary_string_still_decodes_as_binary() {
        use crate::bit_string::BitString;

        // "0001" has no digit outside 0/1 — indistinguishable from binary,
        // matches asn1c's own heuristic (see xer_decode_into's own doc).
        let mut r = XerReader::new_lenient("0001");
        let mut got = BitString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, BitString { bytes: vec![0b0001_0000], unused_bits: 4 });
    }

    #[test]
    fn bit_string_xer_lenient_rejects_odd_length_hex() {
        use crate::bit_string::BitString;

        let mut r = XerReader::new_lenient("04A");
        let mut got = BitString::default();
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn oid_ber_round_trips_through_the_trait() {
        use crate::oid::ObjectIdentifier;

        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        assert_eq!(out, vec![0x06, 0x03, 0x55, 0x04, 0x03]);

        let mut r = Reader::new(&out);
        let mut got = ObjectIdentifier::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_xer_round_trips_wrapped_by_hand() {
        use crate::oid::ObjectIdentifier;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = String::new();
        write_open_tag(&mut out, "oid");
        v.xer_encode(&mut out, 0);
        write_close_tag(&mut out, "oid");
        assert_eq!(out, "<oid>2.5.4.3</oid>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("oid").unwrap();
        let mut got = ObjectIdentifier::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("oid").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_xer_single_arc_round_trips() {
        use crate::oid::ObjectIdentifier;

        let mut r = XerReader::new("2");
        let mut got = ObjectIdentifier::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, ObjectIdentifier(vec![2]));
    }

    #[test]
    fn oid_xer_empty_round_trips() {
        use crate::oid::ObjectIdentifier;

        let mut r = XerReader::new("");
        let mut got = ObjectIdentifier(vec![1, 2, 3]);
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, ObjectIdentifier::default());
    }

    #[test]
    fn relative_oid_ber_round_trips_through_the_trait() {
        use crate::relative_oid::RelativeOid;

        let v = RelativeOid(vec![8571, 1]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        assert_eq!(out, vec![0x0D, 0x03, 0xC2, 0x7B, 0x01]);

        let mut r = Reader::new(&out);
        let mut got = RelativeOid::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn relative_oid_xer_round_trips_wrapped_by_hand() {
        use crate::relative_oid::RelativeOid;
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let v = RelativeOid(vec![8571, 1]);
        let mut out = String::new();
        write_open_tag(&mut out, "roid");
        v.xer_encode(&mut out, 0);
        write_close_tag(&mut out, "roid");
        assert_eq!(out, "<roid>8571.1</roid>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("roid").unwrap();
        let mut got = RelativeOid::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("roid").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn relative_oid_xer_empty_round_trips() {
        use crate::relative_oid::RelativeOid;

        let mut r = XerReader::new("");
        let mut got = RelativeOid(vec![1, 2]);
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got, RelativeOid::default());
    }

    #[test]
    fn f64_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        Real(1.5).ber_encode(&mut out);

        let mut r = Reader::new(&out);
        let mut got = Real(0.0);
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        Real(1.5).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1.5</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got = Real(0.0);
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_zero_preserves_sign() {
        let mut out = String::new();
        Real(0.0).xer_encode(&mut out, 0);
        assert_eq!(out, "0");

        // X.693 §17.9: -0.0 is distinct decimal text from +0.0, unlike
        // the special-value keywords (PLUS-INFINITY/NOT-A-NUMBER), which
        // have no sign-of-zero analogue to lose.
        let mut out2 = String::new();
        Real(-0.0).xer_encode(&mut out2, 0);
        assert_eq!(out2, "-0");
    }

    #[test]
    fn f64_xer_special_values_round_trip() {
        for v in [Real(f64::INFINITY), Real(f64::NEG_INFINITY)] {
            let mut out = String::new();
            v.xer_encode(&mut out, 0);
            let mut r = XerReader::new(&out);
            let mut got = Real(0.0);
            got.xer_decode_into(&mut r).unwrap();
            assert_eq!(got, v);
        }

        let mut out = String::new();
        Real(f64::NAN).xer_encode(&mut out, 0);
        assert_eq!(out, "<NOT-A-NUMBER/>");
        let mut r = XerReader::new(&out);
        let mut got = Real(0.0);
        got.xer_decode_into(&mut r).unwrap();
        assert!(got.is_nan());
    }

    #[test]
    fn f64_xer_trims_trailing_zeros_but_keeps_one_digit() {
        let mut out = String::new();
        Real(2.0).xer_encode(&mut out, 0);
        assert_eq!(out, "2.0");
    }

    #[test]
    fn f64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got = Real(0.0);
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn bool_xer_round_trips_wrapped_by_hand() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "flag");
        Boolean(true).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "flag");
        assert_eq!(out, "<flag><true/></flag>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("flag").unwrap();
        let mut got = Boolean(false);
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("flag").unwrap();
        assert!(got.0);
    }

    #[test]
    fn bool_xer_false_round_trips() {
        let mut out = String::new();
        Boolean(false).xer_encode(&mut out, 0);
        assert_eq!(out, "<false/>");

        let mut r = XerReader::new("<false/>");
        let mut got = Boolean(true);
        got.xer_decode_into(&mut r).unwrap();
        assert!(!got.0);
    }

    #[test]
    fn bool_xer_rejects_non_empty_element_form() {
        let mut r = XerReader::new("true");
        let mut got = Boolean(false);
        assert!(got.xer_decode_into(&mut r).is_err());
    }

    #[test]
    fn bool_xer_lenient_accepts_text_content() {
        let mut r = XerReader::new_lenient("true");
        let mut got = Boolean(false);
        got.xer_decode_into(&mut r).unwrap();
        assert!(got.0);

        let mut r = XerReader::new_lenient("false");
        let mut got = Boolean(true);
        got.xer_decode_into(&mut r).unwrap();
        assert!(!got.0);
    }

    #[test]
    fn bool_xer_lenient_still_accepts_empty_element_form() {
        let mut r = XerReader::new_lenient("<true/>");
        let mut got = Boolean(false);
        got.xer_decode_into(&mut r).unwrap();
        assert!(got.0);
    }

    #[test]
    fn string_ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        crate::strings::Ia5String("hi".to_string()).ber_encode(&mut out);
        assert_eq!(out, vec![0x16, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = crate::strings::Ia5String::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got.0, "hi");
    }

    #[test]
    fn string_xer_escapes_and_round_trips() {
        use crate::xer::writer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "label");
        crate::strings::Ia5String("a<b>&c".to_string()).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "label");
        assert_eq!(out, "<label>a&lt;b&gt;&amp;c</label>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("label").unwrap();
        let mut got = crate::strings::Ia5String::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("label").unwrap();
        assert_eq!(got.0, "a<b>&c");
    }

    #[test]
    fn oid_per_round_trips() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![1, 2, 840, 113549]);
        let mut w = crate::per::writer::Writer::new();
        v.per_encode(&mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut got = ObjectIdentifier::default();
        got.per_decode_into(&mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn oid_per_length_prefix_matches_ber_content_byte_count() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![2, 5, 4, 3]); // commonName, 3 content bytes
        let mut ber_content = Vec::new();
        crate::oid::encode_object_identifier_content(&mut ber_content, &v);
        let mut w = crate::per::writer::Writer::new();
        v.per_encode(&mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let per_bytes = w.into_bytes();
        assert_eq!(per_bytes[0] as usize, ber_content.len());
        assert_eq!(&per_bytes[1..], &ber_content[..]);
    }

    #[test]
    fn relative_oid_per_round_trips() {
        use crate::relative_oid::RelativeOid;
        let v = RelativeOid(vec![8571, 1]);
        let mut w = crate::per::writer::Writer::new();
        v.per_encode(&mut w, &crate::constraints::UNCONSTRAINED);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut got = RelativeOid::default();
        got.per_decode_into(&mut r, &crate::constraints::UNCONSTRAINED).unwrap();
        assert_eq!(got, v);
    }

    // -----------------------------------------------------------------
    // JER — known-correct JSON strings are from the C++ reference's own
    // `tests/jer/*.cpp` (ground truth, not just round-trip-with-itself).

    #[test]
    fn integer_jer_round_trips_and_matches_reference() {
        use crate::integer::Integer;
        let v = Integer(42);
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "42");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Integer::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);

        let neg = Integer(-1);
        let mut out2 = String::new();
        neg.jer_encode(&mut out2);
        assert_eq!(out2, "-1");
    }

    #[test]
    fn boolean_jer_round_trips_and_matches_reference() {
        use crate::boolean::Boolean;
        for (v, text) in [(true, "true"), (false, "false")] {
            let b = Boolean(v);
            let mut out = String::new();
            b.jer_encode(&mut out);
            assert_eq!(out, text);
            let mut r = crate::jer::reader::Reader::new(&out);
            let mut got = Boolean::default();
            got.jer_decode_into(&mut r).unwrap();
            assert_eq!(got, b);
        }
    }

    #[test]
    fn null_jer_round_trips_and_matches_reference() {
        use crate::null::Null;
        let v = Null;
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "null");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Null;
        got.jer_decode_into(&mut r).unwrap();
    }

    #[test]
    fn real_jer_special_values_match_reference() {
        // X.697 Table 2: "-0"/"-INF"/"INF"/"NaN" -- not "PLUS-INFINITY"/
        // "MINUS-INFINITY" (that's X.693/XER's spelling, a different
        // clause; confirmed against the standard text directly).
        use crate::real::Real;
        for (v, text) in [
            (f64::NAN, "\"NaN\""),
            (f64::INFINITY, "\"INF\""),
            (f64::NEG_INFINITY, "\"-INF\""),
            (0.0, "0"),
            (-0.0, "\"-0\""),
        ] {
            let r = Real(v);
            let mut out = String::new();
            r.jer_encode(&mut out);
            assert_eq!(out, text);
        }
    }

    #[test]
    fn real_jer_round_trips_finite_value() {
        use crate::real::Real;
        let v = Real(1.5);
        let mut out = String::new();
        v.jer_encode(&mut out);
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Real::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, v.0);
    }

    #[test]
    fn oid_jer_round_trips_and_matches_reference() {
        use crate::oid::ObjectIdentifier;
        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "\"2.5.4.3\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = ObjectIdentifier::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn octet_string_jer_round_trips_and_matches_reference() {
        use crate::octet_string::OctetString;
        let v = OctetString(vec![0xAB, 0xCD]);
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "\"ABCD\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = OctetString::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn bit_string_jer_round_trips_and_matches_reference() {
        use crate::bit_string::BitString;
        let v = BitString { bytes: vec![0xAB], unused_bits: 0 };
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "{\"value\":\"AB\",\"length\":8}");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = BitString::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn utf8_string_jer_round_trips() {
        use crate::strings::Utf8String;
        let v = Utf8String("hello".to_string());
        let mut out = String::new();
        v.jer_encode(&mut out);
        assert_eq!(out, "\"hello\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = Utf8String::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn t61_string_jer_uses_hex() {
        use crate::strings::T61String;
        let v = T61String("AB".to_string());
        let mut out = String::new();
        v.jer_encode(&mut out);
        // "AB" -> UTF-8 bytes 0x41 0x42 -> hex "4142"
        assert_eq!(out, "\"4142\"");
        let mut r = crate::jer::reader::Reader::new(&out);
        let mut got = T61String::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn seq_of_jer_round_trips_and_matches_reference() {
        use crate::ber::sequence::SeqOf;
        use crate::integer::Integer;

        let empty: SeqOf<Integer> = SeqOf(vec![]);
        let mut out = String::new();
        empty.jer_encode(&mut out);
        assert_eq!(out, "[]");

        let v: SeqOf<Integer> = SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        let mut out2 = String::new();
        v.jer_encode(&mut out2);
        assert_eq!(out2, "[1,2,3]");
        let mut r = crate::jer::reader::Reader::new(&out2);
        let mut got: SeqOf<Integer> = SeqOf::default();
        got.jer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, v.0);
    }
}

// TypeTag impls — kept separate from the Asn1Value
// blocks above (see type_tag.rs's own module doc for why).
impl crate::type_tag::TypeTag for crate::integer::Integer {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::integer::UInteger {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::integer::BigInteger {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::integer::INTEGER_TAG);
}
impl crate::type_tag::TypeTag for crate::boolean::Boolean {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::boolean::BOOLEAN_TAG);
}
impl crate::type_tag::TypeTag for crate::null::Null {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::null::NULL_TAG);
}
impl crate::type_tag::TypeTag for crate::bit_string::BitString {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::bit_string::BIT_STRING_TAG);
}
impl crate::type_tag::TypeTag for crate::oid::ObjectIdentifier {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::oid::OBJECT_IDENTIFIER_TAG);
}
impl crate::type_tag::TypeTag for crate::relative_oid::RelativeOid {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::relative_oid::RELATIVE_OID_TAG);
}
impl crate::type_tag::TypeTag for crate::real::Real {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::real::REAL_TAG);
}
