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
    fn ber_natural_tag(&self) -> crate::tag::Tag;

    /// Writes just the TLV value octets (X.690 §8.1.3) — no tag, no length.
    fn ber_encode_content(&self, out: &mut Vec<u8>);

    /// Parses value octets already extracted from a TLV (tag/length already
    /// consumed and checked by the caller) into `self`.
    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError>;

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
    fn ber_encode_tagged(&self, tag: crate::tag::Tag, out: &mut Vec<u8>) {
        let mut content = Vec::new();
        self.ber_encode_content(&mut content);
        crate::writer::write_primitive(out, tag, &content);
    }

    /// Decode counterpart of `ber_encode_tagged`.
    fn ber_decode_into_tagged(&mut self, r: &mut Reader, tag: crate::tag::Tag) -> Result<(), DecodeError> {
        let tlv = r.read_tlv()?;
        if tlv.tag != tag {
            return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
        }
        self.ber_decode_content(tlv.value)
    }

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

    /// This value's own X.693 §12 element name — the tag a SEQUENCE OF/SET
    /// OF wraps each element in (`sequence::encode_seq_of_xer`/
    /// `decode_seq_of_xer`). Mirrors C++'s `SeqOfXerHandler` reaching
    /// `spec.element->name` on the element's own `TypeDescriptor` — the
    /// same generic "ask the value for its own name" access, done via a
    /// trait method here since Rust has no descriptor object to point at.
    /// A builtin type's own fixed X.680 keyword (e.g. `"INTEGER"`) for a
    /// direct builtin element; a generated composite type overrides this
    /// with its own real ASN.1 type name.
    fn xer_element_name(&self) -> &'static str {
        "Value"
    }

    /// Render this value as one SEQUENCE OF/SET OF element (X.693 §12/§9.3)
    /// — mirrors the dispatch the C++ runtime's `SeqOfXerHandler` does by
    /// inspecting the element's `TypeDescriptor` (`edef.enum_spec`,
    /// `spec.element_xer_tag`) before calling `codec.encode` generically.
    /// The default wraps `xer_encode`'s content in `<name>...</name>`,
    /// `name` being `name_override` when the collection declared one
    /// (X.693 §12 identifier, e.g. `SEQUENCE OF id INTEGER`) or else this
    /// value's own `xer_element_name()`. ENUMERATED and CHOICE override
    /// this to forward straight to `xer_encode` with no wrapper at all —
    /// both already write a complete self-delimiting tag of their own
    /// (a bare `<value-name/>`, or the chosen alternative's own tag) and
    /// X.693 always uses that in place of any wrapper/identifier, mirroring
    /// `SeqOfXerHandler`'s `edef.enum_spec` early-out and `ChoiceXerHandler`
    /// having no outer wrapper either. `()` (NULL) overrides similarly:
    /// `NullXerHandler` self-closes exactly when asked to write under the
    /// literal name `"NULL"`, which is what an unnamed NULL element's own
    /// `edef.name` always is — `Generator::emit_sequence_definition`
    /// (Generator.cpp) never populates `SeqOfSpec::elem_xer_name` for a
    /// NULL element in the first place, so `name_override` is always
    /// `None` for NULL in practice, but the override ignores it either way
    /// for the same reason ENUMERATED/CHOICE do.
    fn xer_encode_seqof_element(&self, out: &mut String, name_override: Option<&str>) {
        let name = name_override.unwrap_or_else(|| self.xer_element_name());
        crate::xer::write_open_tag(out, name);
        self.xer_encode(out);
        crate::xer::write_close_tag(out, name);
    }

    /// Decode counterpart of `xer_encode_seqof_element`. Default consumes
    /// `<name>...</name>` (`name_override` or `xer_element_name()`) around
    /// a normal `xer_decode_into`; ENUMERATED/CHOICE/NULL override to
    /// forward straight to `xer_decode_into`, same reasoning as the encode
    /// leg. Callers (`sequence::decode_seq_of_xer_named`) always invoke
    /// this on an already-`V::default()`-constructed instance, so
    /// `self.xer_element_name()` is safe to read before `xer_decode_into`
    /// overwrites `self` with the real decoded value.
    fn xer_decode_into_seqof_element(&mut self, r: &mut XerReader, name_override: Option<&str>) -> Result<(), DecodeError> {
        let owned;
        let name = match name_override {
            Some(n) => n,
            None => {
                owned = self.xer_element_name().to_string();
                owned.as_str()
            }
        };
        r.consume_open_tag(name)?;
        self.xer_decode_into(r)?;
        r.consume_close_tag(name)?;
        Ok(())
    }
}

/// EXPLICIT tagging (X.690 §8.14.3), generic over any
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

/// EXPLICIT-wrapped ANY (X.208 legacy type; ANY has no fixed tag of its
/// own, so a `[n] ANY` member is always EXPLICIT even under IMPLICIT/
/// AUTOMATIC TAGS — same exception CHOICE gets, X.680 §30.6/§30.7).
/// Unlike `encode_explicit`/`decode_explicit`, not generic over
/// `Asn1Value`: ANY's content is whatever raw bytes are on the wire, not a
/// typed decode — `raw` is captured/replayed verbatim, tag and all.
pub fn encode_explicit_any(out: &mut Vec<u8>, tag: crate::tag::Tag, raw: &[u8]) {
    crate::writer::write_explicit(out, tag, |inner| inner.extend_from_slice(raw));
}

pub fn decode_explicit_any(r: &mut Reader, tag: crate::tag::Tag) -> Result<Vec<u8>, DecodeError> {
    crate::reader::read_explicit(r, tag, |inner| Ok(inner.remaining().to_vec()))
}

/// OPTIONAL member support. An `Option<V>` field (what
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

    // The tag depends only on `V`'s type, never its value.
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        V::default().ber_natural_tag()
    }

    fn xer_element_name(&self) -> &'static str {
        V::default().xer_element_name()
    }

    // Not reached: `ber_encode_tagged`/`ber_decode_into_tagged` are
    // overridden below, since `None` must write no TLV at all (X.690 §8.1
    // has no "empty header" — content-only can't express "no header").
    // Kept as a correct fallback in case anything calls these directly.
    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        if let Some(v) = self {
            v.ber_encode_content(out);
        }
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        let mut v = V::default();
        v.ber_decode_content(content)?;
        *self = Some(v);
        Ok(())
    }

    fn ber_encode_tagged(&self, tag: crate::tag::Tag, out: &mut Vec<u8>) {
        if let Some(v) = self {
            v.ber_encode_tagged(tag, out);
        }
    }

    fn ber_decode_into_tagged(&mut self, r: &mut Reader, tag: crate::tag::Tag) -> Result<(), DecodeError> {
        let mut v = V::default();
        v.ber_decode_into_tagged(r, tag)?;
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
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::integer::INTEGER_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "INTEGER"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::integer::encode_integer_bytes(*self));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::integer::decode_integer_bytes(content)?;
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

/// Wide-range INTEGER storage (a constrained range whose bound exceeds
/// i64::MAX/MIN — `IntStorageKind::U64`/`I128`, `RustBackend::native_int_type`).
/// XER leg is plain decimal text, same shape as `i64`'s own impl below,
/// just unsigned.
impl Asn1Value for u64 {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::integer::INTEGER_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "INTEGER"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::integer::encode_integer_bytes_u64(*self));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::integer::decode_integer_bytes_u64(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        out.push_str(&self.to_string());
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        *self = text.trim().parse::<u64>().map_err(|_| {
            DecodeError::new(format!("XER: invalid INTEGER value: {text}"), 0)
        })?;
        Ok(())
    }
}

/// i128 analogue of the `u64` impl above.
impl Asn1Value for i128 {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::integer::INTEGER_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "INTEGER"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::integer::encode_integer_bytes_i128(*self));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::integer::decode_integer_bytes_i128(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        out.push_str(&self.to_string());
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        *self = text.trim().parse::<i128>().map_err(|_| {
            DecodeError::new(format!("XER: invalid INTEGER value: {text}"), 0)
        })?;
        Ok(())
    }
}

/// Mirrors `BooleanXerHandler` (`runtime/src/XerCodec.cpp`) — BASIC-XER's
/// `EmptyElementBoolean` form: content is a nested self-closing `<true/>`/
/// `<false/>` tag, not text (X.693 §8.2's default form). `xer_decode_into`
/// also accepts EXTENDED-XER §10 TextBoolean (plain `"true"`/`"false"`
/// content) when `XerReader::lenient()` is set — the non-standard asn1c
/// extension `XerDecodeMode::Lenient` allows on the C++ side.
impl Asn1Value for bool {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::boolean::BOOLEAN_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "BOOLEAN"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&crate::boolean::encode_boolean_content(*self));
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::boolean::decode_boolean_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        out.push_str(if *self { "<true/>" } else { "<false/>" });
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        // EXTENDED-XER §10 TextBoolean ("true"/"false" as plain content) is
        // a non-standard asn1c extension, only accepted in lenient mode —
        // detect it by trying to read text content first: the standard
        // empty-element form (`<true/>`/`<false/>`) has none (the reader
        // sits directly on `<`), so an empty result falls through to the
        // tag path unchanged.
        let text = r.read_text_content().trim();
        if !text.is_empty() {
            if !r.lenient() {
                return Err(DecodeError::new("XER BOOLEAN: expected <true/> or <false/>".to_string(), 0));
            }
            return match text {
                "true" => { *self = true; Ok(()) }
                "false" => { *self = false; Ok(()) }
                _ => Err(DecodeError::new("XER BOOLEAN: expected true or false".to_string(), 0)),
            };
        }
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

/// Maps ASN.1 NULL — `native_builtin_type`'s `()` choice,
/// `RustBackend.cpp`. Mirrors `NullXerHandler`'s named-wrapper form
/// (`runtime/src/XerCodec.cpp`): empty content inside the member's own
/// `<name></name>` tag, e.g. `<flag></flag>` — the self-closing `<NULL/>`
/// form that same handler emits only applies when the *type's own name* is
/// literally "NULL" (a raw top-level/SEQUENCE-OF-element descriptor, an
/// asn1c-compat quirk), never a member's field-name-derived tag, so
/// `Asn1Value` (member-embedded content only, per this trait's own doc
/// comment) never needs that branch.
impl Asn1Value for () {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::null::NULL_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "NULL"
    }

    fn ber_encode_content(&self, _out: &mut Vec<u8>) {
        // Empty content — nothing to write.
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        crate::null::decode_null_content(content)
    }

    fn xer_encode(&self, _out: &mut String) {
        // Empty content — nothing to write.
    }

    fn xer_decode_into(&mut self, _r: &mut XerReader) -> Result<(), DecodeError> {
        // Empty content — nothing to consume.
        Ok(())
    }

    // X.693: a NULL SEQUENCE OF/SET OF element self-closes as `<NULL/>`,
    // ignoring any declared X.693 §12 identifier (mirrors `NullXerHandler`
    // self-closing exactly when asked to write under the literal name
    // `"NULL"` — see the trait default's own doc for why `name_override`
    // is always `None` here in practice anyway).
    fn xer_encode_seqof_element(&self, out: &mut String, _name_override: Option<&str>) {
        out.push_str("<NULL/>");
    }

    fn xer_decode_into_seqof_element(&mut self, r: &mut XerReader, _name_override: Option<&str>) -> Result<(), DecodeError> {
        let ti = r.consume_tag();
        if ti.name != "NULL" || ti.closing {
            return Err(DecodeError::new("XER: expected <NULL>".to_string(), 0));
        }
        if !ti.self_closing {
            let close = r.consume_tag();
            if !close.closing || close.name != "NULL" {
                return Err(DecodeError::new("XER: expected </NULL>".to_string(), 0));
            }
        }
        Ok(())
    }
}

/// Maps ASN.1 OCTET STRING (`native_builtin_type`'s `Vec<u8>` choice,
/// `RustBackend.cpp`). Mirrors `OctetStringXerHandler`'s default (non-Base64)
/// encoding: unspaced uppercase hex pairs (`write_hex_bytes`,
/// `runtime/src/HexEncoder.hpp`) — distinct from BIT STRING/hex-string
/// types' *spaced* hex (`format_hex_bytes`), not implemented by this crate.
impl Asn1Value for Vec<u8> {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::octet_string::OCTET_STRING_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "OCTET_STRING"
    }

    // OCTET STRING content octets *are* the value bytes — no encoding step.
    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = content.to_vec();
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
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::bit_string::BIT_STRING_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "BIT_STRING"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::bit_string::encode_bit_string_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::bit_string::decode_bit_string_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        let total = self.bit_count();
        for i in 0..total {
            let bit = (self.bytes[i / 8] >> (7 - (i % 8))) & 1;
            out.push(if bit == 1 { '1' } else { '0' });
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        let mut content = String::with_capacity(text.len());
        let mut has_hex = false;
        for c in text.chars() {
            if c.is_whitespace() {
                continue;
            }
            match c {
                '0' | '1' => {}
                _ if c.is_ascii_hexdigit() => has_hex = true,
                _ => return Err(DecodeError::new(format!("XER: invalid BIT STRING character '{c}'"), 0)),
            }
            content.push(c);
        }
        if has_hex && !r.lenient() {
            return Err(DecodeError::new(
                "XER: hex BIT STRING requires lenient mode (non-standard extension)".to_string(),
                0,
            ));
        }
        if has_hex {
            // Non-standard asn1c extension: hex pairs, one byte each, 0
            // unused bits (no production for this in X.680 §21's
            // XMLBitStringValue grammar).
            if content.len() % 2 != 0 {
                return Err(DecodeError::new("XER: odd-length hex BIT STRING".to_string(), 0));
            }
            let cbytes = content.as_bytes();
            let mut bytes = Vec::with_capacity(cbytes.len() / 2);
            let mut i = 0;
            while i < cbytes.len() {
                let hi = (cbytes[i] as char).to_digit(16).unwrap() as u8;
                let lo = (cbytes[i + 1] as char).to_digit(16).unwrap() as u8;
                bytes.push((hi << 4) | lo);
                i += 2;
            }
            *self = crate::bit_string::BitString { bytes, unused_bits: 0 };
            return Ok(());
        }
        let mut bytes = Vec::new();
        let mut cur = 0u8;
        let mut bit_count = 0usize;
        for c in content.chars() {
            let bit = if c == '1' { 1u8 } else { 0u8 };
            cur = (cur << 1) | bit;
            bit_count += 1;
            if bit_count % 8 == 0 {
                bytes.push(cur);
                cur = 0;
            }
        }
        let unused_bits = if bit_count % 8 == 0 {
            0
        } else {
            let pad = 8 - (bit_count % 8);
            cur <<= pad;
            bytes.push(cur);
            pad as u8
        };
        *self = crate::bit_string::BitString { bytes, unused_bits };
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
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::oid::OBJECT_IDENTIFIER_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "OBJECT_IDENTIFIER"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::oid::encode_object_identifier_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::oid::decode_object_identifier_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                out.push('.');
            }
            out.push_str(&arc.to_string());
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        let mut arcs = Vec::new();
        for part in text.trim().split('.') {
            if part.is_empty() {
                break;
            }
            match part.parse::<u64>() {
                Ok(v) => arcs.push(v),
                Err(_) => break,
            }
        }
        *self = crate::oid::ObjectIdentifier(arcs);
        Ok(())
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
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::relative_oid::RELATIVE_OID_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "RELATIVE_OID"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::relative_oid::encode_relative_oid_content(out, self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::relative_oid::decode_relative_oid_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                out.push('.');
            }
            out.push_str(&arc.to_string());
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let text = r.read_text_content();
        let mut arcs = Vec::new();
        for part in text.trim().split('.') {
            if part.is_empty() {
                break;
            }
            match part.parse::<u64>() {
                Ok(v) => arcs.push(v),
                Err(_) => break,
            }
        }
        *self = crate::relative_oid::RelativeOid(arcs);
        Ok(())
    }
}

/// Maps ASN.1 REAL — `native_builtin_type`'s `f64`
/// choice, `RustBackend.cpp`. Mirrors `RealXerHandler`'s content model
/// (`runtime/src/XerCodec.cpp`): special values as nested self-closing
/// tags (`<PLUS-INFINITY/>`/`<MINUS-INFINITY/>`/`<NOT-A-NUMBER/>` — same
/// shape as `bool`'s `<true/>`/`<false/>`), `0`/`-0` as the literal text
/// `"0"`, everything else as `%.15f` with trailing zeros trimmed (keeping
/// at least one digit after the decimal point).
impl Asn1Value for f64 {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::real::REAL_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "REAL"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        crate::real::encode_real_content(out, *self);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::real::decode_real_value(content, 0)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String) {
        if self.is_nan() {
            out.push_str("<NOT-A-NUMBER/>");
        } else if self.is_infinite() {
            out.push_str(if *self > 0.0 { "<PLUS-INFINITY/>" } else { "<MINUS-INFINITY/>" });
        } else if *self == 0.0 {
            out.push('0');
        } else {
            let mut buf = format!("{self:.15}");
            if let Some(dot) = buf.find('.') {
                let mut last = buf.len() - 1;
                while last > dot + 1 && buf.as_bytes()[last] == b'0' {
                    last -= 1;
                }
                buf.truncate(last + 1);
            }
            out.push_str(&buf);
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        let peek = r.peek_tag();
        if !peek.name.is_empty() {
            let ti = r.consume_tag();
            *self = match ti.name.as_str() {
                "PLUS-INFINITY" => f64::INFINITY,
                "MINUS-INFINITY" => f64::NEG_INFINITY,
                "NOT-A-NUMBER" => f64::NAN,
                _ => {
                    return Err(DecodeError::new(
                        format!("XER: unknown REAL special value: {}", ti.name),
                        0,
                    ))
                }
            };
            if !ti.self_closing {
                let close = r.consume_tag();
                if !close.closing || close.name != ti.name {
                    return Err(DecodeError::new("XER: malformed REAL special value".to_string(), 0));
                }
            }
            return Ok(());
        }
        let text = r.read_text_content();
        let trimmed = text.trim();
        *self = trimmed
            .parse::<f64>()
            .map_err(|_| DecodeError::new(format!("XER: invalid REAL value: {trimmed}"), 0))?;
        Ok(())
    }
}

/// Maps `IA5String` (`native_builtin_type`'s `String` choice covers all 12
/// string kinds; this impl is scoped to IA5String's wire tag specifically,
/// see `strings.rs`'s module doc on widening to the others). Mirrors
/// `XerStringHandler`: escaped text content, via `xer::escape`/`xer::unescape`.
impl Asn1Value for String {
    fn ber_natural_tag(&self) -> crate::tag::Tag {
        crate::strings::IA5_STRING_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "IA5String"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        *self = crate::strings::decode_string_content(content, "IA5String")?;
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

/// `Box<T>` forwarding — the heap indirection `RustBackend` gives a
/// self-referential/mutually-recursive member (`SequenceMemberSpec::
/// member_type_in_cycle`, `RustBackend.cpp`; Rust gives a plain field no
/// indirection at all unlike C++'s pointer-by-default `unique_ptr`, so a
/// genuine recursive ASN.1 type chain needs one explicitly or the struct
/// has infinite size) is purely a Rust ownership/storage concern — the
/// wire representation is identical to `T` itself, so every method just
/// forwards through the box.
impl<T: Asn1Value> Asn1Value for Box<T> {
    fn is_present(&self) -> bool {
        (**self).is_present()
    }

    fn ber_natural_tag(&self) -> crate::tag::Tag {
        (**self).ber_natural_tag()
    }

    fn xer_element_name(&self) -> &'static str {
        (**self).xer_element_name()
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        (**self).ber_encode_content(out)
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        (**self).ber_decode_content(content)
    }

    fn ber_encode(&self, out: &mut Vec<u8>) {
        (**self).ber_encode(out)
    }

    fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
        (**self).ber_decode_into(r)
    }

    fn ber_encode_tagged(&self, tag: crate::tag::Tag, out: &mut Vec<u8>) {
        (**self).ber_encode_tagged(tag, out)
    }

    fn ber_decode_into_tagged(&mut self, r: &mut Reader, tag: crate::tag::Tag) -> Result<(), DecodeError> {
        (**self).ber_decode_into_tagged(r, tag)
    }

    fn xer_encode(&self, out: &mut String) {
        (**self).xer_encode(out)
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        (**self).xer_decode_into(r)
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
        use crate::xer::{write_close_tag, write_open_tag};

        // 1010 0000, 4 unused bits -> logical bits "1010" (bit_count=4).
        // Padding bits are zero here deliberately: XER only carries the
        // logical bit sequence (bit_count), zero-filling padding on decode
        // (X.680's XMLBitStringValue captures no padding-bit-value
        // information) — a fixture with *non-zero* padding wouldn't
        // round-trip byte-for-byte through XER, which is expected, not a bug.
        let v = BitString { bytes: vec![0b1010_0000], unused_bits: 4 };
        let mut out = String::new();
        write_open_tag(&mut out, "flags");
        v.xer_encode(&mut out);
        write_close_tag(&mut out, "flags");
        assert_eq!(out, "<flags>1010</flags>");

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
        use crate::xer::{write_close_tag, write_open_tag};

        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        let mut out = String::new();
        write_open_tag(&mut out, "oid");
        v.xer_encode(&mut out);
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
        use crate::xer::{write_close_tag, write_open_tag};

        let v = RelativeOid(vec![8571, 1]);
        let mut out = String::new();
        write_open_tag(&mut out, "roid");
        v.xer_encode(&mut out);
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
        1.5f64.ber_encode(&mut out);

        let mut r = Reader::new(&out);
        let mut got: f64 = 0.0;
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag};

        let mut out = String::new();
        write_open_tag(&mut out, "x");
        1.5f64.xer_encode(&mut out);
        write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1.5</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let mut got: f64 = 0.0;
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("x").unwrap();
        assert_eq!(got, 1.5);
    }

    #[test]
    fn f64_xer_zero_encodes_as_bare_zero() {
        let mut out = String::new();
        0.0f64.xer_encode(&mut out);
        assert_eq!(out, "0");

        let mut out2 = String::new();
        (-0.0f64).xer_encode(&mut out2);
        assert_eq!(out2, "0");
    }

    #[test]
    fn f64_xer_special_values_round_trip() {
        for v in [f64::INFINITY, f64::NEG_INFINITY] {
            let mut out = String::new();
            v.xer_encode(&mut out);
            let mut r = XerReader::new(&out);
            let mut got: f64 = 0.0;
            got.xer_decode_into(&mut r).unwrap();
            assert_eq!(got, v);
        }

        let mut out = String::new();
        f64::NAN.xer_encode(&mut out);
        assert_eq!(out, "<NOT-A-NUMBER/>");
        let mut r = XerReader::new(&out);
        let mut got: f64 = 0.0;
        got.xer_decode_into(&mut r).unwrap();
        assert!(got.is_nan());
    }

    #[test]
    fn f64_xer_trims_trailing_zeros_but_keeps_one_digit() {
        let mut out = String::new();
        2.0f64.xer_encode(&mut out);
        assert_eq!(out, "2.0");
    }

    #[test]
    fn f64_xer_invalid_text_is_error() {
        let mut r = XerReader::new("not-a-number");
        let mut got: f64 = 0.0;
        assert!(got.xer_decode_into(&mut r).is_err());
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
    fn bool_xer_lenient_accepts_text_content() {
        let mut r = XerReader::new_lenient("true");
        let mut got = false;
        got.xer_decode_into(&mut r).unwrap();
        assert!(got);

        let mut r = XerReader::new_lenient("false");
        let mut got = true;
        got.xer_decode_into(&mut r).unwrap();
        assert!(!got);
    }

    #[test]
    fn bool_xer_lenient_still_accepts_empty_element_form() {
        let mut r = XerReader::new_lenient("<true/>");
        let mut got = false;
        got.xer_decode_into(&mut r).unwrap();
        assert!(got);
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

    #[test]
    fn explicit_any_captures_the_wrapped_bytes_verbatim() {
        // The wrapped "value" here is itself a full INTEGER TLV — ANY's
        // whole point is to capture that unparsed, tag and all.
        let inner_tlv = [0x02u8, 0x01, 0x2A]; // INTEGER 42
        let mut buf = Vec::new();
        encode_explicit_any(&mut buf, crate::tag::Tag::context(1, true), &inner_tlv);
        assert_eq!(buf, vec![0xA1, 0x03, 0x02, 0x01, 0x2A]);

        let mut r = Reader::new(&buf);
        let got = decode_explicit_any(&mut r, crate::tag::Tag::context(1, true)).unwrap();
        assert_eq!(got, inner_tlv);
    }

    #[test]
    fn explicit_any_rejects_wrong_wrapper_tag() {
        let mut buf = Vec::new();
        encode_explicit_any(&mut buf, crate::tag::Tag::context(1, true), &[0x02, 0x01, 0x2A]);

        let mut r = Reader::new(&buf);
        assert!(decode_explicit_any(&mut r, crate::tag::Tag::context(2, true)).is_err());
    }

    // ---- generic IMPLICIT retagging (ber_encode_tagged/ber_decode_into_tagged) ----

    #[test]
    fn tagged_matching_natural_tag_is_identical_to_plain_encode() {
        let mut a = Vec::new();
        42i64.ber_encode(&mut a);
        let mut b = Vec::new();
        42i64.ber_encode_tagged(crate::integer::INTEGER_TAG, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn tagged_substitutes_the_tag_for_a_scalar() {
        let context_0 = crate::tag::Tag::context(0, false);
        let mut out = Vec::new();
        42i64.ber_encode_tagged(context_0, &mut out);
        assert_eq!(out, vec![0x80, 0x01, 0x2A]); // context primitive 0, not universal INTEGER (0x02)

        let mut r = Reader::new(&out);
        let mut got: i64 = 0;
        got.ber_decode_into_tagged(&mut r, context_0).unwrap();
        assert_eq!(got, 42);
    }

    #[test]
    fn tagged_substitutes_the_tag_for_a_constructed_value() {
        // BitString isn't constructed, but exercise a real non-trivial
        // multi-byte value to make sure content bytes survive the
        // splice-and-resplice untouched.
        use crate::bit_string::BitString;
        let v = BitString { bytes: vec![0b1010_1000, 0xFF], unused_bits: 2 };
        let context_3 = crate::tag::Tag::context(3, false);
        let mut out = Vec::new();
        v.ber_encode_tagged(context_3, &mut out);
        assert_eq!(out[0], 0x83); // context primitive 3

        let mut r = Reader::new(&out);
        let mut got = BitString::default();
        got.ber_decode_into_tagged(&mut r, context_3).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn tagged_decode_rejects_wrong_tag() {
        let context_0 = crate::tag::Tag::context(0, false);
        let context_1 = crate::tag::Tag::context(1, false);
        let mut out = Vec::new();
        42i64.ber_encode_tagged(context_0, &mut out);

        let mut r = Reader::new(&out);
        let mut got: i64 = 0;
        assert!(got.ber_decode_into_tagged(&mut r, context_1).is_err());
    }

    // ---- Option<V> through the tagged path -----------------------------
    //
    // A `None` optional member with an IMPLICIT tag override must write
    // *nothing at all* — not a zero-length TLV under the override tag. This
    // can't be expressed by the default content+tag composition (there's no
    // way to say "write no header"), so `Option<V>` overrides
    // `ber_encode_tagged`/`ber_decode_into_tagged` directly rather than
    // relying on `ber_encode_content` — this test is the regression guard
    // for that override existing at all.

    #[test]
    fn none_through_tagged_path_writes_nothing() {
        let v: Option<i64> = None;
        let context_0 = crate::tag::Tag::context(0, false);
        let mut out = Vec::new();
        v.ber_encode_tagged(context_0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn some_through_tagged_path_round_trips() {
        let v: Option<i64> = Some(7);
        let context_0 = crate::tag::Tag::context(0, false);
        let mut out = Vec::new();
        v.ber_encode_tagged(context_0, &mut out);
        assert_eq!(out, vec![0x80, 0x01, 0x07]); // context primitive 0, not universal INTEGER

        let mut r = Reader::new(&out);
        let mut got: Option<i64> = None;
        got.ber_decode_into_tagged(&mut r, context_0).unwrap();
        assert_eq!(got, Some(7));
    }
}
