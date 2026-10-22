//! Non-generic JER walker for every reflective construct kind — the
//! JER counterpart of `ber::object`.

use crate::ber::reader::DecodeError;
use crate::constraints::{Constraints, UNCONSTRAINED};
use crate::encode_error::EncodeError;
use crate::jer::reader::Reader;
use crate::spec::object::{Asn1Choice, Asn1Pdu, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{jer_decode_primitive, jer_encode_primitive};

/// @brief Writes one value's JER form, dispatching on its reflective shape.
/// @param c  The value's own constraints (a fixed-size BIT STRING has its
///           own JER form; a collection carries its element constraints).
/// @return `Err` for a member or alternative codegen marked unsupported,
///         or a primitive kind with no JER form.
/// @see X.697 — JSON encoding rules.
fn encode_bare(m: MemberRef, c: &Constraints, out: &mut String) -> Result<(), EncodeError> {
    match m {
        MemberRef::Absent => Ok(()),
        MemberRef::Unsupported(msg) => Err(EncodeError::new(msg)),
        MemberRef::Primitive(p) => jer_encode_primitive(p, c, out),
        MemberRef::Contained(v, spec) => encode_contained(v, spec, c, out),
        MemberRef::Composite(inner) => encode_seq_into(inner, out),
        MemberRef::Choice(inner) => encode_choice_into(inner, out),
        MemberRef::SeqOf(inner) => encode_seqof_into(inner, c, out),
        MemberRef::Enumerated(slot, spec) => {
            crate::jer::enumerated::jer_encode_enum(out, spec, slot.enum_get());
            Ok(())
        }
    }
}

fn decode_bare(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    if !matches!(m, MemberRefMut::Composite(_) | MemberRefMut::Choice(_) | MemberRefMut::SeqOf(_)) {
        return decode_bare_level(m, c, r);
    }
    if !r.depth.enter() {
        return Err(DecodeError::new(crate::nesting::too_deep(), r.pos()));
    }
    let res = decode_bare_level(m, c, r);
    r.depth.leave();
    res
}

/// @brief The per-kind decode `decode_bare` dispatches to once it has counted
///        the nesting level a constructed value enters.
fn decode_bare_level(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Unsupported(msg) => Err(DecodeError::new(msg, r.pos())),
        MemberRefMut::Primitive(p) => jer_decode_primitive(p, c, r),
        MemberRefMut::Contained(v, spec) => decode_contained(v, spec, c, r),
        MemberRefMut::Composite(inner) => decode_seq_into(inner, r),
        MemberRefMut::Choice(inner) => decode_choice_into(inner, r),
        MemberRefMut::SeqOf(inner) => decode_seqof_into(inner, c, r),
        MemberRefMut::Enumerated(slot, spec) => crate::jer::enumerated::jer_decode_enum_into(slot, r, spec),
    }
}

/// @brief JER form of a contained field (`Containing<T>`, X.682 §11): a
///        hex string, or `{"containing": <JER of the inner value>}` (X.697
///        §25.4), or that plus `"raw": "<hex>"` (`inline_raw`, an extension).
fn encode_contained(v: &dyn crate::containing::Contained, spec: &'static crate::containing::ContainedSpec, c: &Constraints, out: &mut String) -> Result<(), EncodeError> {
    use crate::containing::{ContainedEncoding, ContainedText};
    let wire = v.wire_octets(spec, ContainedEncoding::Ber);
    let (Some(inner), false) = (v.inner_ref(), spec.jer == ContainedText::Hex) else {
        return jer_encode_primitive(crate::spec::primitive::PrimitiveRef::OctetString(&wire), c, out);
    };
    out.push_str("{\"containing\":");
    encode_bare(inner, &crate::constraints::UNCONSTRAINED, out)?;
    if spec.jer == ContainedText::InlineRaw {
        out.push_str(",\"raw\":\"");
        crate::jer::writer::to_hex_upper(&wire.0, out);
        out.push('"');
    }
    out.push('}');
    Ok(())
}

/// @brief Decode counterpart of [`encode_contained`]; accepts every form.
fn decode_contained(v: &mut dyn crate::containing::Contained, spec: &'static crate::containing::ContainedSpec, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    if r.peek_char() != b'{' {
        let mut os = crate::octet_string::OctetString::default();
        jer_decode_primitive(crate::spec::primitive::PrimitiveRefMut::OctetString(&mut os), c, r)?;
        v.set_raw_from_wire(os.0);
        return Ok(());
    }
    r.expect_char(b'{')?;
    let mut have_inner = false;
    let mut raw = None;
    loop {
        match r.peek_char() {
            b'}' => {
                r.expect_char(b'}')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
            }
            0 => return Err(DecodeError::new("JER: unexpected end in contained value".to_string(), r.pos())),
            _ => {
                let key = r.read_json_string()?;
                r.expect_char(b':')?;
                match key.as_str() {
                    "containing" => {
                        v.inline_decode(&mut |m| decode_bare(m, &crate::constraints::UNCONSTRAINED, r))?;
                        have_inner = true;
                    }
                    "raw" => raw = Some(crate::jer::writer::parse_hex_str(&r.read_json_string()?)),
                    _ => r.skip_json_value()?,
                }
            }
        }
    }
    if !have_inner {
        return Err(DecodeError::new("JER: contained value object without \"containing\"".to_string(), r.pos()));
    }
    v.finish_inline(raw, spec).map_err(|e| DecodeError::new(e, r.pos()))
}

// ---------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------

pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut String) -> Result<(), EncodeError> {
    let spec = obj.spec();
    let mut first = true;
    for (i, m) in spec.members.iter().enumerate() {
        let member = obj.get_member(i);
        if matches!(member, MemberRef::Absent) {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(m.name);
        out.push_str("\":");
        encode_bare(member, m.constraints, out)?;
    }
    Ok(())
}

pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut String) -> Result<(), EncodeError> {
    out.push('{');
    encode_seq_content(obj, out)?;
    out.push('}');
    Ok(())
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> Result<String, EncodeError> {
    let mut out = String::new();
    encode_seq_into(obj, &mut out)?;
    Ok(out)
}

/// Decodes a complete JER object (including its own `{`/`}`) into an
/// already-default-initialized `obj` — scans arbitrary key order, same
/// key-driven scan `jer::sequence`'s own decoder makes.
pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    r.expect_char(b'{')?;
    let member_count = obj.spec().members.len();
    let mut seen = vec![false; member_count];
    loop {
        match r.peek_char() {
            b'}' => {
                r.expect_char(b'}')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
                continue;
            }
            0 => return Err(DecodeError::new("JER: unexpected end in object".to_string(), r.pos())),
            _ => {
                let key = r.read_json_string()?;
                r.expect_char(b':')?;
                let Some(i) = (0..member_count).find(|&i| obj.spec().members[i].name == key) else {
                    r.skip_json_value()?;
                    continue;
                };
                let constraints = obj.spec().members[i].constraints;
                decode_bare(obj.get_member_mut(i), constraints, r)?;
                seen[i] = true;
            }
        }
    }
    for i in 0..member_count {
        if !seen[i] && !obj.spec().members[i].optional {
            return Err(DecodeError::new(format!("JER: missing required member: {}", obj.spec().members[i].name), r.pos()));
        }
    }
    // Contained fields that arrived as hex: decode their inner value.
    if !obj.spec().contained_members.is_empty() {
        crate::containing::decode_contained_members(obj, crate::containing::ContainedEncoding::Ber, r.depth, None)
            .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.pos()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

/// `{"altname":value}` — single-key object, self-delimiting like every
/// other JER value (X.697 §11).
pub fn encode_choice_into(obj: &dyn Asn1Choice, out: &mut String) -> Result<(), EncodeError> {
    let Some(i) = obj.active_index() else {
        return Err(crate::spec::object::no_alternative_selected(obj.spec()));
    };
    let alt = &obj.spec().alternatives[i];
    out.push_str("{\"");
    out.push_str(alt.name);
    out.push_str("\":");
    encode_bare(obj.get_active(), alt.constraints, out)?;
    out.push('}');
    Ok(())
}

pub fn decode_choice_into(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    r.expect_char(b'{')?;
    if r.peek_char() == b'}' {
        r.expect_char(b'}')?;
        return Ok(());
    }
    let key = r.read_json_string()?;
    r.expect_char(b':')?;
    for (i, alt) in obj.spec().alternatives.iter().enumerate() {
        if key == alt.name {
            let constraints = alt.constraints;
            decode_bare(obj.select_mut(i), constraints, r)?;
            r.expect_char(b'}')?;
            return crate::containing::decode_contained_alternative(obj, crate::containing::ContainedEncoding::Ber, r.depth, None)
                .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.pos()));
        }
    }
    Err(DecodeError::new(format!("JER: CHOICE: unknown alternative: {key}"), r.pos()))
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

/// @param c  The collection's own constraints; its `element` entry
///           applies to every element.
pub fn encode_seqof_into(obj: &dyn Asn1SeqOf, c: &Constraints, out: &mut String) -> Result<(), EncodeError> {
    let elem = c.element.unwrap_or(&UNCONSTRAINED);
    out.push('[');
    for i in 0..obj.len() {
        if i > 0 {
            out.push(',');
        }
        encode_bare(obj.get(i), elem, out)?;
    }
    out.push(']');
    Ok(())
}

/// @param c  The collection's own constraints, as `encode_seqof_into`.
pub fn decode_seqof_into(obj: &mut dyn Asn1SeqOf, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    let elem = c.element.unwrap_or(&UNCONSTRAINED);
    r.expect_char(b'[')?;
    loop {
        match r.peek_char() {
            b']' => {
                r.expect_char(b']')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
                continue;
            }
            0 => return Err(DecodeError::new("JER: unexpected end in array".to_string(), r.pos())),
            _ => decode_bare(obj.push_default_mut(), elem, r)?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Top-level (document root) entry points
// ---------------------------------------------------------------------

/// @brief Encodes `v` as a complete JER document. JER has no root
///        wrapper, so this is exactly the value's own JSON encoding.
/// @param v  Any generated SEQUENCE/SET/CHOICE/SEQUENCE OF type.
/// @return The JSON text, or `Err` when `v` holds a value this runtime
///         cannot encode in JER.
/// @see X.697 §8 — top-level JSON value.
pub fn encode_pdu<T: Asn1Pdu + ?Sized>(v: &T) -> Result<String, EncodeError> {
    let mut out = String::new();
    encode_bare(v.as_member_ref(), T::PDU_CONSTRAINTS, &mut out)?;
    Ok(out)
}

/// @brief Decodes a complete JER document into a fresh `T`.
/// @return The decoded value, or `Err` on malformed JSON or a shape
///         mismatch.
/// @see X.697 §8.
pub fn decode_pdu<T: Asn1Pdu>(json: &str) -> Result<T, DecodeError> {
    let mut v = T::default();
    decode_bare(v.as_member_ref_mut(), T::PDU_CONSTRAINTS, &mut Reader::new(json))?;
    Ok(v)
}
