//! Non-generic JER walker for every reflective construct kind — the
//! JER counterpart of `ber::object`.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::spec::object::{Asn1Choice, Asn1Pdu, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{jer_decode_primitive, jer_encode_primitive};

fn encode_bare(m: MemberRef, out: &mut String) {
    match m {
        MemberRef::Absent => {}
        MemberRef::Primitive(p) => jer_encode_primitive(p, out),
        MemberRef::Composite(inner) => encode_seq_into(inner, out),
        MemberRef::Choice(inner) => encode_choice_into(inner, out),
        MemberRef::SeqOf(inner) => encode_seqof_into(inner, out),
        MemberRef::Enumerated(slot, spec) => crate::jer::enumerated::jer_encode_enum(out, spec, slot.enum_get()),
    }
}

fn decode_bare(m: MemberRefMut, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => jer_decode_primitive(p, r),
        MemberRefMut::Composite(inner) => decode_seq_into(inner, r),
        MemberRefMut::Choice(inner) => decode_choice_into(inner, r),
        MemberRefMut::SeqOf(inner) => decode_seqof_into(inner, r),
        MemberRefMut::Enumerated(slot, spec) => crate::jer::enumerated::jer_decode_enum_into(slot, r, spec),
    }
}

// ---------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------

pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut String) {
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
        encode_bare(member, out);
    }
}

pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut String) {
    out.push('{');
    encode_seq_content(obj, out);
    out.push('}');
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> String {
    let mut out = String::new();
    encode_seq_into(obj, &mut out);
    out
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
                decode_bare(obj.get_member_mut(i), r)?;
                seen[i] = true;
            }
        }
    }
    for i in 0..member_count {
        if !seen[i] && !obj.spec().members[i].optional {
            return Err(DecodeError::new(format!("JER: missing required member: {}", obj.spec().members[i].name), r.pos()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

/// `{"altname":value}` — single-key object, self-delimiting like every
/// other JER value (X.697 §11).
pub fn encode_choice_into(obj: &dyn Asn1Choice, out: &mut String) {
    let Some(i) = obj.active_index() else {
        out.push_str("{}");
        return;
    };
    let alt = &obj.spec().alternatives[i];
    out.push_str("{\"");
    out.push_str(alt.name);
    out.push_str("\":");
    encode_bare(obj.get_active(), out);
    out.push('}');
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
            decode_bare(obj.select_mut(i), r)?;
            r.expect_char(b'}')?;
            return Ok(());
        }
    }
    Err(DecodeError::new(format!("JER: CHOICE: unknown alternative: {key}"), r.pos()))
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

pub fn encode_seqof_into(obj: &dyn Asn1SeqOf, out: &mut String) {
    out.push('[');
    for i in 0..obj.len() {
        if i > 0 {
            out.push(',');
        }
        encode_bare(obj.get(i), out);
    }
    out.push(']');
}

pub fn decode_seqof_into(obj: &mut dyn Asn1SeqOf, r: &mut Reader) -> Result<(), DecodeError> {
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
            _ => decode_bare(obj.push_default_mut(), r)?,
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
/// @return The JSON text.
/// @see X.697 §8 — top-level JSON value.
pub fn encode_pdu<T: Asn1Pdu + ?Sized>(v: &T) -> String {
    let mut out = String::new();
    encode_bare(v.as_member_ref(), &mut out);
    out
}

/// @brief Decodes a complete JER document into a fresh `T`.
/// @return The decoded value, or `Err` on malformed JSON or a shape
///         mismatch.
/// @see X.697 §8.
pub fn decode_pdu<T: Asn1Pdu>(json: &str) -> Result<T, DecodeError> {
    let mut v = T::default();
    decode_bare(v.as_member_ref_mut(), &mut Reader::new(json))?;
    Ok(v)
}
