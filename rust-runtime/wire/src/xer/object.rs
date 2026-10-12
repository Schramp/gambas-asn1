//! Non-generic XER walker for every reflective construct kind — the
//! XER counterpart of `ber::object`. No BER tag concept applies here
//! (X.693 names elements by field, not by wire tag), so
//! `MemberMeta::ber`/`AltMeta::ber` are simply ignored.

use crate::ber::reader::DecodeError;
use crate::spec::object::{Asn1Choice, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut, XerInstruction};
use crate::spec::primitive::{xer_decode_primitive, xer_encode_primitive, PrimitiveRef, PrimitiveRefMut};
use crate::value::Asn1Value;
use crate::xer::reader::XerReader;
use crate::xer::writer::{indent, write_close_tag, write_open_tag};

/// Writes a value's own content with no wrapper tag at all — the shape
/// every kind's own `xer_encode` has on its own (a composite recurses
/// into its own member loop, a CHOICE into its own alternative tag,
/// ...). `encode_wrapped` below adds the *caller's* own field/element
/// name around this. No BASE64/UTF8 instruction applies here — those
/// are read off the row before this is ever called (`encode_wrapped`'s
/// own doc).
fn encode_bare(m: MemberRef, out: &mut String, depth: usize) {
    match m {
        MemberRef::Absent => {}
        MemberRef::Primitive(p) => xer_encode_primitive(p, out, depth),
        MemberRef::Composite(inner) => encode_seq_content(inner, out, depth),
        MemberRef::Choice(inner) => encode_choice_content(inner, out, depth),
        MemberRef::SeqOf(inner) => encode_seqof_content(inner, out, depth),
        MemberRef::Enumerated(slot, spec) => crate::ber::enumerated::xer_encode_enum(out, spec, slot.enum_get()),
    }
}

/// Writes one SEQUENCE/SET member's content, wrapped in `name`'s open/
/// close tags (X.693 names a member by its own field, X.680 §11.15/§24).
/// A CHOICE-typed member gets the same field-name wrapper as every other
/// kind — matching `SequenceXerHandler`'s own member-wrapping (the
/// *alternative's* own name nests one level further inside, written by
/// `encode_choice_content`, not instead of this wrapper.
///
/// `instruction`: `MemberMeta::xer_instruction` — table data, read by
/// the *caller*, not a separate
/// `MemberRef` shape. Only a plain `Primitive(PrimitiveRef::OctetString)`
/// payload ever has a non-`Default` instruction (`RustBackend`'s
/// `xer_instruction` lambda only sets one for an OCTET STRING); every
/// other call site passes `XerInstruction::Default` and falls straight
/// through to `encode_bare`.
fn encode_wrapped(name: &str, instruction: XerInstruction, m: MemberRef, out: &mut String, depth: usize) {
    if matches!(m, MemberRef::Absent) {
        return;
    }
    let is_choice = matches!(m, MemberRef::Choice(_));
    out.push('\n');
    out.push_str(&indent(depth));
    write_open_tag(out, name);
    match (instruction, &m) {
        (XerInstruction::Base64, MemberRef::Primitive(PrimitiveRef::OctetString(x))) => x.xer_encode_base64(out),
        (XerInstruction::Utf8, MemberRef::Primitive(PrimitiveRef::OctetString(x))) => x.xer_encode_utf8(out),
        _ => encode_bare(m, out, depth),
    }
    if is_choice {
        // Mirrors the old per-type `Asn1Value::xer_encode` override for
        // CHOICE, which added this same trailing bit after
        // `encode_choice_xer_into` — every other kind's own content
        // already ends at the right place for `write_close_tag` to
        // follow directly.
        out.push('\n');
        out.push_str(&indent(depth));
    }
    write_close_tag(out, name);
}

/// Member-loop content, no outer `<name>`/`</name>` wrapper — see
/// `xer::sequence::encode_sequence_xer_content`'s own doc for the exact
/// contract this mirrors (depth convention, empty-SEQUENCE case).
pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut String, depth: usize) {
    let spec = obj.spec();
    let mut any = false;
    for (i, m) in spec.members.iter().enumerate() {
        let member = obj.get_member(i);
        if matches!(member, MemberRef::Absent) {
            continue;
        }
        any = true;
        encode_wrapped(m.name, m.xer_instruction, member, out, depth + 1);
    }
    if any {
        out.push('\n');
        out.push_str(&indent(depth));
    }
}

pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut String, depth: usize) {
    encode_seq_content(obj, out, depth);
}

/// X.693 §8.3.1 document-root wrapper for any top-level `Asn1Value` —
/// `encode_seq`/`encode_choice` below are this same shape specialized to
/// `Asn1Seq`/`Asn1Choice`; a top-level named SEQUENCE OF/SET OF type has
/// neither (its own `xer_encode` — `encode_seq_of_xer` — only writes the
/// per-element content, same "no wrapper tag of its own" convention
/// every kind's bare `xer_encode` follows, `encode_bare`'s own doc), so
/// it's the one top-level kind that needs this generic form instead.
pub fn encode_value(obj: &dyn Asn1Value) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, obj.xer_element_name());
    obj.xer_encode(&mut out, 0);
    write_close_tag(&mut out, obj.xer_element_name());
    out.push('\n');
    out
}

/// Decode counterpart of `encode_value`.
pub fn decode_value_into(obj: &mut dyn Asn1Value, r: &mut XerReader) -> Result<(), DecodeError> {
    let name = obj.xer_element_name();
    r.consume_open_tag(name)?;
    obj.xer_decode_into(r)?;
    r.consume_close_tag(name)?;
    Ok(())
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, obj.spec().name);
    encode_seq_content(obj, &mut out, 0);
    write_close_tag(&mut out, obj.spec().name);
    out.push('\n');
    out
}

/// Decodes a SEQUENCE/SET's XER member-loop content into an already-
/// default-initialized `obj` — peek-match on the next open tag's name,
/// same canonical-order assumption `xer::sequence`'s own decoder makes.
pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut XerReader) -> Result<(), DecodeError> {
    let member_count = obj.spec().members.len();
    for i in 0..member_count {
        let (name, optional, instruction) = {
            let m = &obj.spec().members[i];
            (m.name, m.optional, m.xer_instruction)
        };
        if optional {
            let peeked = r.peek_tag();
            if peeked.closing || peeked.name != name {
                continue;
            }
        }
        r.consume_open_tag(name)?;
        decode_instructed(instruction, obj.get_member_mut(i), r)?;
        r.consume_close_tag(name)?;
    }
    Ok(())
}

fn decode_bare(m: MemberRefMut, r: &mut XerReader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => xer_decode_primitive(p, r),
        MemberRefMut::Composite(inner) => decode_seq_content_into(inner, r),
        MemberRefMut::Choice(inner) => decode_choice_content_into(inner, r),
        MemberRefMut::SeqOf(inner) => decode_seqof_content_into(inner, r),
        MemberRefMut::Enumerated(slot, spec) => crate::ber::enumerated::xer_decode_enum_into(slot, r, spec),
    }
}

/// Decode counterpart of `encode_wrapped`'s instruction check.
fn decode_instructed(instruction: XerInstruction, m: MemberRefMut, r: &mut XerReader) -> Result<(), DecodeError> {
    match (instruction, m) {
        (XerInstruction::Base64, MemberRefMut::Primitive(PrimitiveRefMut::OctetString(x))) => x.xer_decode_into_base64(r),
        (XerInstruction::Utf8, MemberRefMut::Primitive(PrimitiveRefMut::OctetString(x))) => x.xer_decode_into_utf8(r),
        (_, m) => decode_bare(m, r),
    }
}

pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut XerReader) -> Result<(), DecodeError> {
    r.consume_open_tag(obj.spec().name)?;
    decode_seq_content_into(obj, r)?;
    r.consume_close_tag(obj.spec().name)?;
    Ok(())
}

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

/// Writes `\n<indent><altname>content</altname>`, no trailing newline —
/// the shape a containing member's own wrapper (`encode_wrapped`) or a
/// further-nested nested nested recursion needs. `pub` (not just crate-
/// internal) so a generated type's thin `Asn1Value::xer_encode` forwarder
/// (used only by an external caller invoking the trait method directly —
/// the generated SEQUENCE/CHOICE walkers always go through `MemberRef`
/// instead) can reach it.
pub fn encode_choice_content(obj: &dyn Asn1Choice, out: &mut String, depth: usize) {
    let Some(i) = obj.active_index() else {
        panic!("encode_choice: no alternative matched — codegen/table mismatch");
    };
    let alt = &obj.spec().alternatives[i];
    let active = obj.get_active();
    // A CHOICE-typed alternative (nested CHOICE-of-CHOICE, e.g. a
    // self-referential `RecChoice ::= CHOICE { c RecChoice, a INTEGER }`)
    // needs the same trailing `\n` + indent before closing its own tag
    // that `encode_wrapped`'s `is_choice` case adds one level up — every
    // other alternative kind's own content already ends at the right
    // place for the close tag to follow directly.
    let is_nested_choice = matches!(active, MemberRef::Choice(_));
    let mut inner = String::new();
    encode_bare(active, &mut inner, depth + 1);
    if is_nested_choice {
        inner.push('\n');
        inner.push_str(&indent(depth + 1));
    }
    out.push('\n');
    out.push_str(&indent(depth + 1));
    write_open_tag(out, alt.name);
    out.push_str(&inner);
    write_close_tag(out, alt.name);
}

/// X.693 §8.3.1 document-root wrapper — only the top-level
/// `encode_xer()` entry point uses this; a nested CHOICE member/element
/// uses `encode_choice_content` (via `encode_bare`) directly, no type
/// name wrapper.
pub fn encode_choice(obj: &dyn Asn1Choice) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, obj.spec().name);
    encode_choice_content(obj, &mut out, 0);
    // Matches `encode_seq`'s own closing convention (and the
    // ground-truth C++ runtime's `SequenceXerHandler`/`ChoiceXerHandler`
    // document-root form): the closing tag sits on its own, un-indented
    // line, not glued onto the chosen alternative's own closing tag.
    out.push('\n');
    write_close_tag(&mut out, obj.spec().name);
    out.push('\n');
    out
}

/// `pub` for the same reason as `encode_choice_content` above.
pub fn decode_choice_content_into(obj: &mut dyn Asn1Choice, r: &mut XerReader) -> Result<(), DecodeError> {
    let ti = r.peek_tag();
    for (i, alt) in obj.spec().alternatives.iter().enumerate() {
        if ti.name == alt.name {
            let open = r.consume_tag();
            if open.name != alt.name || open.closing {
                return Err(DecodeError::new(format!("XER: expected <{}>", alt.name), 0));
            }
            decode_bare(obj.select_mut(i), r)?;
            if !open.self_closing {
                r.consume_close_tag(alt.name)?;
            }
            return Ok(());
        }
    }
    Err(DecodeError::new(format!("XER: unknown CHOICE alternative: {}", ti.name), 0))
}

pub fn decode_choice(xml: &str, obj: &mut dyn Asn1Choice) -> Result<(), DecodeError> {
    let mut r = XerReader::new(xml);
    r.consume_open_tag(obj.spec().name)?;
    decode_choice_content_into(obj, &mut r)?;
    r.consume_close_tag(obj.spec().name)?;
    Ok(())
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

/// X.693 §12: each element wrapped in a tag, all nested directly inside
/// the containing member's own `<name>...</name>` (no extra container).
/// A primitive element uses its own natural XER name; a composite
/// element its own type name; CHOICE/ENUMERATED self-delimit (no
/// wrapper, matching their own standalone form) — same per-kind split
/// `xer::seq_of`'s own doc documents for the old design.
pub(crate) fn encode_seqof_content(obj: &dyn Asn1SeqOf, out: &mut String, depth: usize) {
    let name_override = obj.elem_xer_name();
    let mut any = false;
    for i in 0..obj.len() {
        let el = obj.get(i);
        if matches!(el, MemberRef::Absent) {
            continue;
        }
        any = true;
        match &el {
            // NULL self-closes as `<NULL/>` as a SEQUENCE OF/SET OF
            // element (X.693; `value.rs`'s `Asn1Value::
            // xer_encode_seqof_element` override for `Null` has the
            // exact same shape) — ignoring any X.693 §12 element
            // identifier, same as that override's own doc.
            MemberRef::Primitive(PrimitiveRef::Null(_)) => {
                out.push('\n');
                out.push_str(&indent(depth + 1));
                out.push_str("<NULL/>");
            }
            // `obj.elem_natural_xer_name(i)`, not `xer_element_name_of(*p)`:
            // `p`/`x` here are already unwrapped to the element's native
            // field (`AsMemberRef`'s own doc) — for an aliased element
            // (a named INTEGER/builtin alias, X.680 §19) that's the
            // *wrapped* type's generic name ("INTEGER"), not the alias's
            // own override ("TimeslotISCP") — `elem_natural_xer_name`
            // reads the un-unwrapped element's own `Asn1Value::
            // xer_element_name()` directly (`Asn1SeqOf`'s own doc).
            // SEQUENCE OF/SET OF elements carry no metadata row at all
            // (X.690 §8.9.2 — always the element's own natural tag,
            // repeated), so there's nowhere to read a BASE64/UTF8
            // override from even if an aliased element declared one;
            // always `Default`.
            MemberRef::Primitive(_) => encode_wrapped(name_override.unwrap_or_else(|| obj.elem_natural_xer_name(i)), XerInstruction::Default, el, out, depth + 1),
            MemberRef::Composite(inner) => {
                let name = name_override.unwrap_or(inner.spec().name);
                encode_wrapped(name, XerInstruction::Default, el, out, depth + 1)
            }
            MemberRef::Choice(_) | MemberRef::Enumerated(..) => {
                out.push('\n');
                out.push_str(&indent(depth + 1));
                encode_bare(el, out, depth + 1);
            }
            MemberRef::SeqOf(inner) => {
                let name = name_override.unwrap_or(inner.own_xer_name());
                encode_wrapped(name, XerInstruction::Default, el, out, depth + 1)
            }
            MemberRef::Absent => unreachable!(),
        }
    }
    if any {
        out.push('\n');
        out.push_str(&indent(depth));
    }
}

pub(crate) fn decode_seqof_content_into(obj: &mut dyn Asn1SeqOf, r: &mut XerReader) -> Result<(), DecodeError> {
    loop {
        let peeked = r.peek_tag();
        if peeked.closing {
            return Ok(());
        }
        let el = obj.push_default_mut();
        match el {
            MemberRefMut::Choice(_) | MemberRefMut::Enumerated(..) => decode_bare(el, r)?,
            MemberRefMut::Primitive(PrimitiveRefMut::Null(_)) => {
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
            }
            _ => {
                let name = peeked.name.to_string();
                r.consume_open_tag(&name)?;
                decode_bare(el, r)?;
                r.consume_close_tag(&name)?;
            }
        }
    }
}
