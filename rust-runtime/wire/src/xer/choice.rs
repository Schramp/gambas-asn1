//! CHOICE XER encode/decode — X.693 §8.3.1. Mirrors `ChoiceXerHandler`
//! (`runtime/src/XerCodec.cpp`), table-driven off the same `ChoiceSpec<T>`
//! `ber::choice`'s BER leg uses — part of the `xer/` module
//! (gambas-asn1#666), not split across `ber/choice.rs` the way it used to
//! be.
//!
//! A CHOICE has no outer wrapper *as a SEQUENCE/SET/CHOICE member* —
//! X.690 §8.13.1: "the value is that of the chosen alternative", so the
//! wire tag IS the chosen alternative's own tag; `ChoiceXerHandler`
//! confirms the same in XER for the member case (encodes/decodes using
//! the *alternative's* name, never the CHOICE type's own name — no
//! `<Choice>` wrapper the way `SequenceXerHandler` wraps every member in
//! `<Widget>`). But X.693 §8.3.1 requires the XML *document element* —
//! the outermost value in a standalone encoding — to always be an
//! "XMLTypedValue" (`<TypeName>...</TypeName>`), CHOICE included
//! (confirmed against real asn1c output: a root-level `Alt4` value
//! encodes as `<Alt4>\n<str>j</str>\n</Alt4>`, not bare `<str>j</str>`).
//! `encode_choice_xer`/`decode_choice_xer` (the top-level, non-`_into`
//! entry points a generated CHOICE's own `encode_xer()`/`decode_xer()`
//! call) are the only place this wrapper applies — the `_into` variants
//! used for nested/member CHOICE stay wrapper-free.

use crate::ber::reader::DecodeError;
use crate::spec::choice::{active_alt, AlternativeAccess, ChoiceSpec};
use crate::spec::primitive::{xer_decode_primitive, xer_encode_primitive};
use crate::xer::reader::XerReader;
use crate::xer::writer::{indent, write_close_tag, write_open_tag};

/// Generic CHOICE XER encoder, top-level entry point (a generated CHOICE's
/// own `.encode_xer()`): the X.693 §8.3.1 document-element wrapper around
/// `encode_choice_xer_into` at depth 0.
pub fn encode_choice_xer<T>(spec: &ChoiceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, spec.name);
    encode_choice_xer_into(spec, value, &mut out, 0);
    out.push('\n');
    write_close_tag(&mut out, spec.name);
    out.push('\n');
    out
}

/// Writes the chosen alternative as `\n<indent><name>payload</name>`, no
/// trailing newline. The wrapper is always paired, never self-closing
/// (matches `NullXerHandler::encode`); `decode_choice_xer_into` still
/// accepts a self-closing `<a/>` on input, as asn1c's own decoder does.
pub fn encode_choice_xer_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut String, depth: usize) {
    if let Some((_, alt)) = active_alt(spec, value) {
        let mut inner = String::new();
        match &alt.access {
            AlternativeAccess::Primitive { get, .. } => xer_encode_primitive(get(value), &mut inner, depth + 1),
            AlternativeAccess::Composite { xer_encode, .. } => xer_encode(value, &mut inner, depth + 1),
            AlternativeAccess::Unsupported { reason } => panic!("alternative '{}' not supported: {reason}", alt.name),
        }
        out.push('\n');
        out.push_str(&indent(depth + 1));
        write_open_tag(out, alt.name);
        out.push_str(&inner);
        write_close_tag(out, alt.name);
        return;
    }
    panic!("encode_choice_xer_into: no alternative matched — codegen/table mismatch");
}

pub fn decode_choice_xer<T: Default>(spec: &ChoiceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new(xml);
    r.consume_open_tag(spec.name)?;
    let mut v = T::default();
    decode_choice_xer_into(spec, &mut v, &mut r)?;
    r.consume_close_tag(spec.name)?;
    Ok(v)
}

/// XER dispatches by element *name* (`ChoiceXerHandler` peeks the tag name),
/// not by wire tag.
pub fn decode_choice_xer_into<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut XerReader) -> Result<(), DecodeError> {
    let ti = r.peek_tag();
    for alt in spec.alternatives {
        if ti.name == alt.name {
            // Tolerate a self-closing alternative tag (`<name/>`), as every
            // C++ XER handler does; the payload decode is content-only.
            let open = r.consume_tag();
            if open.name != alt.name || open.closing {
                return Err(DecodeError::new(format!("XER: expected <{}>", alt.name), 0));
            }
            match &alt.access {
                AlternativeAccess::Primitive { get_mut, .. } => xer_decode_primitive(get_mut(value), r)?,
                AlternativeAccess::Composite { xer_decode, .. } => xer_decode(value, r)?,
                AlternativeAccess::Unsupported { reason } => panic!("alternative '{}' not supported: {reason}", alt.name),
            }
            if !open.self_closing {
                r.consume_close_tag(alt.name)?;
            }
            return Ok(());
        }
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative element <{}>", ti.name), 0))
}
