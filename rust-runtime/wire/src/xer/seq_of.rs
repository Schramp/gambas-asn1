//! SEQUENCE OF / SET OF XER encode/decode — X.693 §12. Mirrors
//! `SeqOfXerHandler` (`runtime/src/XerCodec.cpp`) — part of the `xer/`
//! module (gambas-asn1#666), not split across `ber/sequence.rs` the way
//! it used to be.
//!
//! Each element is wrapped in a tag, all nested directly inside the
//! member's own `<name>...</name>` (no extra container). Per-element tag
//! shape is delegated to `Asn1Value::xer_encode_seqof_element`
//! (builtin/composite: `<elem_name>content</elem_name>`; ENUMERATED/
//! CHOICE/NULL: their own self-delimiting form, no wrapper) — no codegen
//! decision required here for that split; `name_override` only ever
//! matters to the wrapped-form default.

use crate::ber::reader::DecodeError;
use crate::value::Asn1Value;
use crate::xer::reader::XerReader;
use crate::xer::writer::indent;

pub fn encode_seq_of_xer<V: Asn1Value>(out: &mut String, items: &[V], depth: usize) {
    encode_seq_of_xer_named(out, items, depth, None);
}

/// `name_override` is `Some` for a SEQUENCE OF/SET OF that declared an
/// X.693 §12 element identifier (e.g. `SEQUENCE OF id INTEGER`) — the
/// generated top-level SeqOf newtype's own `xer_encode` passes
/// `SeqOfSpec::elem_xer_name` through here (see `emit_seq_of_definition`,
/// RustBackend.cpp). ENUMERATED/CHOICE/NULL elements ignore it (X.693
/// always uses their own self-delimiting tag regardless — `Generator.cpp`
/// doesn't even set `elem_xer_name` for a NULL element in the first place).
///
/// `depth` is *this collection's own* depth (matching `Asn1Value::
/// xer_encode`'s own "argument = my position" convention). Every element
/// writes its own leading `\n` + indent at `depth + 1`
/// (`Asn1Value::xer_encode_seqof_element`'s own doc) — most kinds add
/// nothing after their own closing tag, relying on the *next* element's
/// leading `\n` (or, for the last element, this function's own trailing
/// bit below) as the separator. CHOICE is the one exception: its own
/// element (`xer_encode_seqof_element`'s CHOICE override) adds a trailing
/// `\n` of its own too, matching `ChoiceXerHandler`'s own unconditional
/// `... << "</" << alt.name << ">\n"` (`runtime/src/XerCodec.cpp`) — when
/// two CHOICE elements sit back to back, that produces a genuine blank
/// line between them (confirmed against a real schema:
/// `Messaging-Property ::= CHOICE` used as a `SET OF` element — not a
/// bug, `SeqOfXerHandler`'s own loop only special-cases *its own* leading
/// newline for a non-CHOICE element, `if (!edef.choice_spec) { ...
/// os << s.indent(1); }`, so two adjacent CHOICE elements each
/// unconditionally contribute their own leading *and* trailing newline
/// with nothing to deduplicate them).
///
/// This function's own trailing bit — `\n` + `indent(depth)`, iff at
/// least one element was written (an empty collection contributes
/// nothing at all, matching `SeqOfXerHandler`'s own `count == 0` case —
/// the caller's `<name></name>` results automatically with no special
/// case needed here, same reasoning `sequence::encode_sequence_xer_content`'s
/// own empty-content case gives) — only adds the `\n` when the last
/// element didn't already end with one (CHOICE's own case): otherwise
/// the two would combine into an unwanted blank line right before the
/// closing tag, which real ground-truth output never has.
pub fn encode_seq_of_xer_named<V: Asn1Value>(out: &mut String, items: &[V], depth: usize, name_override: Option<&str>) {
    let start = out.len();
    for item in items {
        item.xer_encode_seqof_element(out, depth, name_override);
    }
    if out.len() > start {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&indent(depth));
    }
}

pub fn decode_seq_of_xer<V: Asn1Value + Default>(r: &mut XerReader) -> Result<Vec<V>, DecodeError> {
    decode_seq_of_xer_named(r, None)
}

/// Decode counterpart of `encode_seq_of_xer_named`. Loop termination is
/// purely "next tag is a closing tag" (mirrors `SeqOfXerHandler::decode`'s
/// `ti.closing && ti.name == def.name` check — the outer `<name>...</name>`
/// is already consumed by the caller before/after this runs, same as
/// there), not a per-element name comparison: the element's own tag varies
/// per item for ENUMERATED (value name) and CHOICE (chosen alternative),
/// so a fixed-name peek would wrongly stop after the first element.
/// Same in-place-decode shape as `ber::sequence::decode_seq_of_content`'s
/// own doc — `resize_with` constructs each new element directly in
/// `result`, avoiding a separate stack temporary and its move-in `memcpy`.
pub fn decode_seq_of_xer_named<V: Asn1Value + Default>(r: &mut XerReader, name_override: Option<&str>) -> Result<Vec<V>, DecodeError> {
    let mut result: Vec<V> = Vec::new();
    let mut count = 0;
    loop {
        let peeked = r.peek_tag();
        if peeked.closing || peeked.name.is_empty() {
            break;
        }
        if count >= result.len() {
            result.resize_with(count + 1, V::default);
        }
        result[count].xer_decode_into_seqof_element(r, name_override)?;
        count += 1;
    }
    result.truncate(count);
    Ok(result)
}
