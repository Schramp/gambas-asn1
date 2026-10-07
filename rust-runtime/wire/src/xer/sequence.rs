//! SEQUENCE XER encode/decode — X.693. Mirrors `SequenceXerHandler`
//! (`runtime/src/XerCodec.cpp`), table-driven off the *same*
//! `SequenceSpec<T>`/`MemberDescriptor<T>` table `ber::sequence`'s BER leg
//! already uses (one table drives both wire formats, see `lib.rs`'s crate
//! doc) — part of the `xer/` module (gambas-asn1#666), not split across
//! `ber/sequence.rs` the way it used to be.

use crate::ber::reader::DecodeError;
use crate::spec::sequence::{MemberAccess, SequenceSpec};
use crate::xer::reader::XerReader;
use crate::xer::writer::{indent, write_close_tag, write_open_tag};

/// Member-loop content of a SEQUENCE's XER encoding, without the outer
/// `<name>`/`</name>` wrapper — shared by `encode_sequence_xer` (the type's
/// own name) and, once a generated SEQUENCE/SET type has its own
/// `Asn1Value` impl, by a *member*'s field-name-derived wrapper instead
/// (XER tags are always field-derived, never type-derived — see `reader`'s
/// own module doc — so a nested composite member's inner content is
/// exactly this loop, wrapped in the *member's* tag by the caller, same
/// contract `Asn1Value::xer_encode` already documents for every other type).
///
/// OPTIONAL suppression: an absent member is skipped entirely (no
/// `<member></member>` pair), via `Asn1Value::is_present` — unlike BER,
/// XER's outer element tag is this walker's own responsibility, not
/// something `Option<V>::xer_encode` can suppress by itself.
///
/// `depth` is *this SEQUENCE's own* depth — the level its own wrapper tag
/// sits at (`Asn1Value::xer_encode`'s own "argument = my position"
/// convention, matching the C++ runtime's `XerEncodeStream::depth()`
/// exactly). Each present member is written one level deeper (`depth + 1`,
/// `writer::indent`), and if that member's own value is itself composite
/// (SEQUENCE/CHOICE/SeqOf/SetOf), *its* content recurses at `depth + 1`
/// too. An empty SEQUENCE (no present members) contributes nothing at
/// all — `<Name></Name>` results automatically once the caller's own
/// open/close tags are placed back to back, matching `SequenceXerHandler`'s
/// own `!any_present` early return with no special case needed here.
fn encode_sequence_xer_content<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String, depth: usize) {
    let mut any = false;
    for m in spec.members {
        match &m.access {
            // TaggedScalar reuses Scalar's get here: XER
            // element tags are always field-name-derived, never
            // type-derived, so the BER-only tag override doesn't apply.
            MemberAccess::Scalar { get, .. } | MemberAccess::TaggedScalar { get, .. } | MemberAccess::ExplicitScalar { get, .. } => {
                let val = get(value);
                if !val.is_present() {
                    continue;
                }
                any = true;
                out.push('\n');
                out.push_str(&indent(depth + 1));
                write_open_tag(out, m.name);
                val.xer_encode(out, depth + 1);
                write_close_tag(out, m.name);
            }
            MemberAccess::Base64Scalar { get, .. } => {
                let val = get(value);
                if !val.is_present() {
                    continue;
                }
                any = true;
                out.push('\n');
                out.push_str(&indent(depth + 1));
                write_open_tag(out, m.name);
                val.xer_encode_base64(out);
                write_close_tag(out, m.name);
            }
            // ANY has no defined XER form here — `Any`'s own `xer_encode`
            // uses `Asn1Value`'s default (`unimplemented!`), reached
            // through the combined `Scalar`/`TaggedScalar`/`ExplicitScalar`
            // arm above only if this member is actually written.
            MemberAccess::Unsupported { reason, .. } => panic!("member '{}' not supported: {}", m.name, reason),
        }
    }
    if any {
        out.push('\n');
        out.push_str(&indent(depth));
    }
}

pub fn encode_sequence_xer<T>(spec: &SequenceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, spec.name);
    encode_sequence_xer_content(spec, value, &mut out, 0);
    write_close_tag(&mut out, spec.name);
    out.push('\n');
    out
}

/// Appends a SEQUENCE's XER content (no outer wrapper) to an existing
/// buffer — the shape `Asn1Value::xer_encode` needs (writes only inner
/// content, wrapper is the caller's job) so a generated SEQUENCE/SET type
/// can implement that trait leg and become usable as a nested composite
/// member, same role `ber::sequence::encode_sequence_into` plays for the
/// BER leg.
pub fn encode_sequence_xer_into<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String, depth: usize) {
    encode_sequence_xer_content(spec, value, out, depth);
}

/// Generic SEQUENCE XER decoder — the XER analogue of
/// `ber::sequence::decode_sequence` and the Rust equivalent of
/// `SequenceXerHandler::decode`. `T::default()` provides the initial
/// value, each member is decoded in table order directly into its field.
///
/// OPTIONAL members: peek the next open tag's name before
/// consuming it — if it doesn't match this member's own element name, the
/// member is absent (leave it at its `Default`, i.e. `None`) and nothing is
/// consumed, same linear-scan/canonical-order assumption `decode_sequence`'s
/// BER leg documents.
fn decode_sequence_xer_content<T: Default>(spec: &SequenceSpec<T>, r: &mut XerReader) -> Result<T, DecodeError> {
    let mut result = T::default();
    for m in spec.members {
        if m.optional {
            let peeked = r.peek_tag();
            if peeked.closing || peeked.name != m.name {
                continue;
            }
        }
        r.consume_open_tag(m.name)?;
        match &m.access {
            MemberAccess::Scalar { get_mut, .. } | MemberAccess::TaggedScalar { get_mut, .. } | MemberAccess::ExplicitScalar { get_mut, .. } =>
                get_mut(&mut result).xer_decode_into(r)?,
            MemberAccess::Base64Scalar { get_mut, .. } => get_mut(&mut result).xer_decode_into_base64(r)?,
            MemberAccess::Unsupported { reason, .. } => panic!("member '{}' not supported: {}", m.name, reason),
        }
        r.consume_close_tag(m.name)?;
    }
    Ok(result)
}

pub fn decode_sequence_xer<T: Default>(spec: &SequenceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new(xml);
    r.consume_open_tag(spec.name)?;
    let result = decode_sequence_xer_content(spec, &mut r)?;
    r.consume_close_tag(spec.name)?;
    Ok(result)
}

/// `decode_sequence_xer`, but accepting the non-standard asn1c extensions
/// `XerReader::new_lenient` does (hex BIT STRING, text BOOLEAN) — not
/// wired into any generated type's own `decode_xer` (codegen has no way to
/// know which callers need leniency), so callers that do reach for this
/// directly, spec in hand (e.g. cross-validating against an asn1c-authored
/// fixture that uses those extensions).
pub fn decode_sequence_xer_lenient<T: Default>(spec: &SequenceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new_lenient(xml);
    r.consume_open_tag(spec.name)?;
    let result = decode_sequence_xer_content(spec, &mut r)?;
    r.consume_close_tag(spec.name)?;
    Ok(result)
}

/// Reads a SEQUENCE's XER content (no outer wrapper — already consumed by
/// the caller, same contract `Asn1Value::xer_decode_into` documents) from
/// the caller's current reader position — the shape that trait leg needs
/// so a generated SEQUENCE/SET type can implement it and become usable as
/// a nested composite member, same role `ber::sequence::decode_sequence_from`
/// plays for the BER leg.
pub fn decode_sequence_xer_from<T: Default>(spec: &SequenceSpec<T>, r: &mut XerReader) -> Result<T, DecodeError> {
    decode_sequence_xer_content(spec, r)
}
