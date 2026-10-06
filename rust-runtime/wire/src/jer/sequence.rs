//! SEQUENCE/SET -- X.697 §9. `{"member":value,...}`; absent OPTIONAL
//! members are omitted entirely (not `null`). Mirrors `SequenceJerHandler`
//! (`runtime/src/JerCodec.cpp`).
//!
//! Unlike XER's decode (`decode_sequence_xer_content`, `xer.rs`), which
//! can assume canonical member order and peek-match sequentially, JER
//! decode scans arbitrary key order (JSON objects have no mandated
//! order) -- this mirrors the C++ reference's own key-driven scan
//! exactly: read a key, look it up in the member table by name
//! (matches in any position), skip unknown keys, error on a required
//! member never seen.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::spec::sequence::{MemberAccess, SequenceSpec};

fn encode_sequence_jer_content<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String) {
    let mut first = true;
    for m in spec.members {
        // JER has no tag/explicit-wrap concept -- every access kind
        // just needs the member's own `jer_encode`, full stop.
        let val = match &m.access {
            MemberAccess::Scalar { get, .. }
            | MemberAccess::TaggedScalar { get, .. }
            | MemberAccess::ExplicitScalar { get, .. }
            | MemberAccess::Base64Scalar { get, .. } => get(value),
            MemberAccess::Unsupported { reason, .. } => panic!("member '{}' not supported: {}", m.name, reason),
        };
        if !val.is_present() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(m.name);
        out.push_str("\":");
        val.jer_encode(out);
    }
}

pub fn encode_sequence_jer_into<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String) {
    out.push('{');
    encode_sequence_jer_content(spec, value, out);
    out.push('}');
}

pub fn encode_sequence_jer<T>(spec: &SequenceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    encode_sequence_jer_into(spec, value, &mut out);
    out
}

/// Decodes a SEQUENCE's complete JER value, including its own `{`/`}` --
/// unlike XER (where a generic parent-level walker consumes each
/// member's open/close tag around calling its `xer_decode_into`, so a
/// nested type's own method never touches tags), JER's object braces
/// aren't a separable "wrapper" a generic caller can peel off first --
/// every JER value (including a nested SEQUENCE-typed member) is
/// self-delimiting JSON, so this one function is both the top-level
/// entry point (`decode_sequence_jer`) and what a generated type's own
/// `Asn1Value::jer_decode_into` calls directly for a nested member.
pub fn decode_sequence_jer_into<T: Default>(spec: &SequenceSpec<T>, r: &mut Reader) -> Result<T, DecodeError> {
    r.expect_char(b'{')?;
    let mut result = T::default();
    let mut seen = vec![false; spec.members.len()];
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
                let Some((idx, m)) = spec.members.iter().enumerate().find(|(_, m)| m.name == key) else {
                    r.skip_json_value()?;
                    continue;
                };
                match &m.access {
                    MemberAccess::Scalar { get_mut, .. }
                    | MemberAccess::TaggedScalar { get_mut, .. }
                    | MemberAccess::ExplicitScalar { get_mut, .. }
                    | MemberAccess::Base64Scalar { get_mut, .. } => {
                        get_mut(&mut result).jer_decode_into(r)?;
                    }
                    MemberAccess::Unsupported { reason, .. } => panic!("member '{}' not supported: {}", m.name, reason),
                }
                seen[idx] = true;
            }
        }
    }
    for (i, m) in spec.members.iter().enumerate() {
        if !seen[i] && !m.optional {
            return Err(DecodeError::new(format!("JER: missing required member: {}", m.name), r.pos()));
        }
    }
    Ok(result)
}

pub fn decode_sequence_jer<T: Default>(spec: &SequenceSpec<T>, json: &str) -> Result<T, DecodeError> {
    let mut r = Reader::new(json);
    decode_sequence_jer_into(spec, &mut r)
}
