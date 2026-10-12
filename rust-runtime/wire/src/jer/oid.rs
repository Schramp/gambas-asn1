//! X.697 §8.14: quoted dotted-decimal string — same arc text
//! `xer::oid` formats, just JSON-quoted. Kept as its own module rather
//! than shared with `jer::relative_oid` despite near-identical logic, for
//! the same reason `xer::oid`/`xer::relative_oid` stay separate (see that
//! module's own doc).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::oid::ObjectIdentifier;

pub fn encode(value: &ObjectIdentifier, out: &mut String) {
    out.push('"');
    for (i, arc) in value.0.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&arc.to_string());
    }
    out.push('"');
}

pub fn decode_into(value: &mut ObjectIdentifier, r: &mut Reader<'_>) -> Result<(), DecodeError> {
    let text = r.read_json_string()?;
    let mut arcs = Vec::new();
    for part in text.split('.') {
        if part.is_empty() {
            break;
        }
        match part.parse::<u64>() {
            Ok(v) => arcs.push(v),
            Err(_) => break,
        }
    }
    value.0 = arcs;
    Ok(())
}
