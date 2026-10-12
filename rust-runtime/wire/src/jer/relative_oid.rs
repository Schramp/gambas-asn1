//! X.697 §8.14 analogue for RELATIVE-OID — see `jer::oid`'s doc for why
//! this stays a separate module instead of sharing code with it.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::relative_oid::RelativeOid;

pub fn encode(value: &RelativeOid, out: &mut String) {
    out.push('"');
    for (i, arc) in value.0.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&arc.to_string());
    }
    out.push('"');
}

pub fn decode_into(value: &mut RelativeOid, r: &mut Reader<'_>) -> Result<(), DecodeError> {
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
