//! XER RELATIVE-OID encode/decode — X.680 §33. Same dotted-decimal arc
//! grammar `xer::oid` uses (RELATIVE-OID just skips OID's first-two-arc
//! combining rule, which is purely a BER concern anyway) — see
//! `xer::oid`'s own doc for why this isn't a shared formatter.

use crate::ber::reader::DecodeError;
use crate::relative_oid::RelativeOid;
use crate::xer::reader::XerReader;

pub fn encode(value: &RelativeOid, out: &mut String) {
    for (i, arc) in value.0.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&arc.to_string());
    }
}

pub fn decode_into(value: &mut RelativeOid, r: &mut XerReader) -> Result<(), DecodeError> {
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
    value.0 = arcs;
    Ok(())
}
