//! XER OBJECT IDENTIFIER encode/decode — X.680 §32. Mirrors
//! `OidXerHandler`'s content model (`runtime/include/asn1cpp/codec/
//! XerCodec.hpp`'s `format_arcs`/`parse_arcs`): dotted-decimal arcs,
//! e.g. `2.5.4.3`. Deliberately not shared with `xer::relative_oid`'s
//! near-identical formatter (same arc-joining text, different types,
//! same accepted duplication the BER leg already has between
//! `oid::encode_arc`/`decode_arc` and `relative_oid::encode_arc`/
//! `decode_arc` — RELATIVE-OID gets its own type, not a shared generic
//! one, by this crate's existing "distinct type per ASN.1 kind"
//! convention).

use crate::ber::reader::DecodeError;
use crate::oid::ObjectIdentifier;
use crate::xer::reader::XerReader;

pub fn encode(value: &ObjectIdentifier, out: &mut String) {
    for (i, arc) in value.0.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&arc.to_string());
    }
}

pub fn decode_into(value: &mut ObjectIdentifier, r: &mut XerReader) -> Result<(), DecodeError> {
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
