//! X.691 §24/§10.2 "Open type fields" analogue for RELATIVE-OID — see
//! `per::oid`'s doc for why this stays a separate module instead of
//! sharing code with it.

use crate::per::length::{get_octets, put_octets};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::relative_oid::RelativeOid;

pub fn encode(value: &RelativeOid, w: &mut Writer) {
    let mut content = Vec::new();
    crate::relative_oid::encode_relative_oid_content(&mut content, value);
    put_octets(w, &content);
}

pub fn decode_into(value: &mut RelativeOid, r: &mut Reader) -> Result<(), DecodeError> {
    let content = get_octets(r)?;
    *value = crate::relative_oid::decode_relative_oid_content(&content)
        .map_err(|e| DecodeError::new(e.message, r.bit_pos()))?;
    Ok(())
}
