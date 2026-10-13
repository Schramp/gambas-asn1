//! X.691 §23/§10.2 "Open type fields": length-prefixed raw BER content
//! bytes, no bit-packing — mirrors `OidPerHandler`
//! (`runtime/src/PerCodec.cpp`, `per_detail::encode_ber_content<Oid>`)
//! exactly.

use crate::oid::ObjectIdentifier;
use crate::per::length::{get_length, put_length};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode(value: &ObjectIdentifier, w: &mut Writer) {
    let mut content = Vec::new();
    crate::oid::encode_object_identifier_content(&mut content, value);
    put_length(w, content.len());
    for b in content {
        w.put_bits(b as u64, 8);
    }
}

pub fn decode_into(value: &mut ObjectIdentifier, r: &mut Reader) -> Result<(), DecodeError> {
    let len = get_length(r)?;
    let mut content = Vec::with_capacity(len);
    for _ in 0..len {
        content.push(r.get_bits(8)? as u8);
    }
    *value = crate::oid::decode_object_identifier_content(&content)
        .map_err(|e| DecodeError::new(e.message, r.bit_pos()))?;
    Ok(())
}
