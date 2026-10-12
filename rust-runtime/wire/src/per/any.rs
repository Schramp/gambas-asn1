//! X.691 §10.2 "Open type fields": length-prefixed raw octets, no
//! bit-packing — mirrors `AnyPerHandler` (`runtime/src/PerCodec.cpp`) and
//! asn1c's own `ANY_encode_uper` exactly. Legacy ANY (X.208) has no
//! defined type of its own, so PER treats its captured content the same
//! way it treats an unknown CHOICE extension alternative's payload.

use crate::per::length::{get_length, put_length};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode(bytes: &[u8], w: &mut Writer) {
    put_length(w, bytes.len());
    for b in bytes {
        w.put_bits(*b as u64, 8);
    }
}

pub fn decode(r: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    let len = get_length(r)?;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(r.get_bits(8)? as u8);
    }
    Ok(bytes)
}
