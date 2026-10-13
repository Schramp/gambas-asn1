//! X.691 §10.2 "Open type fields": length-prefixed raw octets, no
//! bit-packing — mirrors `AnyPerHandler` (`runtime/src/PerCodec.cpp`) and
//! asn1c's own `ANY_encode_uper` exactly. Legacy ANY (X.208) has no
//! defined type of its own, so PER treats its captured content the same
//! way it treats an unknown CHOICE extension alternative's payload.

use crate::per::length::{get_octets, put_octets};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode(bytes: &[u8], w: &mut Writer) {
    put_octets(w, bytes);
}

pub fn decode(r: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    get_octets(r)
}
