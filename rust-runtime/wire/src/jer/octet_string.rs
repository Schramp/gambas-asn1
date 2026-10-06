//! OCTET STRING -- X.697 §8.9. Quoted uppercase hex, no spaces (not
//! base64). Mirrors `OctetStringJerHandler` (`runtime/src/JerCodec.cpp`).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::jer::writer::{parse_hex_str, to_hex_upper};

pub fn encode(bytes: &[u8], out: &mut String) {
    out.push('"');
    to_hex_upper(bytes, out);
    out.push('"');
}

pub fn decode(r: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    let hex = r.read_json_string()?;
    Ok(parse_hex_str(&hex))
}
