//! ENUMERATED -- X.697 §8.28 analogue (quoted identifier string, bare
//! number fallback for an unrecognized value on encode -- can't happen
//! on decode, see below). Mirrors `EnumeratedJerHandler`
//! (`runtime/src/JerCodec.cpp`); calling convention mirrors
//! `xer_encode_enum`/`xer_decode_enum` (`ber/enumerated.rs`) exactly.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::spec::enumerated::EnumSpec;

pub fn jer_encode_enum(out: &mut String, spec: &EnumSpec, value: i64) {
    match spec.entries.iter().find(|e| e.value == value) {
        Some(e) => {
            out.push('"');
            out.push_str(e.name);
            out.push('"');
        }
        // Unreachable in practice -- a real Rust enum instance can only
        // ever hold a value `T::try_from` already accepted -- kept for
        // parity with the C++ reference's own defensive fallback.
        None => out.push_str(&value.to_string()),
    }
}

pub fn jer_decode_enum<T: TryFrom<i64>>(r: &mut Reader, spec: &EnumSpec) -> Result<T, DecodeError> {
    r.skip_ws();
    let raw: i64 = if r.peek_char() == b'"' {
        let name = r.read_json_string()?;
        spec.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.value)
            .ok_or_else(|| DecodeError::new(format!("JER: unknown enum value: {name}"), r.pos()))?
    } else {
        let tok = r.read_json_token()?;
        tok.parse()
            .map_err(|_| DecodeError::new(format!("JER: invalid ENUMERATED: {tok}"), r.pos()))?
    };
    T::try_from(raw).map_err(|_| DecodeError::new(format!("JER: invalid ENUMERATED value: {raw}"), r.pos()))
}
