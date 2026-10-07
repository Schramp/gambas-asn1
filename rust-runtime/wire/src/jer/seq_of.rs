//! SEQUENCE OF / SET OF -- X.697 §10. `[v1,v2,...]`. Mirrors
//! `SeqOfJerHandler` (`runtime/src/JerCodec.cpp`). No element-rename
//! concept the way XER's X.693 §12 `elem_xer_name` has -- JSON array
//! elements carry no name at all, so (unlike `encode_seq_of_xer_named`/
//! `decode_seq_of_xer_named`) there's only ever one shape here.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::value::Asn1Value;

pub fn encode_seq_of_jer<V: Asn1Value>(out: &mut String, items: &[V]) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        item.jer_encode(out);
    }
    out.push(']');
}

pub fn decode_seq_of_jer<V: Asn1Value + Default>(r: &mut Reader) -> Result<Vec<V>, DecodeError> {
    r.expect_char(b'[')?;
    let mut result = Vec::new();
    loop {
        match r.peek_char() {
            b']' => {
                r.expect_char(b']')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
                continue;
            }
            0 => return Err(DecodeError::new("JER: unexpected end in array".to_string(), r.pos())),
            _ => {
                result.push(V::default());
                let last = result.len() - 1;
                result[last].jer_decode_into(r)?;
            }
        }
    }
    Ok(result)
}
