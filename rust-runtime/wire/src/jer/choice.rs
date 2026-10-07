//! CHOICE -- X.697 §11 analogue. Single-key object `{"altName":value}`.
//! Mirrors `ChoiceJerHandler` (`runtime/src/JerCodec.cpp`). No
//! `own_tag`/`BerTagging` concept applies -- JER dispatch is purely
//! name-based (the one JSON key), so this ignores `Alternative::ber`
//! entirely (it's a BER/XER framing detail, meaningless for JSON).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::spec::choice::{active_alt, ChoiceSpec};

pub fn encode_choice_jer_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut String) {
    let Some((_, alt)) = active_alt(spec, value) else {
        // No alternative matched -- codegen/table mismatch, or a value
        // that was never decoded/set. Matches the C++ reference's own
        // `{}` fallback (ChoiceJerHandler::encode: "pr <= 0 || pr >
        // spec.count" -> empty object) rather than panicking, since an
        // empty-CHOICE JSON object round-trips (JER has no tag to be
        // "wrong" the way BER/XER would notice).
        out.push_str("{}");
        return;
    };
    out.push_str("{\"");
    out.push_str(alt.name);
    out.push_str("\":");
    (alt.jer_encode)(value, out);
    out.push('}');
}

pub fn encode_choice_jer<T>(spec: &ChoiceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    encode_choice_jer_into(spec, value, &mut out);
    out
}

pub fn decode_choice_jer_into<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    r.expect_char(b'{')?;
    if r.peek_char() == b'}' {
        r.expect_char(b'}')?;
        return Ok(());
    }
    let key = r.read_json_string()?;
    r.expect_char(b':')?;
    for alt in spec.alternatives {
        if key == alt.name {
            (alt.jer_decode)(value, r)?;
            r.expect_char(b'}')?;
            return Ok(());
        }
    }
    Err(DecodeError::new(format!("JER: CHOICE: unknown alternative: {key}"), r.pos()))
}

pub fn decode_choice_jer<T: Default>(spec: &ChoiceSpec<T>, json: &str) -> Result<T, DecodeError> {
    let mut r = Reader::new(json);
    let mut v = T::default();
    decode_choice_jer_into(spec, &mut v, &mut r)?;
    Ok(v)
}
