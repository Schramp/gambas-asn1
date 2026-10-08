//! Non-generic JER walker for `spec::object::Asn1Seq` — the JER
//! counterpart of `ber::object` (gambas-asn1#681 second pass). One
//! function, shared by every SEQUENCE/SET type.

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::spec::object::{Asn1Seq, MemberRef, MemberRefMut};
use crate::spec::primitive::{jer_decode_primitive, jer_encode_primitive};

pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut String) {
    let spec = obj.spec();
    let mut first = true;
    for (i, m) in spec.members.iter().enumerate() {
        let member = obj.get_member(i);
        if matches!(member, MemberRef::Absent) {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(m.name);
        out.push_str("\":");
        match member {
            MemberRef::Absent => unreachable!(),
            MemberRef::Primitive(p) => jer_encode_primitive(p, out),
            MemberRef::Composite(inner) => encode_seq_into(inner, out),
        }
    }
}

pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut String) {
    out.push('{');
    encode_seq_content(obj, out);
    out.push('}');
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> String {
    let mut out = String::new();
    encode_seq_into(obj, &mut out);
    out
}

/// Decodes a complete JER object (including its own `{`/`}`) into an
/// already-default-initialized `obj` — scans arbitrary key order, same
/// key-driven scan `jer::sequence`'s own decoder makes.
pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    r.expect_char(b'{')?;
    let member_count = obj.spec().members.len();
    let mut seen = vec![false; member_count];
    loop {
        match r.peek_char() {
            b'}' => {
                r.expect_char(b'}')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
                continue;
            }
            0 => return Err(DecodeError::new("JER: unexpected end in object".to_string(), r.pos())),
            _ => {
                let key = r.read_json_string()?;
                r.expect_char(b':')?;
                let Some(i) = (0..member_count).find(|&i| obj.spec().members[i].name == key) else {
                    r.skip_json_value()?;
                    continue;
                };
                match obj.get_member_mut(i) {
                    MemberRefMut::Absent => {}
                    MemberRefMut::Primitive(p) => jer_decode_primitive(p, r)?,
                    MemberRefMut::Composite(inner) => decode_seq_into(inner, r)?,
                }
                seen[i] = true;
            }
        }
    }
    for i in 0..member_count {
        if !seen[i] && !obj.spec().members[i].optional {
            return Err(DecodeError::new(format!("JER: missing required member: {}", obj.spec().members[i].name), r.pos()));
        }
    }
    Ok(())
}
