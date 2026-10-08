//! Non-generic XER walker for `spec::object::Asn1Seq` — the XER
//! counterpart of `ber::object` (gambas-asn1#681 second pass). One
//! function, shared by every SEQUENCE/SET type; no BER tag concept
//! applies here (X.693 names elements by field, not by wire tag), so
//! `MemberMeta::ber` is simply ignored.

use crate::ber::reader::DecodeError;
use crate::spec::object::{Asn1Seq, MemberRef, MemberRefMut};
use crate::spec::primitive::{xer_decode_primitive, xer_encode_primitive};
use crate::xer::reader::XerReader;
use crate::xer::writer::{indent, write_close_tag, write_open_tag};

/// Member-loop content, no outer `<name>`/`</name>` wrapper — see
/// `xer::sequence::encode_sequence_xer_content`'s own doc for the exact
/// contract this mirrors (depth convention, empty-SEQUENCE case).
pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut String, depth: usize) {
    let spec = obj.spec();
    let mut any = false;
    for (i, m) in spec.members.iter().enumerate() {
        let member = obj.get_member(i);
        if matches!(member, MemberRef::Absent) {
            continue;
        }
        any = true;
        out.push('\n');
        out.push_str(&indent(depth + 1));
        write_open_tag(out, m.name);
        match member {
            MemberRef::Absent => unreachable!(),
            MemberRef::Primitive(p) => xer_encode_primitive(p, out, depth + 1),
            MemberRef::Composite(inner) => encode_seq_content(inner, out, depth + 1),
        }
        write_close_tag(out, m.name);
    }
    if any {
        out.push('\n');
        out.push_str(&indent(depth));
    }
}

pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut String, depth: usize) {
    encode_seq_content(obj, out, depth);
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, obj.spec().name);
    encode_seq_content(obj, &mut out, 0);
    write_close_tag(&mut out, obj.spec().name);
    out.push('\n');
    out
}

/// Decodes a SEQUENCE/SET's XER member-loop content into an already-
/// default-initialized `obj` — peek-match on the next open tag's name,
/// same canonical-order assumption `xer::sequence`'s own decoder makes.
pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut XerReader) -> Result<(), DecodeError> {
    let member_count = obj.spec().members.len();
    for i in 0..member_count {
        let (name, optional) = {
            let m = &obj.spec().members[i];
            (m.name, m.optional)
        };
        if optional {
            let peeked = r.peek_tag();
            if peeked.closing || peeked.name != name {
                continue;
            }
        }
        r.consume_open_tag(name)?;
        match obj.get_member_mut(i) {
            MemberRefMut::Absent => {}
            MemberRefMut::Primitive(p) => xer_decode_primitive(p, r)?,
            MemberRefMut::Composite(inner) => decode_seq_content_into(inner, r)?,
        }
        r.consume_close_tag(name)?;
    }
    Ok(())
}

pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut XerReader) -> Result<(), DecodeError> {
    r.consume_open_tag(obj.spec().name)?;
    decode_seq_content_into(obj, r)?;
    r.consume_close_tag(obj.spec().name)?;
    Ok(())
}
