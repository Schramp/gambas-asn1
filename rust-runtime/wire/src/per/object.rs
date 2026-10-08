//! Non-generic PER walker for `spec::object::Asn1Seq` — the PER
//! counterpart of `ber::object` (gambas-asn1#681 second pass). Mirrors
//! `per::sequence`'s preamble-bitmap/extension-bitmap logic exactly
//! (X.691 §18.1/§18.8), just driven by `Asn1Seq`'s reflective accessors
//! instead of a generic `SequenceSpec<T>`.

use crate::per::length::{get_length, get_nslength, put_length, put_nslength};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::spec::object::{Asn1Seq, MemberRef, MemberRefMut};
use crate::spec::primitive::{per_decode_primitive, per_encode_primitive};

fn is_present(obj: &dyn Asn1Seq, i: usize) -> bool {
    !matches!(obj.get_member(i), MemberRef::Absent)
}

fn root_end(obj: &dyn Asn1Seq) -> usize {
    let spec = obj.spec();
    if spec.ext_at >= 0 {
        spec.ext_at as usize
    } else {
        spec.members.len()
    }
}

fn access_encode(obj: &dyn Asn1Seq, i: usize, w: &mut Writer) {
    let m = &obj.spec().members[i];
    if let Some(reason) = m.per_unsupported {
        panic!("member '{}' not supported: {}", m.name, reason);
    }
    match obj.get_member(i) {
        MemberRef::Absent => {}
        MemberRef::Primitive(p) => per_encode_primitive(p, w, m.constraints),
        MemberRef::Composite(inner) => encode_seq_content(inner, w),
    }
}

fn access_decode(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let (per_unsupported, constraints) = {
        let m = &obj.spec().members[i];
        (m.per_unsupported, m.constraints)
    };
    if let Some(reason) = per_unsupported {
        panic!("member '{}' not supported: {}", obj.spec().members[i].name, reason);
    }
    match obj.get_member_mut(i) {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => per_decode_primitive(p, r, constraints),
        MemberRefMut::Composite(inner) => decode_seq_content_into(inner, r),
    }
}

fn encode_open_type(obj: &dyn Asn1Seq, i: usize, w: &mut Writer) {
    let mut tmp = Writer::new();
    access_encode(obj, i, &mut tmp);
    tmp.flush();
    let bytes = tmp.into_bytes();
    put_length(w, bytes.len());
    for b in bytes {
        w.put_bits(b as u64, 8);
    }
}

fn decode_open_type(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let len = get_length(r)?;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(r.get_bits(8)? as u8);
    }
    let mut inner = Reader::new(&bytes);
    access_decode(obj, i, &mut inner)
}

fn skip_open_type(r: &mut Reader) -> Result<(), DecodeError> {
    let len = get_length(r)?;
    for _ in 0..len {
        r.get_bits(8)?;
    }
    Ok(())
}

pub fn encode_seq_content(obj: &dyn Asn1Seq, w: &mut Writer) {
    let end = root_end(obj);
    let spec = obj.spec();
    let mut has_ext = false;
    if spec.ext_at >= 0 {
        has_ext = (end..spec.members.len()).any(|i| is_present(obj, i));
        w.put_bits(has_ext as u64, 1);
    }
    for i in 0..end {
        if !spec.members[i].optional {
            continue;
        }
        let suppress = obj.is_default_equal(i);
        let present = is_present(obj, i) && !suppress;
        w.put_bits(present as u64, 1);
    }
    for i in 0..end {
        if spec.members[i].optional && !is_present(obj, i) {
            continue;
        }
        if obj.is_default_equal(i) {
            continue;
        }
        access_encode(obj, i, w);
    }
    if has_ext {
        let total = spec.members.len();
        let n_ext = total - end;
        put_nslength(w, n_ext);
        for i in end..total {
            w.put_bits(is_present(obj, i) as u64, 1);
        }
        for i in end..total {
            if !is_present(obj, i) {
                continue;
            }
            encode_open_type(obj, i, w);
        }
    }
}

pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let end = root_end(obj);
    let mut ext_flag = false;
    if obj.spec().ext_at >= 0 {
        ext_flag = r.get_bits(1)? != 0;
    }

    let roms = obj.spec().roms_count;
    let mut bitmap = [false; 64];
    for slot in bitmap.iter_mut().take(roms.min(64)) {
        *slot = r.get_bits(1)? != 0;
    }

    let mut opt_idx = 0;
    for i in 0..end {
        if obj.spec().members[i].optional {
            let present = bitmap[opt_idx];
            opt_idx += 1;
            if !present {
                obj.set_default(i);
                continue;
            }
        }
        access_decode(obj, i, r)?;
    }

    if obj.spec().ext_at >= 0 {
        let total = obj.spec().members.len();
        let known_ext = total - end;
        if ext_flag {
            let n_ext = get_nslength(r)?;
            let mut ext_bitmap = [false; 64];
            for slot in ext_bitmap.iter_mut().take(n_ext.min(64)) {
                *slot = r.get_bits(1)? != 0;
            }
            for i in 0..n_ext {
                if !ext_bitmap[i.min(63)] {
                    continue;
                }
                if i < known_ext {
                    decode_open_type(obj, end + i, r)?;
                } else {
                    skip_open_type(r)?;
                }
            }
        }
    }

    Ok(())
}
