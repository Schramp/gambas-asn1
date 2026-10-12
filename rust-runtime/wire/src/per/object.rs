//! Non-generic PER walker for every reflective construct kind — the
//! PER counterpart of `ber::object`. SEQUENCE/SET/CHOICE bit-level
//! framing (X.691 §18/§22) and SEQUENCE OF/SET OF element iteration
//! (`per::seq_of`, X.691 §19-20) live here, driven by the reflective
//! `Asn1Seq`/`Asn1Choice`/`Asn1SeqOf` accessors rather than a
//! generated per-type `*Spec<T>` table.

use crate::constraints::Constraints;
use crate::per::length::{decode_size_field, encode_size_field, get_length, get_nslength, get_nsnn, put_length, put_nslength, put_nsnn};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::spec::object::{Asn1Choice, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{per_decode_primitive, per_encode_primitive};

fn encode_bare(m: MemberRef, c: &Constraints, w: &mut Writer) {
    match m {
        MemberRef::Absent => {}
        MemberRef::Primitive(p) => per_encode_primitive(p, w, c),
        MemberRef::Composite(inner) => encode_seq_content(inner, w),
        MemberRef::Choice(inner) => encode_choice_content(inner, w),
        MemberRef::SeqOf(inner) => encode_seqof_content(inner, c, w),
        MemberRef::Enumerated(slot, spec) => crate::per::enumerated::encode_enum(w, spec, slot.enum_get()),
    }
}

fn decode_bare(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => per_decode_primitive(p, r, c),
        MemberRefMut::Composite(inner) => decode_seq_content_into(inner, r),
        MemberRefMut::Choice(inner) => decode_choice_content_into(inner, r),
        MemberRefMut::SeqOf(inner) => decode_seqof_content_into(inner, c, r),
        MemberRefMut::Enumerated(slot, spec) => {
            let v = crate::per::enumerated::decode_enum(r, spec)?;
            if slot.enum_set(v) {
                Ok(())
            } else {
                Err(DecodeError::new(format!("PER: invalid ENUMERATED value: {v}"), r.bit_pos()))
            }
        }
    }
}

// ---------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------

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
    encode_bare(obj.get_member(i), m.constraints, w);
}

fn access_decode(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let (per_unsupported, constraints) = {
        let m = &obj.spec().members[i];
        (m.per_unsupported, m.constraints)
    };
    if let Some(reason) = per_unsupported {
        panic!("member '{}' not supported: {}", obj.spec().members[i].name, reason);
    }
    decode_bare(obj.get_member_mut(i), constraints, r)
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

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

fn choice_root_count(obj: &dyn Asn1Choice) -> usize {
    let spec = obj.spec();
    if spec.ext_at >= 0 {
        spec.ext_at as usize
    } else {
        spec.alternatives.len()
    }
}

pub fn encode_choice_content(obj: &dyn Asn1Choice, w: &mut Writer) {
    let Some(def_idx) = obj.active_index() else {
        return; // codegen-bug backstop: no alternative matched a real generated enum.
    };
    let alt = &obj.spec().alternatives[def_idx];
    if let Some(reason) = alt.per_unsupported {
        panic!("alternative '{}' not supported: {}", alt.name, reason);
    }
    let root_count = choice_root_count(obj);
    let in_ext = obj.spec().ext_at >= 0 && def_idx >= root_count;
    let spec = obj.spec();
    if spec.ext_at >= 0 {
        w.put_bits(in_ext as u64, 1);
    }
    let constraints = alt.constraints;
    if !in_ext {
        if spec.range_bits > 0 {
            w.put_bits(def_idx as u64, spec.range_bits);
        }
        encode_bare(obj.get_active(), constraints, w);
    } else {
        put_nsnn(w, (def_idx - root_count) as i64);
        let mut tmp = Writer::new();
        encode_bare(obj.get_active(), constraints, &mut tmp);
        tmp.flush();
        let bytes = tmp.into_bytes();
        put_length(w, bytes.len());
        for b in bytes {
            w.put_bits(b as u64, 8);
        }
    }
}

pub fn decode_choice_content_into(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    let root_count = choice_root_count(obj);
    let spec_ext_at = obj.spec().ext_at;
    let mut in_ext = false;
    if spec_ext_at >= 0 {
        in_ext = r.get_bits(1)? != 0;
    }
    if !in_ext {
        let range_bits = obj.spec().range_bits;
        let def_idx = if range_bits > 0 { r.get_bits(range_bits)? as usize } else { 0 };
        if def_idx >= root_count {
            return Err(DecodeError::new("PER: CHOICE index out of range", r.bit_pos()));
        }
        let (per_unsupported, constraints) = {
            let alt = &obj.spec().alternatives[def_idx];
            (alt.per_unsupported, alt.constraints)
        };
        if let Some(reason) = per_unsupported {
            panic!("alternative not supported: {reason}");
        }
        decode_bare(obj.select_mut(def_idx), constraints, r)
    } else {
        let ext_idx = get_nsnn(r)?;
        let def_idx = root_count + ext_idx as usize;
        if def_idx >= obj.spec().alternatives.len() {
            let len = get_length(r)?;
            for _ in 0..len {
                r.get_bits(8)?;
            }
            return Err(DecodeError::new(
                "PER: CHOICE extension alternative unknown to this schema (no capture mechanism yet)",
                r.bit_pos(),
            ));
        }
        let len = get_length(r)?;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(r.get_bits(8)? as u8);
        }
        let mut inner = Reader::new(&bytes);
        let (per_unsupported, constraints) = {
            let alt = &obj.spec().alternatives[def_idx];
            (alt.per_unsupported, alt.constraints)
        };
        if let Some(reason) = per_unsupported {
            panic!("alternative not supported: {reason}");
        }
        decode_bare(obj.select_mut(def_idx), constraints, &mut inner)
    }
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

pub(crate) fn encode_seqof_content(obj: &dyn Asn1SeqOf, pc: &Constraints, w: &mut Writer) {
    encode_size_field(w, pc, obj.len());
    let elem = pc.element.unwrap_or(&crate::constraints::UNCONSTRAINED);
    for i in 0..obj.len() {
        encode_bare(obj.get(i), elem, w);
    }
}

pub(crate) fn decode_seqof_content_into(obj: &mut dyn Asn1SeqOf, pc: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    let count = decode_size_field(r, pc)?;
    let elem = pc.element.unwrap_or(&crate::constraints::UNCONSTRAINED);
    for _ in 0..count {
        decode_bare(obj.push_default_mut(), elem, r)?;
    }
    Ok(())
}
