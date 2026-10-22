//! Non-generic PER walker for every reflective construct kind — the
//! PER counterpart of `ber::object`. SEQUENCE/SET/CHOICE bit-level
//! framing (X.691 §18/§22) and SEQUENCE OF/SET OF element iteration
//! (X.691 §19-20) live here, driven by the reflective
//! `Asn1Seq`/`Asn1Choice`/`Asn1SeqOf` accessors rather than a
//! generated per-type `*Spec<T>` table.

use crate::ber::tag::Tag;
use crate::constraints::Constraints;
use crate::per::length::{decode_ext_size_and_items, encode_ext_size_and_items, get_nslength, get_nsnn, get_octets, put_nslength, put_nsnn, put_octets};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;
use crate::encode_error::EncodeError;
use crate::spec::object::{Asn1Choice, Asn1Pdu, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{per_decode_primitive, per_encode_primitive};

/// @brief Writes one value's unaligned-PER form, dispatching on its
///        reflective shape.
/// @param c  The value's own PER-visible constraints.
/// @return `Err` for a member or alternative codegen marked unsupported,
///         or a value PER cannot represent (constraint violation).
/// @brief Encode one value with its PER-visible constraints (crate entry
///        point for contained values).
pub(crate) fn encode_member_ref(m: MemberRef, c: &Constraints, w: &mut Writer) -> Result<(), EncodeError> {
    encode_bare(m, c, w)
}

/// @brief Decode one value with its PER-visible constraints (crate entry
///        point for contained values).
pub(crate) fn decode_member_ref(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    decode_bare(m, c, r)
}

fn encode_bare(m: MemberRef, c: &Constraints, w: &mut Writer) -> Result<(), EncodeError> {
    match m {
        MemberRef::Absent => Ok(()),
        MemberRef::Unsupported(msg) => Err(EncodeError::new(msg)),
        MemberRef::Primitive(p) => per_encode_primitive(p, w, c),
        MemberRef::Contained(v, spec) => {
            let os = v.wire_octets(spec, crate::containing::ContainedEncoding::PerUnaligned);
            per_encode_primitive(crate::spec::primitive::PrimitiveRef::OctetString(&os), w, c)
        }
        MemberRef::Composite(inner) => encode_seq_content(inner, w),
        MemberRef::Choice(inner) => encode_choice_content(inner, w),
        MemberRef::SeqOf(inner) => encode_seqof_content(inner, c, w),
        MemberRef::Enumerated(slot, spec) => {
            crate::per::enumerated::encode_enum(w, spec, slot.enum_get());
            Ok(())
        }
    }
}

fn decode_bare(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    if !matches!(m, MemberRefMut::Composite(_) | MemberRefMut::Choice(_) | MemberRefMut::SeqOf(_)) {
        return decode_bare_level(m, c, r);
    }
    if !r.depth.enter() {
        return Err(DecodeError::new(crate::nesting::too_deep(), r.bit_pos()));
    }
    let res = decode_bare_level(m, c, r);
    r.depth.leave();
    res
}

/// @brief The per-kind decode `decode_bare` dispatches to once it has counted
///        the nesting level a constructed value enters.
fn decode_bare_level(m: MemberRefMut, c: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Unsupported(msg) => Err(DecodeError::new(msg, r.bit_pos())),
        MemberRefMut::Primitive(p) => per_decode_primitive(p, r, c),
        MemberRefMut::Contained(v, _) => {
            let mut os = crate::octet_string::OctetString::default();
            per_decode_primitive(crate::spec::primitive::PrimitiveRefMut::OctetString(&mut os), r, c)?;
            v.set_raw_from_wire(os.0);
            Ok(())
        }
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

fn access_encode(obj: &dyn Asn1Seq, i: usize, w: &mut Writer) -> Result<(), EncodeError> {
    let m = &obj.spec().members[i];
    encode_bare(obj.get_member(i), m.constraints, w)
}

fn access_decode(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let constraints = obj.spec().members[i].constraints;
    decode_bare(obj.get_member_mut(i), constraints, r)
}

fn encode_open_type(obj: &dyn Asn1Seq, i: usize, w: &mut Writer) -> Result<(), EncodeError> {
    let mut tmp = Writer::new();
    access_encode(obj, i, &mut tmp)?;
    tmp.flush();
    put_octets(w, &tmp.into_bytes());
    Ok(())
}

fn decode_open_type(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let bytes = get_octets(r)?;
    let mut inner = r.sub(&bytes);
    access_decode(obj, i, &mut inner)
}

fn skip_open_type(r: &mut Reader) -> Result<(), DecodeError> {
    get_octets(r).map(|_| ())
}

/// @brief Encodes a SEQUENCE/SET: extension bit, presence bitmap, root
///        members, then extension additions as open types.
/// @return `Err` when a member cannot be encoded.
/// @see X.691 §18.
pub fn encode_seq_content(obj: &dyn Asn1Seq, w: &mut Writer) -> Result<(), EncodeError> {
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
        access_encode(obj, i, w)?;
    }
    if has_ext {
        let units = ext_units(spec, end);
        put_nslength(w, units.len());
        for &(b, e, _) in &units {
            w.put_bits((b..e).any(|i| is_present(obj, i)) as u64, 1);
        }
        for &(b, e, group) in &units {
            if !(b..e).any(|i| is_present(obj, i)) {
                continue;
            }
            if group {
                encode_group_open_type(obj, b, e, w)?;
            } else {
                encode_open_type(obj, b, w)?;
            }
        }
    }
    Ok(())
}

/// @brief The extension additions as PER units (X.691 §18.9), from the
///        spec's precomputed `ext_units`: `(first member, end, is group)`.
///        Without a unit table every extension member is its own unit.
fn ext_units(spec: &crate::spec::object::SequenceSpec, end: usize) -> Vec<(usize, usize, bool)> {
    if spec.ext_units.is_empty() {
        return (end..spec.members.len()).map(|i| (i, i + 1, false)).collect();
    }
    let mut begin = end;
    spec.ext_units
        .iter()
        .map(|u| {
            let unit = (begin, u.end, u.group);
            begin = u.end;
            unit
        })
        .collect()
}

/// @brief Encodes one present extension addition group as a sequence of
///        its members (presence bitmap for the members declared
///        OPTIONAL/DEFAULT inside the group, then the present members)
///        inside one open type (X.691 §18.9).
/// @return `Err` when a mandatory group member is absent (X.680 §24.12)
///         or a member cannot be encoded.
fn encode_group_open_type(obj: &dyn Asn1Seq, begin: usize, end: usize, w: &mut Writer) -> Result<(), EncodeError> {
    let opt = obj.spec().group_member_optional;
    let mut g = Writer::new();
    for i in begin..end {
        if opt[i] {
            g.put_bits(is_present(obj, i) as u64, 1);
        }
    }
    for i in begin..end {
        if !is_present(obj, i) {
            // X.680 §24.12: a present group carries all its mandatory members.
            if !opt[i] {
                return Err(EncodeError::new(format!("extension group member absent: {}", obj.spec().members[i].name)));
            }
            continue;
        }
        access_encode(obj, i, &mut g)?;
    }
    g.flush();
    put_octets(w, &g.into_bytes());
    Ok(())
}

/// @brief Decode counterpart of [`encode_group_open_type`].
fn decode_group_open_type(obj: &mut dyn Asn1Seq, begin: usize, end: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let bytes = get_octets(r)?;
    let mut g = r.sub(&bytes);
    let opt = obj.spec().group_member_optional;
    let mut present = vec![true; end - begin];
    for i in begin..end {
        if opt[i] {
            present[i - begin] = g.get_bits(1)? != 0;
        }
    }
    for i in begin..end {
        if present[i - begin] {
            access_decode(obj, i, &mut g)?;
        } else {
            obj.set_default(i);
        }
    }
    Ok(())
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

    if obj.spec().ext_at >= 0 && ext_flag {
        let units = ext_units(obj.spec(), end);
        let n_ext = get_nslength(r)?;
        let mut ext_bitmap = [false; 64];
        for slot in ext_bitmap.iter_mut().take(n_ext.min(64)) {
            *slot = r.get_bits(1)? != 0;
        }
        for i in 0..n_ext {
            if !ext_bitmap[i.min(63)] {
                continue;
            }
            match units.get(i) {
                Some(&(b, e, true)) => decode_group_open_type(obj, b, e, r)?,
                Some(&(b, _, false)) => decode_open_type(obj, b, r)?,
                None => skip_open_type(r)?,
            }
        }
    }

    if !obj.spec().contained_members.is_empty() {
        crate::containing::decode_contained_members(obj, crate::containing::ContainedEncoding::PerUnaligned, r.depth, r.contained)
            .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.bit_pos()))?;
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

/// @brief Encodes a CHOICE: extension bit, index, then the chosen
///        alternative (an open type when it is an extension addition).
/// @return `Err` when the alternative cannot be encoded.
/// @see X.691 §23.
pub fn encode_choice_content(obj: &dyn Asn1Choice, w: &mut Writer) -> Result<(), EncodeError> {
    let Some(def_idx) = obj.active_index() else {
        return Err(crate::spec::object::no_alternative_selected(obj.spec()));
    };
    let alt = &obj.spec().alternatives[def_idx];
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
        encode_bare(obj.get_active(), constraints, w)
    } else {
        put_nsnn(w, (def_idx - root_count) as i64);
        let mut tmp = Writer::new();
        encode_bare(obj.get_active(), constraints, &mut tmp)?;
        tmp.flush();
        put_octets(w, &tmp.into_bytes());
        Ok(())
    }
}

pub fn decode_choice_content_into(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    decode_choice_alternative(obj, r)?;
    crate::containing::decode_contained_alternative(obj, crate::containing::ContainedEncoding::PerUnaligned, r.depth, r.contained)
        .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.bit_pos()))
}

/// @brief Decode the CHOICE index and the selected alternative (X.691 §23).
fn decode_choice_alternative(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
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
        let constraints = obj.spec().alternatives[def_idx].constraints;
        decode_bare(obj.select_mut(def_idx), constraints, r)
    } else {
        let ext_idx = get_nsnn(r)?;
        let def_idx = root_count + ext_idx as usize;
        if def_idx >= obj.spec().alternatives.len() {
            // X.691 §23.8: an extension alternative this schema version
            // doesn't define still arrives as a complete open type. Keep its
            // contents (under a context tag carrying the extension index)
            // instead of failing, as the C++ ChoicePerHandler skips it.
            let bytes = get_octets(r)?;
            obj.construct_unknown_extension(Tag::context(ext_idx as u32, false), bytes);
            return Ok(());
        }
        let bytes = get_octets(r)?;
        let mut inner = r.sub(&bytes);
        let constraints = obj.spec().alternatives[def_idx].constraints;
        decode_bare(obj.select_mut(def_idx), constraints, &mut inner)
    }
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

/// @brief Encodes a SEQUENCE OF/SET OF: count under its SIZE
///        constraint, then the elements (a SET OF in X.691 §21.1 order).
/// @return `Err` when an element cannot be encoded.
/// @see X.691 §20, §21.
pub fn encode_seqof_content(obj: &dyn Asn1SeqOf, pc: &Constraints, w: &mut Writer) -> Result<(), EncodeError> {
    let elem = pc.element.unwrap_or(&crate::constraints::UNCONSTRAINED);
    if obj.natural_tag() == crate::spec::sequence::SET_TAG && obj.len() > 1 {
        let parts = set_of_sorted_parts(obj, elem)?;
        encode_ext_size_and_items(w, pc, parts.len(), |w, range| {
            for (bytes, nbits) in &parts[range] {
                w.put_bit_string(bytes, *nbits);
            }
        });
        return Ok(());
    }
    // The count helper may call `items` once per fragment (X.691 §11.9.3.8),
    // so the first element error is kept and the remaining items skipped.
    let mut err = None;
    encode_ext_size_and_items(w, pc, obj.len(), |w, range| {
        for i in range {
            if err.is_some() {
                return;
            }
            if let Err(e) = encode_bare(obj.get(i), elem, w) {
                err = Some(e);
            }
        }
    });
    err.map_or(Ok(()), Err)
}

/// @brief Encodes a SET OF's elements and orders them as X.691 §21.1
///        (CANONICAL-PER) defines: ascending by component encoding,
///        compared as bit strings zero-padded to an octet boundary, the
///        shorter one extended with 0-octets. The only order the standard
///        defines, and valid BASIC-PER too (X.691 §8); asn1c and the C++
///        `SeqOfPerHandler` emit the same.
/// @param obj  The SET OF value.
/// @param elem Per-element constraints.
/// @return Each element's encoding and exact bit count, in §21.1 order;
///         `Err` when an element cannot be encoded.
/// @see X.691 §21.1, §21.2.
fn set_of_sorted_parts(obj: &dyn Asn1SeqOf, elem: &Constraints) -> Result<Vec<(Vec<u8>, usize)>, EncodeError> {
    let mut parts: Vec<(Vec<u8>, usize)> = (0..obj.len())
        .map(|i| {
            let mut ew = Writer::new();
            encode_bare(obj.get(i), elem, &mut ew)?;
            let nbits = ew.bit_pos();
            ew.flush();
            Ok((ew.into_bytes(), nbits))
        })
        .collect::<Result<_, EncodeError>>()?;
    parts.sort_by(|(a, _), (b, _)| {
        let n = a.len().max(b.len());
        (0..n)
            .map(|k| (a.get(k).copied().unwrap_or(0), b.get(k).copied().unwrap_or(0)))
            .find(|(x, y)| x != y)
            .map_or(std::cmp::Ordering::Equal, |(x, y)| x.cmp(&y))
    });
    Ok(parts)
}

pub fn decode_seqof_content_into(obj: &mut dyn Asn1SeqOf, pc: &Constraints, r: &mut Reader) -> Result<(), DecodeError> {
    let elem = pc.element.unwrap_or(&crate::constraints::UNCONSTRAINED);
    decode_ext_size_and_items(r, pc, |r, m| {
        obj.reserve(m);
        for _ in 0..m {
            decode_bare(obj.push_default_mut(), elem, r)?;
        }
        Ok(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Top-level (document root) entry points
// ---------------------------------------------------------------------

/// @brief Appends `v`'s unaligned-PER encoding to `w` (no flush — the
///        caller owns the writer and pads it).
/// @param v  Any generated SEQUENCE/SET/CHOICE/SEQUENCE OF type; a named
///           SEQUENCE OF's own SIZE bounds come from
///           `Asn1Pdu::PDU_CONSTRAINTS`.
/// @return `Err` when `v` holds a value this runtime cannot encode in
///         PER; `w` then holds a partial encoding the caller should
///         discard.
/// @see X.691 §10.1 — complete encoding of the outermost value.
pub fn encode_pdu_into<T: Asn1Pdu + ?Sized>(v: &T, w: &mut Writer) -> Result<(), EncodeError> {
    let r = encode_bare(v.as_member_ref(), T::PDU_CONSTRAINTS, w);
    if let Err(e) = &r {
        if crate::debug::debug_flags() & crate::debug::DBG_PER != 0 {
            eprintln!("[PER-ENC] encode failed: {}", e.message);
        }
    }
    r
}

/// @brief One-record convenience form of `encode_pdu_into`, flushed to
///        a whole number of octets.
/// @return The encoded bytes, or `Err` as `encode_pdu_into`.
/// @see X.691 §10.1.3 — octet-aligned complete encoding.
pub fn encode_pdu<T: Asn1Pdu + ?Sized>(v: &T) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    encode_pdu_into(v, &mut w)?;
    w.flush();
    Ok(w.into_bytes())
}

/// @brief Decodes one unaligned-PER value from `r` into `v`.
/// @param v  Destination; expected to be `Default`-fresh.
/// @param r  Bit reader positioned at the value's first bit.
/// @see X.691 §10.1.
pub fn decode_pdu_into<T: Asn1Pdu + ?Sized>(v: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    decode_bare(v.as_member_ref_mut(), T::PDU_CONSTRAINTS, r)
}

/// @brief Whole-buffer form of `decode_pdu_into`.
/// @return The decoded value.
pub fn decode_pdu<T: Asn1Pdu>(data: &[u8]) -> Result<T, DecodeError> {
    let mut v = T::default();
    decode_pdu_into(&mut v, &mut Reader::new(data))?;
    Ok(v)
}

/// @brief Whole-buffer decode with contained-value settings: the decoder
///        registry, `off`, and the XER/JER overrides apply to every
///        contained field (X.682 §11) in the value.
/// @return The decoded value.
pub fn decode_pdu_with<T: Asn1Pdu>(data: &[u8], opts: &crate::containing::ContainedOptions) -> Result<T, DecodeError> {
    let mut v = T::default();
    let mut r = Reader::new(data);
    r.set_contained(opts);
    decode_pdu_into(&mut v, &mut r)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::sequence::{SeqOf, SetOf};
    use crate::constraints::UNCONSTRAINED;
    use crate::integer::Integer;

    fn bytes(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.flush();
        w.into_bytes()
    }

    #[test]
    fn set_of_is_written_in_canonical_per_order_sequence_of_is_not() {
        // Unconstrained INTEGER elements: length octet + minimal
        // two's-complement octets each. X.691 §21.1 compares the padded
        // element encodings: 01 05 < 01 FF < 02 01 2C.
        let vals = vec![Integer(300), Integer(-1), Integer(5)];
        let set = bytes(|w| encode_seqof_content(&SetOf(vals.clone()), &UNCONSTRAINED, w).unwrap());
        assert_eq!(set, vec![0x03, 0x01, 0x05, 0x01, 0xFF, 0x02, 0x01, 0x2C]);
        let seq = bytes(|w| encode_seqof_content(&SeqOf(vals), &UNCONSTRAINED, w).unwrap());
        assert_eq!(seq, vec![0x03, 0x02, 0x01, 0x2C, 0x01, 0xFF, 0x01, 0x05]);
    }
}
