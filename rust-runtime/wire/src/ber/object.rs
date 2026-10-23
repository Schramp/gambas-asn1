//! Non-generic BER walker for every reflective construct kind
//! (see `spec::object`'s own doc for the trait design this drives).
//! One function per operation per kind, shared by every type of that
//! kind in the program: calling any of them never needs a fresh
//! monomorphization per concrete type, so a BER-only caller never has
//! to compile (or address-take) anything XER/JER/PER-shaped to reach a
//! nested member/alternative/element of any kind.

use crate::ber::enumerated::{read_enumerated_tagged_into, write_enumerated_tagged, ENUMERATED_TAG};
use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::ber::writer::{write_explicit, write_primitive, write_tagged};
use crate::containing::ContainedOptions;
use crate::encode_error::EncodeError;
use crate::spec::choice::BerTagging;
use crate::spec::object::{Asn1Choice, Asn1Pdu, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{ber_decode_primitive, ber_encode_primitive};

/// @brief Error for a member or alternative codegen marked unsupported
///        (`BerTagging::Unsupported`), reached through its BER framing.
/// @param reason  The table's own diagnostic.
fn unsupported_framing(reason: &'static str) -> EncodeError {
    EncodeError::new(format!("member not supported: {reason}"))
}

/// Decode counterpart of [`unsupported_framing`].
fn unsupported_framing_decode(reason: &'static str, r: &Reader) -> DecodeError {
    DecodeError::new(format!("member not supported: {reason}"), r.pos())
}

/// @brief Encodes one member/alternative/element value under `framing` —
///        the one place that dispatches on `MemberRef`'s kind, shared by
///        the SEQUENCE/SET member loop, the CHOICE alternative dispatch,
///        and the SEQUENCE OF/SET OF element loop.
/// @param m        The value, by reflective shape.
/// @param framing  The row's X.690 §8.14 tagging.
/// @param out      Destination buffer.
/// @return `Err` for a member or alternative codegen marked unsupported.
/// @see X.690 §8.14 — EXPLICIT/IMPLICIT tagging.
pub(crate) fn encode_member_ref(m: MemberRef, framing: BerTagging, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    match m {
        MemberRef::Absent => Ok(()),
        MemberRef::Unsupported(msg) => Err(EncodeError::new(msg)),
        MemberRef::Primitive(p) => ber_encode_primitive(p, framing, out),
        MemberRef::Contained(c, spec) => {
            let os = c.wire_octets(spec, crate::containing::ContainedEncoding::Ber, opts)?;
            ber_encode_primitive(crate::spec::primitive::PrimitiveRef::OctetString(&os), framing, out)
        }
        MemberRef::Composite(inner) => match framing {
            BerTagging::Explicit(tag) => write_tagged(out, tag, |out| encode_seq_into(inner, out, opts)),
            BerTagging::Implicit(tag) => write_tagged(out, tag, |out| encode_seq_content(inner, out, opts)),
            BerTagging::Delegate => encode_seq_into(inner, out, opts),
            BerTagging::Unsupported(reason) => Err(unsupported_framing(reason)),
        },
        MemberRef::Choice(inner) => match framing {
            BerTagging::Explicit(tag) => write_explicit(out, tag, |out| encode_choice_dispatch(inner, out, opts)),
            BerTagging::Implicit(tag) => encode_choice_tagged(inner, tag, out, opts),
            BerTagging::Delegate => encode_choice_into(inner, out, opts),
            BerTagging::Unsupported(reason) => Err(unsupported_framing(reason)),
        },
        MemberRef::SeqOf(inner) => {
            let natural = inner.natural_tag();
            match framing {
                BerTagging::Explicit(tag) => write_tagged(out, tag, |out| write_tagged(out, natural, |out| encode_seqof_content(inner, out, opts))),
                BerTagging::Implicit(tag) => write_tagged(out, tag, |out| encode_seqof_content(inner, out, opts)),
                BerTagging::Delegate => write_tagged(out, natural, |out| encode_seqof_content(inner, out, opts)),
                BerTagging::Unsupported(reason) => Err(unsupported_framing(reason)),
            }
        }
        MemberRef::Enumerated(slot, _spec) => {
            let v = slot.enum_get();
            match framing {
                BerTagging::Explicit(tag) => write_tagged(out, tag, |out| write_enumerated_tagged(out, ENUMERATED_TAG, v)),
                BerTagging::Implicit(tag) => write_enumerated_tagged(out, tag, v),
                BerTagging::Delegate => write_enumerated_tagged(out, ENUMERATED_TAG, v),
                BerTagging::Unsupported(reason) => return Err(unsupported_framing(reason)),
            }
            Ok(())
        }
    }
}

/// @brief Decode counterpart of `encode_member_ref`.
/// @return `Err` on malformed BER, a tag mismatch, or a member or
///         alternative codegen marked unsupported.
pub(crate) fn decode_member_ref(m: MemberRefMut, framing: BerTagging, r: &mut Reader) -> Result<(), DecodeError> {
    if !matches!(m, MemberRefMut::Composite(_) | MemberRefMut::Choice(_) | MemberRefMut::SeqOf(_)) {
        return decode_member_ref_level(m, framing, r);
    }
    if !r.depth.enter() {
        return Err(DecodeError::new(crate::nesting::too_deep(), r.pos()));
    }
    let res = decode_member_ref_level(m, framing, r);
    r.depth.leave();
    res
}

/// @brief The per-kind decode `decode_member_ref` dispatches to once it has counted
///        the nesting level a constructed value enters.
fn decode_member_ref_level(m: MemberRefMut, framing: BerTagging, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Unsupported(msg) => Err(DecodeError::new(msg, r.pos())),
        MemberRefMut::Primitive(p) => ber_decode_primitive(p, framing, r),
        MemberRefMut::Contained(c, _) => {
            let mut os = crate::octet_string::OctetString::default();
            ber_decode_primitive(crate::spec::primitive::PrimitiveRefMut::OctetString(&mut os), framing, r)?;
            c.set_raw_from_wire(os.0, crate::containing::ContainedEncoding::Ber);
            Ok(())
        }
        MemberRefMut::Composite(inner) => decode_composite_member(inner, framing, r),
        MemberRefMut::Choice(inner) => match framing {
            BerTagging::Explicit(tag) => {
                let tlv = r.read_tlv()?;
                if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                    return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                }
                let mut inner_r = r.sub(tlv.value);
                decode_choice_dispatch(inner, &mut inner_r)
            }
            BerTagging::Implicit(tag) => decode_choice_tagged_into(inner, r, tag),
            BerTagging::Delegate => decode_choice_into(inner, r),
            BerTagging::Unsupported(reason) => Err(unsupported_framing_decode(reason, r)),
        },
        MemberRefMut::SeqOf(inner) => {
            let natural = inner.natural_tag();
            match framing {
                BerTagging::Explicit(tag) => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    let mut outer = r.sub(tlv.value);
                    let inner_tlv = outer.read_tlv()?;
                    decode_seqof_content(inner, outer.sub(inner_tlv.value))
                }
                BerTagging::Implicit(tag) => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    decode_seqof_content(inner, r.sub(tlv.value))
                }
                BerTagging::Delegate => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != natural.class || tlv.tag.number != natural.number {
                        return Err(DecodeError::new(format!("expected tag {natural:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    decode_seqof_content(inner, r.sub(tlv.value))
                }
                BerTagging::Unsupported(reason) => Err(unsupported_framing_decode(reason, r)),
            }
        }
        MemberRefMut::Enumerated(slot, _spec) => match framing {
            BerTagging::Explicit(tag) => {
                let tlv = r.read_tlv()?;
                if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                    return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                }
                let mut inner_r = r.sub(tlv.value);
                read_enumerated_tagged_into(slot, &mut inner_r, ENUMERATED_TAG)
            }
            BerTagging::Implicit(tag) => read_enumerated_tagged_into(slot, r, tag),
            BerTagging::Delegate => read_enumerated_tagged_into(slot, r, ENUMERATED_TAG),
            BerTagging::Unsupported(reason) => Err(unsupported_framing_decode(reason, r)),
        },
    }
}

fn decode_composite_member(inner: &mut dyn Asn1Seq, ber: BerTagging, r: &mut Reader) -> Result<(), DecodeError> {
    match ber {
        BerTagging::Explicit(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut outer = r.sub(tlv.value);
            let inner_tlv = outer.read_tlv()?;
            let mut content = outer.sub(inner_tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Implicit(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut content = r.sub(tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Delegate => {
            let natural = inner.spec().tag;
            let tlv = r.read_tlv()?;
            if tlv.tag.class != natural.class || tlv.tag.number != natural.number {
                return Err(DecodeError::new(format!("expected tag {natural:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut content = r.sub(tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Unsupported(reason) => Err(unsupported_framing_decode(reason, r)),
    }
}

// ---------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------

/// @brief The member-loop content, no outer TLV — shared by `encode_seq`
///        (natural tag) and a containing member's own tag override.
/// @return `Err` when a member cannot be encoded.
/// @see X.690 §8.9 (SEQUENCE), §8.11 (SET), §8.14 (tagging).
pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    let spec = obj.spec();
    for (i, m) in spec.members.iter().enumerate() {
        if obj.is_default_equal(i) {
            continue;
        }
        let member = obj.get_member(i);
        let present = !matches!(member, MemberRef::Absent);
        encode_member_ref(member, m.ber, out, opts)?;
        if present {
            let delta = obj.validate(i);
            if delta != 0 {
                crate::validate::check_delta(delta, m.name, "encode");
            }
        }
    }
    Ok(())
}

/// Appends a SEQUENCE/SET's complete TLV (its own natural tag).
pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    write_tagged(out, obj.spec().tag, |out| encode_seq_content(obj, out, opts))
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_seq_into(obj, &mut out, None)?;
    Ok(out)
}

/// IMPLICIT/EXPLICIT retag of a SEQUENCE/SET-typed member (X.690 §8.14) —
/// same content, different outer tag or an extra wrapping TLV. Used by a
/// *containing* type's own member override reaching this SEQUENCE/SET.
pub fn encode_seq_tagged(obj: &dyn Asn1Seq, tag: Tag, explicit: bool, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    if explicit {
        write_tagged(out, tag, |out| encode_seq_into(obj, out, opts))
    } else {
        write_tagged(out, tag, |out| encode_seq_content(obj, out, opts))
    }
}

/// Decodes a SEQUENCE/SET's member-loop content into an already-
/// default-initialized `obj`. OPTIONAL member detection peeks the wire
/// tag first, same canonical-order assumption `ber::sequence`'s own
/// decoder makes.
/// @brief True when a TLV tagged `t` belongs to SET member `i`: its own
///        tag, or for an untagged CHOICE member one of the CHOICE's
///        alternative tags.
fn set_member_matches(obj: &dyn Asn1Seq, i: usize, t: Tag) -> bool {
    let m = &obj.spec().members[i];
    if matches!(m.ber, BerTagging::Delegate) {
        if let MemberRef::Choice(c) = obj.get_member(i) {
            return c.spec().ber_tags.iter().any(|d| d.tag == t);
        }
    }
    m.tag == t
}

/// @brief Copies a SET's component TLVs into member-table order, so the
///        sequential member walk can decode them. BER allows SET components
///        in any order (X.690 §8.11.2); the table holds them in canonical
///        tag order (X.680 §8.6). A TLV matching no member (an unknown
///        extension addition) goes last.
/// @return The reordered TLV bytes.
fn set_in_table_order(obj: &dyn Asn1Seq, content: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let count = obj.spec().members.len();
    let mut slot: Vec<Option<&[u8]>> = vec![None; count];
    let mut unmatched: Vec<&[u8]> = Vec::new();
    let mut scan = Reader::new(content);
    while !scan.at_end() {
        let p0 = scan.pos();
        let t = scan.read_tlv()?.tag;
        let raw = &content[p0..scan.pos()];
        match (0..count).find(|&i| slot[i].is_none() && set_member_matches(obj, i, t)) {
            Some(i) => slot[i] = Some(raw),
            None => unmatched.push(raw),
        }
    }
    let mut out = Vec::with_capacity(content.len());
    for raw in slot.into_iter().flatten().chain(unmatched) {
        out.extend_from_slice(raw);
    }
    Ok(out)
}

pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    if obj.spec().is_set {
        let ordered = set_in_table_order(obj, r.remaining())?;
        return decode_seq_members(obj, &mut r.sub(&ordered));
    }
    decode_seq_members(obj, r)
}

/// Sequential member walk shared by SEQUENCE and (reordered) SET content.
fn decode_seq_members(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let member_count = obj.spec().members.len();
    for i in 0..member_count {
        let (name, tag, optional, ber) = {
            let m = &obj.spec().members[i];
            (m.name, m.tag, m.optional, m.ber)
        };
        let mut has_value = true;
        if optional {
            if r.peek_tag() == Some(tag) {
                decode_member_ref(obj.get_member_mut(i), ber, r)?;
            } else {
                obj.set_default(i);
                if matches!(obj.get_member(i), MemberRef::Absent) {
                    has_value = false;
                }
            }
        } else {
            decode_member_ref(obj.get_member_mut(i), ber, r)?;
        }
        if has_value {
            let delta = obj.validate(i);
            if delta != 0 {
                crate::validate::check_delta(delta, name, "decode");
            }
        }
    }
    if !obj.spec().contained_members.is_empty() {
        crate::containing::decode_contained_members(obj, crate::containing::ContainedEncoding::Ber, r.depth, r.contained)
            .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.pos()))?;
    }
    Ok(())
}

pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let tag = obj.spec().tag;
    let tlv = r.read_tlv()?;
    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    let mut content = r.sub(tlv.value);
    decode_seq_content_into(obj, &mut content)
}

/// Decode counterpart of `encode_seq_tagged`.
pub fn decode_seq_tagged_into(obj: &mut dyn Asn1Seq, r: &mut Reader, tag: Tag, explicit: bool) -> Result<(), DecodeError> {
    decode_composite_member(obj, if explicit { BerTagging::Explicit(tag) } else { BerTagging::Implicit(tag) }, r)
}

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

/// The alternative-dispatch encoding (X.680 §28 — no outer wrapper of its
/// own), before any `own_tag` wrap.
fn encode_choice_dispatch(obj: &dyn Asn1Choice, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    if let Some(i) = obj.active_index() {
        let ber = obj.spec().alternatives[i].ber;
        return encode_member_ref(obj.get_active(), ber, out, opts);
    }
    if let Some((tag, bytes)) = obj.extract_unknown_extension() {
        write_primitive(out, tag, bytes);
        return Ok(());
    }
    Err(crate::spec::object::no_alternative_selected(obj.spec()))
}

/// Appends a CHOICE's encoding to an existing buffer.
pub fn encode_choice_into(obj: &dyn Asn1Choice, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    match obj.spec().own_tag {
        Some(tag) => write_explicit(out, tag, |inner| encode_choice_dispatch(obj, inner, opts)),
        None => encode_choice_dispatch(obj, out, opts),
    }
}

pub fn encode_choice(obj: &dyn Asn1Choice) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_choice_into(obj, &mut out, None)?;
    Ok(out)
}

/// IMPLICIT-retags a CHOICE-with-own_tag value under `tag` instead of its
/// own declared `[n]` (X.680 §22.5/§28.4).
pub fn encode_choice_tagged(obj: &dyn Asn1Choice, tag: Tag, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    write_tagged(out, tag, |out| encode_choice_dispatch(obj, out, opts))
}

/// Decode counterpart of `encode_choice_tagged`.
pub fn decode_choice_tagged_into(obj: &mut dyn Asn1Choice, r: &mut Reader, tag: Tag) -> Result<(), DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    let mut inner = r.sub(tlv.value);
    decode_choice_dispatch(obj, &mut inner)
}

pub fn decode_choice_into(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    match obj.spec().own_tag {
        Some(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut inner = r.sub(tlv.value);
            decode_choice_dispatch(obj, &mut inner)
        }
        None => decode_choice_dispatch(obj, r),
    }
}

/// Peeks the wire tag, selects the alternative through `ber_tags` and
/// decodes its payload in place. Falls back to the unknown-extension
/// capture (if present) by capturing the whole TLV instead of erroring.
fn decode_choice_dispatch(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    let found = obj
        .spec()
        .ber_tags
        .binary_search_by_key(&tag.identifier_key(), |d| d.tag.identifier_key())
        .ok()
        .map(|i| obj.spec().ber_tags[i].alt);
    if let Some(alt_idx) = found {
        let ber = obj.spec().alternatives[alt_idx].ber;
        decode_member_ref(obj.select_mut(alt_idx), ber, r)?;
        if !obj.spec().has_contained {
            return Ok(());
        }
        return crate::containing::decode_contained_alternative(obj, crate::containing::ContainedEncoding::Ber, r.depth, r.contained)
            .map_err(|e| DecodeError::new(format!("{}.{e}", obj.spec().name), r.pos()));
    }
    let tlv = r.read_tlv()?;
    obj.construct_unknown_extension(tlv.tag, tlv.value.to_vec());
    if obj.extract_unknown_extension().is_some() {
        return Ok(());
    }
    // Trace a CHOICE tag miss (DBG_BER_CHOICE) before falling back to the
    // unknown-extension path, so a decode failure here is diagnosable
    // without a rebuild.
    if crate::debug::debug_flags() & crate::debug::DBG_BER_CHOICE != 0 {
        let alt_tags: Vec<Tag> = obj.spec().ber_tags.iter().map(|d| d.tag).collect();
        eprintln!("[DBG_BER_CHOICE] no alternative matches peek tag {tag:?} — known tags: {alt_tags:?}");
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative tag {tag:?}"), 0))
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

/// @brief Writes the elements of a SEQUENCE OF / SET OF, no outer TLV.
///        A SET OF with more than one element is written in ascending
///        order of the elements' encodings, as DER requires (X.690
///        §11.6) and the C++ `SeqOfBerHandler` does; a SEQUENCE OF keeps
///        its order.
/// @param obj The collection; `natural_tag()` tells SET OF apart.
/// @param out Destination buffer.
/// @return `Err` when an element cannot be encoded.
/// @see X.690 §8.10, §8.12, §11.6.
pub fn encode_seqof_content(obj: &dyn Asn1SeqOf, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    if obj.natural_tag() == crate::spec::sequence::SET_TAG && obj.len() > 1 {
        let mut parts: Vec<Vec<u8>> = (0..obj.len())
            .map(|i| {
                let mut buf = Vec::new();
                encode_member_ref(obj.get(i), BerTagging::Delegate, &mut buf, opts)?;
                Ok(buf)
            })
            .collect::<Result<_, EncodeError>>()?;
        parts.sort();
        for p in &parts {
            out.extend_from_slice(p);
        }
        return Ok(());
    }
    for i in 0..obj.len() {
        encode_member_ref(obj.get(i), BerTagging::Delegate, out, opts)?;
    }
    Ok(())
}

/// @brief Decodes the elements of a SEQUENCE OF / SET OF, no outer TLV.
///        Reserves the backing `Vec` once via `Asn1SeqOf::reserve` from a
///        zero-copy top-level-TLV pre-count (`count_top_level_tlvs`)
///        instead of letting `push_default_mut` regrow it geometrically
///        one element at a time.
/// @param obj     The collection, `Default`-fresh.
/// @param content Reader over the element TLVs, at the decode's nesting
///                depth (`Reader::sub`).
/// @return `Err` when an element fails to decode.
/// @see X.690 §8.10, §8.12.
pub fn decode_seqof_content(obj: &mut dyn Asn1SeqOf, mut content: Reader) -> Result<(), DecodeError> {
    obj.reserve(crate::ber::sequence::count_top_level_tlvs(content.remaining()));
    while !content.at_end() {
        decode_member_ref(obj.push_default_mut(), BerTagging::Delegate, &mut content)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Top-level (document root) entry points
// ---------------------------------------------------------------------

/// Top-level SIZE check on a named SEQUENCE OF/SET OF (X.680 §51.5);
/// a SEQUENCE/SET/CHOICE root validates its own members inside the
/// member loop instead.
fn check_pdu_size<T: Asn1Pdu + ?Sized>(v: &T, phase: &str) {
    if let MemberRef::SeqOf(s) = v.as_member_ref() {
        let delta = crate::constraints::validate_size(s.len(), T::PDU_CONSTRAINTS);
        if delta != 0 {
            crate::validate::check_delta(delta, s.own_xer_name(), phase);
        }
    }
}

/// @brief Appends `v`'s complete BER TLV under its own natural (or
///        type-assignment-overridden) tag to `out`.
/// @param v    Any generated SEQUENCE/SET/CHOICE/SEQUENCE OF type.
/// @param out  Output buffer; existing bytes are kept (multi-record
///             streams append one record per call).
/// @return `Err` when `v` holds a value this runtime cannot encode; `out`
///         then holds a partial record the caller should discard.
/// @see X.690 §8.9–§8.13 — constructed-type encodings; §8.14 tagging.
pub fn encode_pdu_into<T: Asn1Pdu + ?Sized>(v: &T, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    encode_pdu_into_with(v, out, None)
}

/// @brief `encode_pdu_into` with contained-value settings: the decoder
///        registry's encode side applies to every modified contained field
///        (X.682 §11).
pub fn encode_pdu_into_with<T: Asn1Pdu + ?Sized>(v: &T, out: &mut Vec<u8>, opts: Option<&ContainedOptions>) -> Result<(), EncodeError> {
    check_pdu_size(v, "encode");
    encode_member_ref(v.as_member_ref(), BerTagging::Delegate, out, opts)
}

/// @brief One-record form of `encode_pdu_into_with`.
pub fn encode_pdu_with<T: Asn1Pdu + ?Sized>(v: &T, opts: &ContainedOptions) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_pdu_into_with(v, &mut out, Some(opts))?;
    Ok(out)
}

/// @brief One-record convenience form of `encode_pdu_into`.
/// @return The encoded TLV, or `Err` as `encode_pdu_into`.
pub fn encode_pdu<T: Asn1Pdu + ?Sized>(v: &T) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_pdu_into(v, &mut out)?;
    Ok(out)
}

/// @brief Decodes one top-level TLV from `r` into `v`, leaving `r`
///        positioned just past it — the streaming form for files that
///        concatenate records (callers read `r.pos()` afterwards).
/// @param v  Destination; expected to be `Default`-fresh.
/// @param r  Reader positioned at the record's tag octet.
/// @return `Err` on malformed BER or a tag mismatch.
/// @see X.690 §8.1 — TLV structure.
pub fn decode_pdu_into<T: Asn1Pdu + ?Sized>(v: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    decode_member_ref(v.as_member_ref_mut(), BerTagging::Delegate, r)?;
    check_pdu_size(v, "decode");
    Ok(())
}

/// @brief Whole-buffer form of `decode_pdu_into`: decodes the first
///        record in `data`.
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
    use crate::constraints::UNCONSTRAINED;
    use crate::integer::{Integer, INTEGER_TAG};
    use crate::spec::object::{MemberMeta, SequenceSpec};
    use crate::spec::sequence::SEQUENCE_TAG;

    /// `Inner ::= SEQUENCE { x INTEGER }` — worked example + test subject
    /// for the reflective `Asn1Seq` design, same dogfooding role `Point`
    /// plays for `ber::sequence`.
    #[derive(Debug, Default, Clone, PartialEq)]
    struct Inner {
        x: Integer,
    }

    static INNER_MEMBERS: [MemberMeta; 1] = [MemberMeta {
        name: "x",
        tag: INTEGER_TAG,
        optional: false,
        ber: BerTagging::Delegate,
        constraints: &UNCONSTRAINED,
        xer_instruction: crate::spec::object::XerInstruction::Default,
        contained: None,
    }];

    static INNER_SPEC: SequenceSpec = SequenceSpec {
        name: "Inner",
        tag: SEQUENCE_TAG,
        members: &INNER_MEMBERS,
        ext_at: -1,
        roms_count: 0,
        is_set: false,
        ext_units: &[],
        group_member_optional: &[],
        contained_members: &[],
    };

    impl Asn1Seq for Inner {
        fn spec(&self) -> &'static SequenceSpec {
            &INNER_SPEC
        }
        fn get_member(&self, i: usize) -> MemberRef<'_> {
            match i {
                0 => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(&self.x)),
                _ => unreachable!(),
            }
        }
        fn get_member_mut(&mut self, i: usize) -> MemberRefMut<'_> {
            match i {
                0 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut self.x)),
                _ => unreachable!(),
            }
        }
        fn set_default(&mut self, _i: usize) {}
        fn is_default_equal(&self, _i: usize) -> bool {
            false
        }
        fn validate(&self, _i: usize) -> i64 {
            0
        }
    }

    /// `Outer ::= SEQUENCE { y INTEGER, inner Inner, maybe INTEGER OPTIONAL }`
    /// — exercises required scalar + required composite + absent-optional
    /// recursion together, the same shape `Contact`/`PhoneNumber` have.
    #[derive(Debug, Default, Clone, PartialEq)]
    struct Outer {
        y: Integer,
        inner: Inner,
        maybe: Option<Integer>,
    }

    static OUTER_MEMBERS: [MemberMeta; 3] = [
        MemberMeta { name: "y", tag: INTEGER_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, contained: None },
        MemberMeta { name: "inner", tag: SEQUENCE_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, contained: None },
        MemberMeta { name: "maybe", tag: INTEGER_TAG, optional: true, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, contained: None },
    ];

    static OUTER_SPEC: SequenceSpec = SequenceSpec {
        name: "Outer",
        tag: SEQUENCE_TAG,
        members: &OUTER_MEMBERS,
        ext_at: -1,
        roms_count: 1,
        is_set: false,
        ext_units: &[],
        group_member_optional: &[],
        contained_members: &[],
    };

    impl Asn1Seq for Outer {
        fn spec(&self) -> &'static SequenceSpec {
            &OUTER_SPEC
        }
        fn get_member(&self, i: usize) -> MemberRef<'_> {
            match i {
                0 => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(&self.y)),
                1 => MemberRef::Composite(&self.inner),
                2 => self.maybe.as_ref().map_or(MemberRef::Absent, |v| MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v))),
                _ => unreachable!(),
            }
        }
        fn get_member_mut(&mut self, i: usize) -> MemberRefMut<'_> {
            match i {
                0 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut self.y)),
                1 => MemberRefMut::Composite(&mut self.inner),
                2 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(self.maybe.get_or_insert_with(Default::default))),
                _ => unreachable!(),
            }
        }
        fn set_default(&mut self, _i: usize) {}
        fn is_default_equal(&self, _i: usize) -> bool {
            false
        }
        fn validate(&self, _i: usize) -> i64 {
            0
        }
    }

    fn roundtrip(v: &Outer) -> Outer {
        let bytes = encode_seq(v).unwrap();
        let mut r = Reader::new(&bytes);
        let mut out = Outer::default();
        decode_seq_into(&mut out, &mut r).unwrap();
        out
    }

    #[test]
    fn encodes_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        // SEQUENCE { INTEGER 7, SEQUENCE { INTEGER 5 } } — no `maybe` (absent optional).
        assert_eq!(encode_seq(&v).unwrap(), vec![0x30, 0x08, 0x02, 0x01, 0x07, 0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn round_trips_without_optional() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn round_trips_with_optional_present() {
        let v = Outer { y: Integer(-3), inner: Inner { x: Integer(42) }, maybe: Some(Integer(99)) };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn xer_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: Some(Integer(1)) };
        let xml = crate::xer::object::encode_seq(&v).unwrap();
        let mut r = crate::xer::reader::XerReader::new(&xml);
        let mut out = Outer::default();
        crate::xer::object::decode_seq_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn jer_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        let json = crate::jer::object::encode_seq(&v).unwrap();
        let mut r = crate::jer::reader::Reader::new(&json);
        let mut out = Outer::default();
        crate::jer::object::decode_seq_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn per_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: Some(Integer(3)) };
        let mut w = crate::per::writer::Writer::new();
        crate::per::object::encode_seq_content(&v, &mut w, None).unwrap();
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut out = Outer::default();
        crate::per::object::decode_seq_content_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }

    /// `Choice ::= CHOICE { num INTEGER, nested Inner }` — worked example
    /// for `Asn1Choice`.
    #[derive(Debug, Clone, PartialEq)]
    enum Choice {
        Num(Integer),
        Nested(Inner),
    }
    impl Default for Choice {
        fn default() -> Self {
            Choice::Num(Integer(0))
        }
    }

    static CHOICE_ALTS: [crate::spec::object::AltMeta; 2] = [
        crate::spec::object::AltMeta { name: "num", ber: BerTagging::Implicit(INTEGER_TAG), constraints: &UNCONSTRAINED, contained: None },
        crate::spec::object::AltMeta { name: "nested", ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, contained: None },
    ];
    static CHOICE_BER_TAGS: [crate::spec::choice::BerDispatch; 2] = [
        crate::spec::choice::BerDispatch { tag: INTEGER_TAG, alt: 0 },
        crate::spec::choice::BerDispatch { tag: SEQUENCE_TAG, alt: 1 },
    ];
    static CHOICE_SPEC: crate::spec::object::ChoiceSpec = crate::spec::object::ChoiceSpec {
        name: "Choice",
        alternatives: &CHOICE_ALTS,
        ber_tags: &CHOICE_BER_TAGS,
        own_tag: None,
        ext_at: -1,
        range_bits: 1, has_contained: false,
    };
    impl Asn1Choice for Choice {
        fn spec(&self) -> &'static crate::spec::object::ChoiceSpec {
            &CHOICE_SPEC
        }
        fn active_index(&self) -> Option<usize> {
            match self {
                Choice::Num(_) => Some(0),
                Choice::Nested(_) => Some(1),
            }
        }
        fn get_active(&self) -> MemberRef<'_> {
            match self {
                Choice::Num(v) => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v)),
                Choice::Nested(v) => MemberRef::Composite(v),
            }
        }
        fn select_mut(&mut self, index: usize) -> MemberRefMut<'_> {
            match index {
                0 => {
                    if !matches!(self, Choice::Num(_)) {
                        *self = Choice::Num(Default::default());
                    }
                    match self {
                        Choice::Num(v) => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(v)),
                        _ => unreachable!(),
                    }
                }
                1 => {
                    if !matches!(self, Choice::Nested(_)) {
                        *self = Choice::Nested(Default::default());
                    }
                    match self {
                        Choice::Nested(v) => MemberRefMut::Composite(v),
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }
        fn construct_unknown_extension(&mut self, _tag: Tag, _bytes: Vec<u8>) {}
        fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])> {
            None
        }
    }

    fn roundtrip_choice(v: &Choice) -> Choice {
        let bytes = encode_choice(v).unwrap();
        let mut r = Reader::new(&bytes);
        let mut out = Choice::default();
        decode_choice_into(&mut out, &mut r).unwrap();
        out
    }

    #[test]
    fn choice_round_trips_primitive_alternative() {
        let v = Choice::Num(Integer(42));
        assert_eq!(roundtrip_choice(&v), v);
    }

    #[test]
    fn choice_round_trips_composite_alternative() {
        let v = Choice::Nested(Inner { x: Integer(7) });
        assert_eq!(roundtrip_choice(&v), v);
    }

    /// `Frame ::= SEQUENCE { ident INTEGER, value ANY }` with `value` an
    /// untagged ANY codegen marks unsupported: its accessors hand back
    /// `MemberRef::Unsupported`, as `RustBackend` emits for such a row.
    #[derive(Debug, Default)]
    struct Frame {
        ident: Integer,
    }

    const FRAME_UNSUPPORTED: &str = "member 'value' not supported: untagged ANY has no tag to detect presence";

    static FRAME_MEMBERS: [MemberMeta; 2] = [
        MemberMeta { name: "ident", tag: INTEGER_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, contained: None },
        MemberMeta { name: "value", tag: SEQUENCE_TAG, optional: false, ber: BerTagging::Unsupported("untagged ANY has no tag to detect presence"), constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, contained: None },
    ];

    static FRAME_SPEC: SequenceSpec = SequenceSpec {
        name: "Frame",
        tag: SEQUENCE_TAG,
        members: &FRAME_MEMBERS,
        ext_at: -1,
        roms_count: 0,
        is_set: false,
        ext_units: &[],
        group_member_optional: &[],
        contained_members: &[],
    };

    impl Asn1Seq for Frame {
        fn spec(&self) -> &'static SequenceSpec {
            &FRAME_SPEC
        }
        fn get_member(&self, i: usize) -> MemberRef<'_> {
            match i {
                0 => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(&self.ident)),
                _ => MemberRef::Unsupported(FRAME_UNSUPPORTED),
            }
        }
        fn get_member_mut(&mut self, i: usize) -> MemberRefMut<'_> {
            match i {
                0 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut self.ident)),
                _ => MemberRefMut::Unsupported(FRAME_UNSUPPORTED),
            }
        }
        fn set_default(&mut self, _i: usize) {}
        fn is_default_equal(&self, _i: usize) -> bool {
            false
        }
        fn validate(&self, _i: usize) -> i64 {
            0
        }
    }

    #[test]
    fn unsupported_member_fails_every_encode_without_panicking() {
        let v = Frame { ident: Integer(1) };
        assert_eq!(encode_seq(&v).unwrap_err().message, FRAME_UNSUPPORTED);
        assert_eq!(crate::xer::object::encode_seq(&v).unwrap_err().message, FRAME_UNSUPPORTED);
        assert_eq!(crate::jer::object::encode_seq(&v).unwrap_err().message, FRAME_UNSUPPORTED);
        let mut w = crate::per::writer::Writer::new();
        assert_eq!(crate::per::object::encode_seq_content(&v, &mut w, None).unwrap_err().message, FRAME_UNSUPPORTED);
    }

    #[test]
    fn unsupported_member_fails_every_decode_without_panicking() {
        // SEQUENCE { INTEGER 1, INTEGER 2 } — the second TLV is where the
        // ANY would be.
        let ber = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let e = decode_seq_into(&mut Frame::default(), &mut Reader::new(&ber)).unwrap_err();
        assert_eq!(e.message, FRAME_UNSUPPORTED);

        let xml = "<Frame><ident>1</ident><value>2</value></Frame>";
        let e = crate::xer::object::decode_seq_into(&mut Frame::default(), &mut crate::xer::reader::XerReader::new(xml)).unwrap_err();
        assert_eq!(e.message, FRAME_UNSUPPORTED);

        let json = r#"{"ident":1,"value":"02"}"#;
        let e = crate::jer::object::decode_seq_into(&mut Frame::default(), &mut crate::jer::reader::Reader::new(json)).unwrap_err();
        assert_eq!(e.message, FRAME_UNSUPPORTED);

        let per = [0x01, 0x01, 0x01, 0x02];
        let e = crate::per::object::decode_seq_content_into(&mut Frame::default(), &mut crate::per::reader::Reader::new(&per)).unwrap_err();
        assert_eq!(e.message, FRAME_UNSUPPORTED);
    }

    /// `Ext ::= CHOICE { num INTEGER, ... }` holding an alternative this
    /// schema version does not know (X.680 §29.6).
    #[derive(Debug)]
    enum Ext {
        Num(Integer),
        UnknownExtension(Tag, Vec<u8>),
    }

    static EXT_ALTS: [crate::spec::object::AltMeta; 1] =
        [crate::spec::object::AltMeta { name: "num", ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, contained: None }];
    static EXT_BER_TAGS: [crate::spec::choice::BerDispatch; 1] = [crate::spec::choice::BerDispatch { tag: INTEGER_TAG, alt: 0 }];
    static EXT_SPEC: crate::spec::object::ChoiceSpec = crate::spec::object::ChoiceSpec {
        name: "Ext",
        alternatives: &EXT_ALTS,
        ber_tags: &EXT_BER_TAGS,
        own_tag: None,
        ext_at: 1,
        range_bits: 0, has_contained: false,
    };
    impl Asn1Choice for Ext {
        fn spec(&self) -> &'static crate::spec::object::ChoiceSpec {
            &EXT_SPEC
        }
        fn active_index(&self) -> Option<usize> {
            match self {
                Ext::Num(_) => Some(0),
                Ext::UnknownExtension(..) => None,
            }
        }
        fn get_active(&self) -> MemberRef<'_> {
            match self {
                Ext::Num(v) => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v)),
                Ext::UnknownExtension(..) => MemberRef::Unsupported("CHOICE Ext: no alternative selected"),
            }
        }
        fn select_mut(&mut self, _index: usize) -> MemberRefMut<'_> {
            *self = Ext::Num(Integer(0));
            match self {
                Ext::Num(v) => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(v)),
                Ext::UnknownExtension(..) => unreachable!(),
            }
        }
        fn construct_unknown_extension(&mut self, tag: Tag, bytes: Vec<u8>) {
            *self = Ext::UnknownExtension(tag, bytes);
        }
        fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])> {
            match self {
                Ext::UnknownExtension(t, b) => Some((*t, b.as_slice())),
                Ext::Num(_) => None,
            }
        }
    }

    #[test]
    fn choice_without_known_alternative_fails_encode_without_panicking() {
        let v = Ext::UnknownExtension(Tag::context(5, false), vec![0x01]);
        // BER replays the captured TLV (X.690 §8.1).
        assert_eq!(encode_choice(&v).unwrap(), vec![0x85, 0x01, 0x01]);
        let msg = "CHOICE Ext: no alternative selected";
        assert_eq!(crate::xer::object::encode_choice(&v).unwrap_err().message, msg);
        let mut json = String::new();
        assert_eq!(crate::jer::object::encode_choice_into(&v, &mut json, None).unwrap_err().message, msg);
        let mut w = crate::per::writer::Writer::new();
        assert_eq!(crate::per::object::encode_choice_content(&v, &mut w, None).unwrap_err().message, msg);
    }

    /// `Rec ::= CHOICE { a [0] INTEGER, c [2] Rec }` — self-referential
    /// (X.680 §29), so an input can nest it arbitrarily deep.
    #[derive(Debug)]
    enum Rec {
        A(Integer),
        C(Box<Rec>),
    }
    impl Default for Rec {
        fn default() -> Self {
            Rec::A(Integer(0))
        }
    }
    static REC_ALTS: [crate::spec::object::AltMeta; 2] = [
        crate::spec::object::AltMeta { name: "a", ber: BerTagging::Implicit(Tag::context(0, false)), constraints: &UNCONSTRAINED, contained: None },
        crate::spec::object::AltMeta { name: "c", ber: BerTagging::Explicit(Tag::context(2, true)), constraints: &UNCONSTRAINED, contained: None },
    ];
    static REC_BER_TAGS: [crate::spec::choice::BerDispatch; 2] = [
        crate::spec::choice::BerDispatch { tag: Tag::context(0, false), alt: 0 },
        crate::spec::choice::BerDispatch { tag: Tag::context(2, true), alt: 1 },
    ];
    static REC_SPEC: crate::spec::object::ChoiceSpec = crate::spec::object::ChoiceSpec {
        name: "Rec",
        alternatives: &REC_ALTS,
        ber_tags: &REC_BER_TAGS,
        own_tag: None,
        ext_at: -1,
        range_bits: 1, has_contained: false,
    };
    impl Asn1Choice for Rec {
        fn spec(&self) -> &'static crate::spec::object::ChoiceSpec {
            &REC_SPEC
        }
        fn active_index(&self) -> Option<usize> {
            Some(match self {
                Rec::A(_) => 0,
                Rec::C(_) => 1,
            })
        }
        fn get_active(&self) -> MemberRef<'_> {
            match self {
                Rec::A(v) => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v)),
                Rec::C(v) => MemberRef::Choice(&**v),
            }
        }
        fn select_mut(&mut self, index: usize) -> MemberRefMut<'_> {
            *self = if index == 0 { Rec::A(Integer(0)) } else { Rec::C(Box::default()) };
            match self {
                Rec::A(v) => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(v)),
                Rec::C(v) => MemberRefMut::Choice(&mut **v),
            }
        }
        fn construct_unknown_extension(&mut self, _tag: Tag, _bytes: Vec<u8>) {}
        fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])> {
            None
        }
    }

    fn nested(levels: usize) -> Rec {
        (0..levels).fold(Rec::A(Integer(5)), |inner, _| Rec::C(Box::new(inner)))
    }

    /// Decodes `levels`-deep `Rec` in every codec; `true` per codec when
    /// the decode succeeded.
    fn decode_nested(levels: usize) -> [bool; 4] {
        let v = nested(levels);
        let ber = encode_choice(&v).unwrap();
        let xml = crate::xer::object::encode_choice(&v).unwrap();
        let mut json = String::new();
        crate::jer::object::encode_choice_into(&v, &mut json, None).unwrap();
        let mut w = crate::per::writer::Writer::new();
        crate::per::object::encode_choice_content(&v, &mut w, None).unwrap();
        w.flush();
        let per = w.into_bytes();
        let ok = [
            decode_choice_into(&mut Rec::default(), &mut Reader::new(&ber)).is_ok(),
            crate::xer::object::decode_choice(&xml, &mut Rec::default()).is_ok(),
            crate::jer::object::decode_choice_into(&mut Rec::default(), &mut crate::jer::reader::Reader::new(&json)).is_ok(),
            crate::per::object::decode_choice_content_into(&mut Rec::default(), &mut crate::per::reader::Reader::new(&per)).is_ok(),
        ];
        // Drop iteratively: a deep Box chain would recurse in Drop.
        let mut cur = v;
        while let Rec::C(inner) = cur {
            cur = *inner;
        }
        ok
    }

    #[test]
    fn decode_nesting_is_limited_in_every_codec() {
        let max = crate::nesting::MAX_DECODE_DEPTH as usize;
        assert_eq!(decode_nested(max - 1), [true; 4]);
        assert_eq!(decode_nested(max + 1), [false; 4]);
        let e = decode_choice_into(&mut Rec::default(), &mut Reader::new(&encode_choice(&nested(max + 1)).unwrap())).unwrap_err();
        assert!(e.message.contains("nesting deeper than"), "{}", e.message);
    }

    /// `Basket ::= SEQUENCE OF INTEGER` — worked example for `Asn1SeqOf`.
    fn roundtrip_seqof(v: &crate::ber::sequence::SeqOf<Integer>) -> crate::ber::sequence::SeqOf<Integer> {
        let mut out = Vec::new();
        out.push(0x30u8); // placeholder, overwritten below
        let mut content = Vec::new();
        encode_seqof_content(v, &mut content, None).unwrap();
        let mut full = Vec::new();
        write_tagged(&mut full, SEQUENCE_TAG, |out| out.extend_from_slice(&content));
        let mut r = Reader::new(&full);
        let tlv = r.read_tlv().unwrap();
        let mut result = crate::ber::sequence::SeqOf::<Integer>::default();
        decode_seqof_content(&mut result, Reader::new(tlv.value)).unwrap();
        let _ = out;
        result
    }

    #[test]
    fn seqof_round_trips_primitive_elements() {
        let v = crate::ber::sequence::SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        assert_eq!(roundtrip_seqof(&v), v);
    }

    #[test]
    fn set_of_is_written_in_der_order_sequence_of_is_not() {
        use crate::ber::sequence::{SeqOf, SetOf};
        let vals = vec![Integer(300), Integer(5), Integer(-1)];
        let mut set = Vec::new();
        encode_seqof_content(&SetOf(vals.clone()), &mut set, None).unwrap();
        // DER (X.690 §11.6): ascending by encoding:
        // 02 01 05 < 02 01 FF < 02 02 01 2C
        assert_eq!(set, vec![0x02, 0x01, 0x05, 0x02, 0x01, 0xFF, 0x02, 0x02, 0x01, 0x2C]);
        let mut seq = Vec::new();
        encode_seqof_content(&SeqOf(vals), &mut seq, None).unwrap();
        assert_eq!(seq, vec![0x02, 0x02, 0x01, 0x2C, 0x02, 0x01, 0x05, 0x02, 0x01, 0xFF]);
    }
}
