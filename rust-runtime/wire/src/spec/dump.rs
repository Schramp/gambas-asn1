//! Canonical descriptor-table dump — the cross-language table check.
//! Every runtime serialises its own static tables in one JSON format
//! (`doc/backend-guide.md`, Appendix A) and
//! `validation-tools/table_diff` compares the dumps field by field. The
//! dump reads the tables only; it never encodes or decodes a value.
//!
//! A field this runtime's tables do not carry is left out of the object;
//! the diff reports it as "not carried" rather than as a mismatch.

use crate::ber::tag::{Tag, TagClass};
use crate::constraints::Constraints;
use crate::spec::choice::BerTagging;
use crate::spec::object::{AsMemberRef, MemberRef, MemberRefMut, XerInstruction};

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn jtag(t: &Tag) -> String {
    let class = match t.class {
        TagClass::Universal => "UNIVERSAL",
        TagClass::Application => "APPLICATION",
        TagClass::Context => "CONTEXT",
        TagClass::Private => "PRIVATE",
    };
    format!("{{\"class\":\"{class}\",\"number\":{},\"constructed\":{}}}", t.number, t.constructed)
}

/// The constraint fields that carry meaning, so two runtimes that leave
/// unused fields at different values still dump alike: the value bounds of
/// the INTEGER storage in use (the unsigned pair when it is set), and only
/// when there is a bound at all; `range_bits` only for a finite range
/// (X.691 §10.5); the upper SIZE bound only for a finite SIZE range; the
/// permitted alphabet only with a FROM constraint (X.691 §26.5.4).
fn jconstraints(c: &Constraints) -> String {
    let finite = c.flags & Constraints::CONSTRAINED != 0;
    let bounded = finite || c.flags & Constraints::SEMI_CONSTRAINED != 0;
    let u64 = c.lower_u64 != 0 || c.upper_u64 != 0;
    let lower = match (bounded, u64) {
        (false, _) => "null".to_string(),
        (true, true) => c.lower_u64.to_string(),
        (true, false) => c.lower_bound.to_string(),
    };
    let upper = match (finite, u64) {
        (false, _) => "null".to_string(),
        (true, true) => c.upper_u64.to_string(),
        (true, false) => c.upper_bound.to_string(),
    };
    let range_bits = if finite { c.range_bits.to_string() } else { "null".to_string() };
    let size_upper =
        if c.flags & Constraints::SIZE_CONSTRAINED != 0 { c.size_upper.to_string() } else { "null".to_string() };
    let alphabet: String = if c.alphabet_bits == 0 {
        String::new()
    } else {
        c.alphabet.unwrap_or(&[]).iter().map(|b| format!("{b:02X}")).collect()
    };
    format!(
        "{{\"flags\":{},\"range_bits\":{range_bits},\"lower\":{lower},\"upper\":{upper},\
         \"size_range_bits\":{},\"size_lower\":{},\"size_upper\":{size_upper},\"alphabet_bits\":{},\"alphabet\":\"{alphabet}\"}}",
        c.flags, c.size_range_bits, c.size_lower, c.alphabet_bits
    )
}

/// The member's tag and framing: IMPLICIT and EXPLICIT carry the tag, a
/// delegating row or one pointing at its type's framing (`OfType`) frames
/// nothing itself (NONE), and an untagged CHOICE has
/// no tag at all (UNTAGGED_CHOICE, X.680 §31.2.7). `untagged_choice` says
/// whether a `Delegate` row's value is such a CHOICE.
fn jtagging(ber: BerTagging, tag: Option<Tag>, untagged_choice: bool) -> String {
    let (tagging, t) = match ber {
        BerTagging::Implicit(t) => ("IMPLICIT", Some(t)),
        BerTagging::Explicit(t) => ("EXPLICIT", Some(t)),
        BerTagging::DelegateChoice(_) => ("UNTAGGED_CHOICE", None),
        BerTagging::Delegate if untagged_choice => ("UNTAGGED_CHOICE", None),
        BerTagging::Delegate => ("NONE", tag),
        BerTagging::OfType(f) => match f.resolve() {
            BerTagging::Implicit(t) | BerTagging::Explicit(t) => ("NONE", Some(tag.unwrap_or(t))),
            _ => ("NONE", tag),
        },
        BerTagging::Unsupported(_) => ("UNSUPPORTED", tag),
    };
    let t = t.map_or("null".to_string(), |t| jtag(&t));
    format!("\"tag\":{t},\"tagging\":\"{tagging}\"")
}

fn xer_name(x: XerInstruction) -> &'static str {
    match x {
        XerInstruction::Default => "DEFAULT",
        XerInstruction::Base64 => "BASE64",
        XerInstruction::Utf8 => "UTF8",
    }
}

/// Canonical kind name of a builtin: its X.693 element name, with ANY for
/// the open type.
fn primitive_kind(m: MemberRef) -> &'static str {
    match crate::spec::primitive::xer_element_name_of(match m {
        MemberRef::Primitive(p) => p,
        _ => return "?",
    }) {
        "Value" => "ANY",
        n => n,
    }
}

/// For each of a CHOICE's `count` alternatives whose payload is itself a
/// CHOICE, that CHOICE's own tag: `Some(None)` for an untagged CHOICE
/// (X.680 §31.2.7), `Some(Some(tag))` for a tagged one; `None` otherwise.
/// A value holds one alternative at a time, so each is selected in turn on
/// a scratch value.
fn choice_alternatives<T: AsMemberRef + Default>(count: usize) -> Vec<Option<Option<Tag>>> {
    let mut w = T::default();
    (0..count)
        .map(|i| match w.as_member_ref_mut() {
            MemberRefMut::Choice(c) => {
                c.select_mut(i);
                match c.get_active() {
                    MemberRef::Choice(x) => Some(x.spec().own_tag),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

/// Dump one type's descriptor tables as one line of canonical JSON.
/// `name` is the ASN.1 type name, used for the shapes whose tables carry
/// none of their own (contained and unsupported values).
pub fn dump_tables<T: AsMemberRef + Default>(name: &str) -> String {
    let v = T::default();
    let m = v.as_member_ref();
    let mut out = String::new();
    match m {
        MemberRef::Composite(s) => {
            let sp = s.spec();
            let rows: Vec<String> = sp
                .members
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let untagged = matches!(s.get_member(i), MemberRef::Choice(c) if c.spec().own_tag.is_none());
                    format!(
                        "{{\"name\":{},{},\"optional\":{},\"constraints\":{},\"xer_instruction\":\"{}\",\"contained\":{}}}",
                        jstr(r.name),
                        jtagging(r.ber, Some(r.tag), untagged),
                        r.optional,
                        jconstraints(r.constraints),
                        xer_name(r.xer_instruction),
                        r.contained.is_some()
                    )
                })
                .collect();
            let units: Vec<String> =
                sp.ext_units.iter().map(|u| format!("{{\"end\":{},\"group\":{}}}", u.end, u.group)).collect();
            let contained: Vec<String> = sp.contained_members.iter().map(|i| i.to_string()).collect();
            out.push_str(&format!(
                "{{\"name\":{},\"kind\":\"{}\",\"tag\":{},\"ext_at\":{},\"roms_count\":{},\"members\":[{}],\"ext_units\":[{}],\"contained_members\":[{}]",
                jstr(sp.name),
                if sp.is_set { "SET" } else { "SEQUENCE" },
                jtag(&sp.tag),
                sp.ext_at,
                sp.roms_count,
                rows.join(","),
                units.join(","),
                contained.join(",")
            ));
        }
        MemberRef::Choice(c) => {
            let sp = c.spec();
            let inner = choice_alternatives::<T>(sp.alternatives.len());
            let rows: Vec<String> = sp
                .alternatives
                .iter()
                .zip(inner)
                .map(|(a, inner)| {
                    format!(
                        "{{\"name\":{},{},\"optional\":false,\"constraints\":{},\"contained\":{}}}",
                        jstr(a.name),
                        jtagging(a.ber, inner.flatten(), inner == Some(None)),
                        jconstraints(a.constraints),
                        a.contained.is_some()
                    )
                })
                .collect();
            let mut tags: Vec<_> = sp.ber_tags.iter().map(|d| (d.tag, d.alt)).collect();
            tags.sort_by_key(|(t, _)| (t.class as u8, t.number));
            let tags: Vec<String> = tags.iter().map(|(t, a)| format!("{{\"tag\":{},\"alt\":{a}}}", jtag(t))).collect();
            out.push_str(&format!(
                "{{\"name\":{},\"kind\":\"CHOICE\",\"tag\":{},\"ext_at\":{},\"range_bits\":{},\"alternatives\":[{}],\"ber_tags\":[{}]",
                jstr(sp.name),
                sp.own_tag.map_or("null".to_string(), |t| jtag(&t)),
                sp.ext_at,
                sp.range_bits,
                rows.join(","),
                tags.join(",")
            ));
        }
        MemberRef::SeqOf(q) => {
            let tag = q.natural_tag();
            out.push_str(&format!(
                "{{\"name\":{},\"kind\":\"{}\",\"tag\":{},\"element_xer_tag\":{}",
                jstr(q.own_xer_name()),
                if tag.number == 17 { "SET_OF" } else { "SEQUENCE_OF" },
                jtag(&tag),
                q.elem_xer_name().map_or("null".to_string(), jstr)
            ));
        }
        MemberRef::Enumerated(_, e) => {
            let entries: Vec<String> =
                e.entries.iter().map(|x| format!("{{\"value\":{},\"name\":{}}}", x.value, jstr(x.name))).collect();
            out.push_str(&format!(
                "{{\"name\":{},\"kind\":\"ENUMERATED\",\"extensible\":{},\"root_count\":{},\"entries\":[{}]",
                jstr(e.name),
                e.extensible,
                e.root_count,
                entries.join(",")
            ));
        }
        // A builtin's tables carry no name of its own.
        p @ MemberRef::Primitive(_) => out.push_str(&format!("{{\"kind\":\"{}\"", primitive_kind(p))),
        MemberRef::Contained(..) => out.push_str(&format!("{{\"name\":{},\"kind\":\"OCTET_STRING\"", jstr(name))),
        MemberRef::Absent | MemberRef::Unsupported(_) => {
            out.push_str(&format!("{{\"name\":{},\"kind\":\"UNSUPPORTED\"", jstr(name)))
        }
    }
    out.push('}');
    out
}
