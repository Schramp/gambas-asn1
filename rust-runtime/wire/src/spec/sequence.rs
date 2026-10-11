//! SEQUENCE/SET natural tags — X.680 §25/§26. The rest of this crate's
//! SEQUENCE/SET handling (the reflective `Asn1Seq` trait, the generic
//! BER/XER/JER/PER walkers) lives in `spec::object`/`ber::object`/
//! `xer::object`/`jer::object`/`per::object` (gambas-asn1#681 full
//! migration) — this module now holds only the two tag constants every
//! one of those still needs, kept here rather than duplicated at each
//! call site.

use crate::ber::tag::{universal, Tag};

pub const SEQUENCE_TAG: Tag = Tag::universal(universal::SEQUENCE, true);

/// SET's own natural tag (X.680 §26, universal 17, constructed) — a
/// SET-typed table must use this instead of `SEQUENCE_TAG`. X.690
/// §8.11/§8.12 SET encoding is canonically member-tag-ordered on the
/// wire, which this crate doesn't enforce.
pub const SET_TAG: Tag = Tag::universal(universal::SET, true);
