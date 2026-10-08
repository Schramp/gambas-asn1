//! The closed set of ASN.1 builtin leaf types (X.680 §18-19/§41, no
//! recursion) — "codec uses type", not "type has a codec" (gambas-asn1
//! #674/#681): a `MemberDescriptor<T>`/`Alternative<T>` row for one of
//! these types stores *one* accessor (`get`/`get_mut`, below) rather
//! than 8 separate per-codec closures. That accessor's own address is
//! all any static table ever takes — its body never names a specific
//! codec's encode/decode function, so building the table does not,
//! by itself, force every codec's machinery for that member's type to
//! be compiled in. Each codec module provides its own small, hand-
//! written, non-generated `match` over this enum (`ber_encode_primitive`
//! etc., below) — reused by every generated type alike, exactly
//! mirroring the C++ side's `prim_dispatch_[32]` (one shared array,
//! indexed by tag, read by `BerCodec`/`JerCodec`/...) versus a
//! per-type generated switch. A composite member (SEQUENCE/SET/CHOICE/
//! SEQUENCE OF/SET OF/ENUMERATED — unbounded, per-schema) can't join
//! this closed enum; it keeps `MemberAccess::Composite`'s per-codec
//! closures, each naming that one inner type's own static table
//! directly (unavoidable — there is no shared handler for an open-
//! ended set of generated types the way there is for 26 fixed
//! builtins).
//!
//! An application that only calls `.encode()`/`.decode()` (BER) never
//! calls `xer_encode_primitive`/`jer_encode_primitive`/
//! `per_encode_primitive` — and nothing else references them either,
//! since no table stores their address — so rustc's own reachability-
//! based dead code elimination removes them, and everything they
//! called (string escaping, JSON writing, PER bit-packing...), for
//! real this time (gambas-asn1#681, following up on #675/#677/#678,
//! whose flat-closure design removed the vtable but not the force-
//! linking: every closure's address still had to be taken to populate
//! the table, which is enough to keep a function alive regardless of
//! whether anything actually calls it through that pointer).

use crate::any::Any;
use crate::bit_string::BitString;
use crate::boolean::Boolean;
use crate::integer::{ArbitraryInteger, BigInteger, Integer, UInteger};
use crate::null::Null;
use crate::octet_string::OctetString;
use crate::oid::ObjectIdentifier;
use crate::real::Real;
use crate::relative_oid::RelativeOid;
use crate::strings::{
    BmpString, GeneralString, GeneralizedTime, GraphicString, Ia5String, NumericString,
    ObjectDescriptor, PrintableString, T61String, UniversalString, UtcTime, VideotexString,
    Utf8String, VisibleString,
};
use crate::value::Asn1Value;

use crate::ber::reader::{DecodeError as BerDecodeError, Reader as BerReader};
use crate::ber::tag::Tag;
use crate::jer::reader::Reader as JerReader;
use crate::per::reader::{DecodeError as PerDecodeError, Reader as PerReader};
use crate::per::writer::Writer as PerWriter;
use crate::xer::reader::XerReader;
use crate::spec::choice::BerTagging;

/// Invokes `$m!` once per builtin leaf kind with `(Variant, Type)` pairs —
/// the single source of truth for `PrimitiveRef`/`PrimitiveRefMut` and
/// every per-codec dispatch `match` below. Adding a 27th builtin means
/// adding one line here, not touching any of the matches by hand.
macro_rules! for_each_primitive {
    ($m:ident) => {
        $m! {
            Boolean => Boolean,
            Integer => Integer,
            UInteger => UInteger,
            BigInteger => BigInteger,
            ArbitraryInteger => ArbitraryInteger,
            Real => Real,
            Null => Null,
            OctetString => OctetString,
            BitString => BitString,
            ObjectIdentifier => ObjectIdentifier,
            RelativeOid => RelativeOid,
            Any => Any,
            Utf8String => Utf8String,
            NumericString => NumericString,
            PrintableString => PrintableString,
            T61String => T61String,
            Ia5String => Ia5String,
            VisibleString => VisibleString,
            GeneralString => GeneralString,
            GraphicString => GraphicString,
            UniversalString => UniversalString,
            BmpString => BmpString,
            VideotexString => VideotexString,
            ObjectDescriptor => ObjectDescriptor,
            UtcTime => UtcTime,
            GeneralizedTime => GeneralizedTime,
        }
    };
}

macro_rules! define_ref_enum {
    ($($variant:ident => $ty:ident,)+) => {
        /// A borrowed reference to one builtin leaf value, tagged by
        /// kind — codegen picks the variant for a given member/
        /// alternative at compile time (`RustBackend::emit_...`), so
        /// this enum only exists for the *codec* side's own generic
        /// `match`, never for runtime type discovery.
        #[derive(Clone, Copy)]
        pub enum PrimitiveRef<'a> {
            $($variant(&'a $ty),)+
        }

        /// Mutable counterpart, used by every codec's decode leg.
        pub enum PrimitiveRefMut<'a> {
            $($variant(&'a mut $ty),)+
        }
    };
}
for_each_primitive!(define_ref_enum);

macro_rules! define_ber_dispatch {
    ($($variant:ident => $ty:ident,)+) => {
        fn ber_encode_plain(p: PrimitiveRef, out: &mut Vec<u8>) {
            match p { $(PrimitiveRef::$variant(x) => x.ber_encode(out),)+ }
        }
        fn ber_encode_tagged_(p: PrimitiveRef, tag: Tag, out: &mut Vec<u8>) {
            match p { $(PrimitiveRef::$variant(x) => x.ber_encode_tagged(tag, out),)+ }
        }
        fn ber_encode_explicit_(p: PrimitiveRef, tag: Tag, out: &mut Vec<u8>) {
            match p { $(PrimitiveRef::$variant(x) => x.ber_encode_explicit(out, tag),)+ }
        }
        fn ber_decode_plain(p: PrimitiveRefMut, r: &mut BerReader) -> Result<(), BerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.ber_decode_into(r),)+ }
        }
        fn ber_decode_tagged_(p: PrimitiveRefMut, tag: Tag, r: &mut BerReader) -> Result<(), BerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.ber_decode_into_tagged(r, tag),)+ }
        }
        fn ber_decode_explicit_(p: PrimitiveRefMut, tag: Tag, r: &mut BerReader) -> Result<(), BerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.ber_decode_into_explicit(r, tag),)+ }
        }
    };
}
for_each_primitive!(define_ber_dispatch);

/// BER encode for a primitive member/alternative, honoring its own
/// `BerTagging` (X.690 §8.14) — the one piece of per-row framing a
/// primitive still needs, since `BerTagging::{Implicit,Explicit}` is a
/// codegen-time fact (the `[n]` on *this* member), not a property of
/// the enum variant.
pub fn ber_encode_primitive(p: PrimitiveRef, framing: BerTagging, out: &mut Vec<u8>) {
    match framing {
        BerTagging::Implicit(tag) => ber_encode_tagged_(p, tag, out),
        BerTagging::Explicit(tag) => ber_encode_explicit_(p, tag, out),
        BerTagging::Delegate => ber_encode_plain(p, out),
        BerTagging::Unsupported(reason) => panic!("primitive not supported: {reason}"),
    }
}

/// Decode counterpart of [`ber_encode_primitive`].
pub fn ber_decode_primitive(p: PrimitiveRefMut, framing: BerTagging, r: &mut BerReader) -> Result<(), BerDecodeError> {
    match framing {
        BerTagging::Implicit(tag) => ber_decode_tagged_(p, tag, r),
        BerTagging::Explicit(tag) => ber_decode_explicit_(p, tag, r),
        BerTagging::Delegate => ber_decode_plain(p, r),
        BerTagging::Unsupported(reason) => panic!("primitive not supported: {reason}"),
    }
}

macro_rules! define_xer_dispatch {
    ($($variant:ident => $ty:ident,)+) => {
        /// XER encode — no BER tag concept, so no framing parameter
        /// (X.693 element names are fixed per type, same for every
        /// tagging the BER side might apply to this same member).
        pub fn xer_encode_primitive(p: PrimitiveRef, out: &mut String, depth: usize) {
            match p { $(PrimitiveRef::$variant(x) => x.xer_encode(out, depth),)+ }
        }
        pub fn xer_decode_primitive(p: PrimitiveRefMut, r: &mut XerReader) -> Result<(), BerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.xer_decode_into(r),)+ }
        }
    };
}
for_each_primitive!(define_xer_dispatch);

macro_rules! define_jer_dispatch {
    ($($variant:ident => $ty:ident,)+) => {
        pub fn jer_encode_primitive(p: PrimitiveRef, out: &mut String) {
            match p { $(PrimitiveRef::$variant(x) => x.jer_encode(out),)+ }
        }
        pub fn jer_decode_primitive(p: PrimitiveRefMut, r: &mut JerReader) -> Result<(), BerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.jer_decode_into(r),)+ }
        }
    };
}
for_each_primitive!(define_jer_dispatch);

macro_rules! define_per_dispatch {
    ($($variant:ident => $ty:ident,)+) => {
        pub fn per_encode_primitive(p: PrimitiveRef, w: &mut PerWriter, c: &crate::constraints::Constraints) {
            match p { $(PrimitiveRef::$variant(x) => x.per_encode(w, c),)+ }
        }
        pub fn per_decode_primitive(p: PrimitiveRefMut, r: &mut PerReader, c: &crate::constraints::Constraints) -> Result<(), PerDecodeError> {
            match p { $(PrimitiveRefMut::$variant(x) => x.per_decode_into(r, c),)+ }
        }
    };
}
for_each_primitive!(define_per_dispatch);
