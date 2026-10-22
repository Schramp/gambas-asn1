//! Contained values (X.682 §11 contents constraints, or a
//! `--container-config` sidecar entry): an OCTET STRING whose bytes are the
//! encoding of another type. Mirrors `asn1::Containing<T>` and
//! `asn1::ContainedDecoders` (`runtime/include/asn1cpp/types/Containing.hpp`,
//! `codec/ContainedDecoders.hpp`).
//!
//! The raw bytes stay authoritative for encoding: a value that was decoded
//! and not modified re-encodes byte-exact. Modifying the inner value marks
//! it dirty; encode then writes the inner value's encoding instead.
//!
//! Every codec walker sees a contained field as `MemberRef::Contained` and
//! treats it as an OCTET STRING over [`Contained::wire_octets`]. The BER and
//! PER SEQUENCE/SET and CHOICE walkers decode the inner value after all
//! members are known ([`decode_contained_members`],
//! [`decode_contained_alternative`]), so a `when` condition or an
//! application decoder can read the siblings.

use std::any::Any;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::nesting::Depth;
use crate::octet_string::OctetString;
use crate::spec::object::{Asn1Choice, Asn1Seq, AsMemberRef, MemberRef, MemberRefMut};
use crate::spec::primitive::PrimitiveRef;

/// State of a contained value after the outer decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainedStatus {
    /// No inner decode attempted (fresh value, or raw bytes set directly).
    #[default]
    NotDecoded,
    /// The inner value is available.
    Decoded,
    /// Not decoded on purpose: `decode: off`, a `when` mismatch, or decoder `none`.
    Skipped,
    /// The inner decode failed; `error()` has the reason, the raw bytes are kept.
    Failed,
}

/// Encoding rules of the contained bytes (X.682 §11.4/§11.6). `Outer` means
/// the encoding rules of the enclosing OCTET STRING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainedEncoding {
    Outer,
    Ber,
    Cer,
    Der,
    PerAligned,
    PerUnaligned,
}

/// XER/JER form of a contained value: hex only, the inner value in place of
/// the hex (X.680 §22.4, X.697 §25.4), or the inner value plus the raw hex
/// (an extension, not standard-conformant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainedText {
    Hex,
    Inline,
    InlineRaw,
}

/// Per-field table row for a contained value, on `MemberMeta::contained` /
/// `AltMeta::contained`. The inner type itself is the field's `T`.
#[derive(Debug)]
pub struct ContainedSpec {
    pub encoding: ContainedEncoding,
    /// `false`: `decode: off`, never decoded.
    pub eager: bool,
    /// Name looked up in [`ContainedDecoders`].
    pub decoder: &'static str,
    /// Index in the enclosing `SequenceSpec::members` of the `when` sibling; -1 = always.
    pub when_member: i32,
    /// Sibling value that enables the decode (enum number, integer, 0/1).
    pub when_value: i64,
    /// `on_error: fail`: a failed inner decode fails the outer decode.
    pub fail_on_error: bool,
    pub xer: ContainedText,
    pub jer: ContainedText,
}

/// Outcome of a contained-value decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedResult {
    pub status: ContainedStatus,
    /// Reason for Skipped/Failed; for Decoded a warning (e.g. non-zero padding).
    pub message: String,
}

impl ContainedResult {
    pub fn ok() -> Self {
        ContainedResult { status: ContainedStatus::Decoded, message: String::new() }
    }
    pub fn skipped(why: impl Into<String>) -> Self {
        ContainedResult { status: ContainedStatus::Skipped, message: why.into() }
    }
    pub fn failed(why: impl Into<String>) -> Self {
        ContainedResult { status: ContainedStatus::Failed, message: why.into() }
    }
}

/// The enclosing value of a contained field, for an application decoder.
#[derive(Clone, Copy)]
pub enum Outer<'a> {
    Seq(&'a dyn Asn1Seq),
    Choice(&'a dyn Asn1Choice),
}

/// What a contained-value decoder gets: the raw bytes, the field's spec, a
/// default inner value to fill, and the enclosing value.
pub struct ContainedDecodeArgs<'a, 'v> {
    pub raw: &'a [u8],
    pub spec: &'static ContainedSpec,
    pub inner: MemberRefMut<'v>,
    pub outer: Outer<'a>,
    /// Resolved encoding (never `Outer`).
    pub encoding: ContainedEncoding,
    pub decoders: &'a ContainedDecoders,
    pub(crate) depth: Depth,
    pub(crate) options: Option<&'a ContainedOptions>,
}

/// What a contained-value encoder gets: the inner value to encode.
pub struct ContainedEncodeArgs<'a> {
    pub inner: MemberRef<'a>,
    pub spec: &'static ContainedSpec,
    /// Resolved encoding (never `Outer`).
    pub encoding: ContainedEncoding,
    pub decoders: &'a ContainedDecoders,
}

/// Decoder: fills `args.inner` from `args.raw`.
pub type ContainedDecodeFn = Box<dyn for<'a, 'v> Fn(&mut ContainedDecodeArgs<'a, 'v>) -> ContainedResult + Send + Sync>;
/// Encoder: the field's bytes from `args.inner`.
pub type ContainedEncodeFn = Box<dyn for<'a> Fn(&ContainedEncodeArgs<'a>) -> Result<Vec<u8>, String> + Send + Sync>;

struct Entry {
    decode: ContainedDecodeFn,
    encode: Option<ContainedEncodeFn>,
}

/// Named contained-value decoders, as referenced by a field's `decoder`
/// setting. Pre-loaded with the built-ins `plain`, `zero_padding`, `pkcs7`
/// and `none` (same rules as the C++ `asn1::ContainedDecoders`).
pub struct ContainedDecoders {
    entries: HashMap<String, Entry>,
    /// Block size the `pkcs7` encoder pads to (default 16, AES).
    pub pkcs7_block_size: usize,
}

impl Default for ContainedDecoders {
    fn default() -> Self {
        let mut d = ContainedDecoders { entries: HashMap::new(), pkcs7_block_size: 16 };
        d.add("plain", Box::new(|a| decode_value(a, None)), Some(Box::new(encode_value)));
        d.add("zero_padding", Box::new(decode_zero_padding), Some(Box::new(encode_value)));
        d.add("pkcs7", Box::new(decode_pkcs7), Some(Box::new(encode_pkcs7)));
        d.add("none", Box::new(|_| ContainedResult::skipped("decoder 'none'")), None);
        d
    }
}

impl ContainedDecoders {
    /// The built-in registry, used when no options are given.
    pub fn defaults() -> &'static ContainedDecoders {
        static D: OnceLock<ContainedDecoders> = OnceLock::new();
        D.get_or_init(ContainedDecoders::default)
    }

    /// Register or replace the decoder `name`.
    pub fn add(&mut self, name: &str, decode: ContainedDecodeFn, encode: Option<ContainedEncodeFn>) {
        self.entries.insert(name.to_string(), Entry { decode, encode });
    }

    fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }
}

/// Contained-value settings for one decode, carried by the BER/PER readers
/// (and on to nested readers).
#[derive(Default)]
pub struct ContainedOptions {
    /// `None`: [`ContainedDecoders::defaults`].
    pub decoders: Option<ContainedDecoders>,
    /// Decode no contained value at all.
    pub off: bool,
    /// Override every field's XER form.
    pub xer: Option<ContainedText>,
    /// Override every field's JER form.
    pub jer: Option<ContainedText>,
}

impl ContainedOptions {
    fn registry(&self) -> &ContainedDecoders {
        self.decoders.as_ref().unwrap_or_else(|| ContainedDecoders::defaults())
    }
}

fn registry(opts: Option<&ContainedOptions>) -> &ContainedDecoders {
    match opts {
        Some(o) => o.registry(),
        None => ContainedDecoders::defaults(),
    }
}

/// @brief Decode `bytes` with the args' encoding into `args.inner`, for use
///        by decoders after they transformed the raw bytes.
/// @param consumed  Receives the octets the value used; when `None`, the
///                  value must use all of `bytes`.
pub fn decode_value_from<'a, 'b>(args: &mut ContainedDecodeArgs<'a, '_>, bytes: &'b [u8], consumed: Option<&mut usize>) -> ContainedResult
where
    'a: 'b,
{
    let inner = std::mem::replace(&mut args.inner, MemberRefMut::Absent);
    let used = match args.encoding {
        ContainedEncoding::Ber | ContainedEncoding::Cer | ContainedEncoding::Der => {
            let mut r = crate::ber::reader::Reader::new(bytes);
            r.depth = args.depth;
            r.contained = args.options;
            if let Err(e) = crate::ber::object::decode_member_ref(inner, crate::spec::choice::BerTagging::Delegate, &mut r) {
                return ContainedResult::failed(e.message);
            }
            r.pos()
        }
        ContainedEncoding::PerUnaligned => {
            let mut r = crate::per::reader::Reader::new(bytes);
            r.depth = args.depth;
            r.contained = args.options;
            if let Err(e) = crate::per::object::decode_member_ref(inner, &crate::constraints::UNCONSTRAINED, &mut r) {
                return ContainedResult::failed(e.message);
            }
            r.bit_pos().div_ceil(8)
        }
        ContainedEncoding::PerAligned => return ContainedResult::failed("aligned PER contents are not supported"),
        ContainedEncoding::Outer => return ContainedResult::failed("unresolved contents encoding"),
    };
    match consumed {
        Some(c) => *c = used,
        None if used < bytes.len() => {
            return ContainedResult::failed(format!("{} octets after the contained value", bytes.len() - used));
        }
        None => {}
    }
    ContainedResult::ok()
}

/// @brief `plain`: `args.raw` is exactly one value.
pub fn decode_value(args: &mut ContainedDecodeArgs, consumed: Option<&mut usize>) -> ContainedResult {
    let raw = args.raw;
    decode_value_from(args, raw, consumed)
}

/// @brief Encode `args.inner` with the args' encoding.
pub fn encode_value(args: &ContainedEncodeArgs) -> Result<Vec<u8>, String> {
    let inner = match &args.inner {
        MemberRef::Composite(v) => MemberRef::Composite(*v),
        MemberRef::Choice(v) => MemberRef::Choice(*v),
        MemberRef::SeqOf(v) => MemberRef::SeqOf(*v),
        MemberRef::Enumerated(s, e) => MemberRef::Enumerated(*s, e),
        MemberRef::Primitive(p) => MemberRef::Primitive(*p),
        MemberRef::Contained(c, sp) => MemberRef::Contained(*c, sp),
        MemberRef::Absent => MemberRef::Absent,
        MemberRef::Unsupported(m) => MemberRef::Unsupported(m),
    };
    match args.encoding {
        ContainedEncoding::Ber | ContainedEncoding::Cer | ContainedEncoding::Der => {
            let mut out = Vec::new();
            crate::ber::object::encode_member_ref(inner, crate::spec::choice::BerTagging::Delegate, &mut out)
                .map_err(|e| e.to_string())?;
            Ok(out)
        }
        ContainedEncoding::PerUnaligned => {
            let mut w = crate::per::writer::Writer::new();
            crate::per::object::encode_member_ref(inner, &crate::constraints::UNCONSTRAINED, &mut w)
                .map_err(|e| e.to_string())?;
            w.flush();
            Ok(w.into_bytes())
        }
        ContainedEncoding::PerAligned => Err("aligned PER contents are not supported".into()),
        ContainedEncoding::Outer => Err("unresolved contents encoding".into()),
    }
}

/// `zero_padding`: one value, then only 0x00 octets (block-cipher padding).
/// The value is decoded from the whole buffer first and the tail checked
/// afterwards: stripping trailing zeros first would cut a value that
/// legitimately ends in 0x00. A non-zero tail keeps the value and reports it.
fn decode_zero_padding(args: &mut ContainedDecodeArgs) -> ContainedResult {
    let mut used = 0;
    let r = decode_value(args, Some(&mut used));
    if r.status != ContainedStatus::Decoded {
        return r;
    }
    if let Some(i) = args.raw[used..].iter().position(|&b| b != 0) {
        return ContainedResult {
            status: ContainedStatus::Decoded,
            message: format!("non-zero padding octet at offset {} of {}", used + i, args.raw.len()),
        };
    }
    r
}

/// `pkcs7`: strip RFC 5652 §6.3 padding (the last octet N, 1..255, repeated
/// N times), then decode the rest as exactly one value.
fn decode_pkcs7(args: &mut ContainedDecodeArgs) -> ContainedResult {
    let raw = args.raw;
    let Some(&n) = raw.last() else {
        return ContainedResult::failed("PKCS#7: empty contents");
    };
    let n = n as usize;
    if n == 0 || n > raw.len() {
        return ContainedResult::failed("PKCS#7: bad padding length");
    }
    if raw[raw.len() - n..].iter().any(|&b| b as usize != n) {
        return ContainedResult::failed("PKCS#7: inconsistent padding octets");
    }
    decode_value_from(args, &raw[..raw.len() - n], None)
}

fn encode_pkcs7(args: &ContainedEncodeArgs) -> Result<Vec<u8>, String> {
    let mut out = encode_value(args)?;
    let bs = args.decoders.pkcs7_block_size;
    if bs == 0 || bs > 255 {
        return Err("PKCS#7: block size must be 1..255".into());
    }
    let n = bs - out.len() % bs;
    out.extend(std::iter::repeat_n(n as u8, n));
    Ok(out)
}

/// Type-erased view of a [`Containing<T>`] for the codec walkers.
pub trait Contained {
    /// The raw bytes.
    fn raw_octets(&self) -> &OctetString;
    /// The bytes the field encodes as: the raw bytes, or after the inner
    /// value was modified, the inner value's encoding.
    fn wire_octets(&self, spec: &'static ContainedSpec, outer: ContainedEncoding) -> Cow<'_, OctetString>;
    /// Raw bytes from the wire, before any inner decode.
    fn set_raw_from_wire(&mut self, raw: Vec<u8>);
    fn status(&self) -> ContainedStatus;
    /// The inner value, if decoded.
    fn inner_ref(&self) -> Option<MemberRef<'_>>;
    /// Decode the inner value into a fresh, detached value (so the
    /// enclosing value can stay borrowed for the decoder).
    fn decode_detached(&self, mk: &mut dyn for<'r, 'v> FnMut(&'r [u8], MemberRefMut<'v>) -> ContainedResult) -> (ContainedResult, Option<Box<dyn Any>>);
    /// Store a [`Contained::decode_detached`] outcome.
    fn install(&mut self, result: ContainedResult, value: Option<Box<dyn Any>>);
    /// The inner value's own XER element name (its type's name).
    fn inner_xer_name(&self) -> &'static str;
    /// Decode the inline XER/JER form: `f` fills a fresh inner value, which
    /// is kept.
    fn inline_decode(&mut self, f: &mut dyn FnMut(MemberRefMut) -> Result<(), crate::ber::reader::DecodeError>) -> Result<(), crate::ber::reader::DecodeError>;
    /// Finish an inline decode: the raw bytes are `raw` (the `inline_raw`
    /// form) or the inner value's encoding; status Decoded.
    fn finish_inline(&mut self, raw: Option<Vec<u8>>, spec: &'static ContainedSpec) -> Result<(), String>;
}

/// An OCTET STRING whose bytes are the encoding of a `T` value. Keeps the
/// raw bytes (`Deref` to [`OctetString`]) plus the inner value decoded
/// during the outer decode. The inner value is boxed, so `T` may be the
/// enclosing type itself.
#[derive(Debug, Default)]
pub struct Containing<T> {
    raw: OctetString,
    inner: Option<Box<T>>,
    status: ContainedStatus,
    error: String,
    dirty: bool,
}

impl<T: Clone> Clone for Containing<T> {
    fn clone(&self) -> Self {
        Containing {
            raw: self.raw.clone(),
            inner: self.inner.clone(),
            status: self.status,
            error: self.error.clone(),
            dirty: self.dirty,
        }
    }
}

/// Equality of the raw bytes; the inner value is derived from them.
impl<T> PartialEq for Containing<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<T> std::ops::Deref for Containing<T> {
    type Target = OctetString;
    fn deref(&self) -> &OctetString {
        &self.raw
    }
}

/// An OCTET STRING on the wire (X.682 §11: the contents constraint does not
/// change the type's tag).
impl<T> crate::type_tag::TypeTag for Containing<T> {
    const TAG: Option<crate::ber::tag::Tag> = Some(crate::octet_string::OCTET_STRING_TAG);
}

impl<T> Containing<T> {
    /// The raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.raw.0
    }
    /// Replace the raw bytes. Drops the inner value: it no longer matches them.
    pub fn set_raw(&mut self, raw: Vec<u8>) {
        self.raw = OctetString(raw);
        self.inner = None;
        self.status = ContainedStatus::NotDecoded;
        self.error.clear();
        self.dirty = false;
    }
    pub fn status(&self) -> ContainedStatus {
        self.status
    }
    /// Reason of a Failed or Skipped status; for Decoded, a warning.
    pub fn error(&self) -> &str {
        &self.error
    }
    pub fn has_value(&self) -> bool {
        self.inner.is_some()
    }
    /// True after the inner value was modified; encode then derives the
    /// bytes from it.
    pub fn dirty(&self) -> bool {
        self.dirty
    }
    /// The decoded inner value.
    pub fn value(&self) -> Option<&T> {
        self.inner.as_deref()
    }
    /// Mutable inner value. Marks the value dirty.
    pub fn value_mut(&mut self) -> Option<&mut T> {
        if self.inner.is_some() {
            self.dirty = true;
            self.status = ContainedStatus::Decoded;
            self.error.clear();
        }
        self.inner.as_deref_mut()
    }
    /// Replace the inner value. Encode derives the bytes from it.
    pub fn set_value(&mut self, v: T) {
        self.inner = Some(Box::new(v));
        self.dirty = true;
        self.status = ContainedStatus::Decoded;
        self.error.clear();
    }
}

impl<T: AsMemberRef + Default + 'static> Contained for Containing<T> {
    fn raw_octets(&self) -> &OctetString {
        &self.raw
    }
    fn wire_octets(&self, spec: &'static ContainedSpec, outer: ContainedEncoding) -> Cow<'_, OctetString> {
        let (Some(inner), true) = (self.inner.as_deref(), self.dirty) else {
            return Cow::Borrowed(&self.raw);
        };
        let reg = ContainedDecoders::defaults();
        let encoding = resolve(spec.encoding, outer);
        let args = ContainedEncodeArgs { inner: inner.as_member_ref(), spec, encoding, decoders: reg };
        let res = match reg.find(spec.decoder).and_then(|e| e.encode.as_ref()) {
            Some(enc) => enc(&args),
            None => Err(format!("decoder '{}' cannot encode", spec.decoder)),
        };
        match res {
            Ok(b) => Cow::Owned(OctetString(b)),
            Err(e) => {
                if crate::debug::debug_flags() & crate::debug::DBG_BER_WRITE != 0 {
                    eprintln!("[CONTAINED] {e}; writing the raw bytes");
                }
                Cow::Borrowed(&self.raw)
            }
        }
    }
    fn set_raw_from_wire(&mut self, raw: Vec<u8>) {
        self.set_raw(raw);
    }
    fn status(&self) -> ContainedStatus {
        self.status
    }
    fn inner_ref(&self) -> Option<MemberRef<'_>> {
        self.inner.as_deref().map(|v| v.as_member_ref())
    }
    fn decode_detached(&self, mk: &mut dyn for<'r, 'v> FnMut(&'r [u8], MemberRefMut<'v>) -> ContainedResult) -> (ContainedResult, Option<Box<dyn Any>>) {
        let mut v = T::default();
        let r = mk(&self.raw.0, v.as_member_ref_mut());
        let keep = r.status == ContainedStatus::Decoded;
        (r, keep.then(|| Box::new(v) as Box<dyn Any>))
    }
    fn install(&mut self, result: ContainedResult, value: Option<Box<dyn Any>>) {
        self.inner = value.and_then(|b| b.downcast::<T>().ok());
        self.status = result.status;
        self.error = result.message;
        self.dirty = false;
    }
    fn inner_xer_name(&self) -> &'static str {
        crate::spec::object::natural_xer_name_of(T::default().as_member_ref())
    }
    fn inline_decode(&mut self, f: &mut dyn FnMut(MemberRefMut) -> Result<(), crate::ber::reader::DecodeError>) -> Result<(), crate::ber::reader::DecodeError> {
        let mut v = T::default();
        f(v.as_member_ref_mut())?;
        self.inner = Some(Box::new(v));
        Ok(())
    }
    fn finish_inline(&mut self, raw: Option<Vec<u8>>, spec: &'static ContainedSpec) -> Result<(), String> {
        let raw = match raw {
            Some(r) => r,
            None => {
                let inner = self.inner.as_deref().ok_or("no inline value")?;
                let encoding = resolve(spec.encoding, ContainedEncoding::Ber);
                encode_value(&ContainedEncodeArgs {
                    inner: inner.as_member_ref(),
                    spec,
                    encoding,
                    decoders: ContainedDecoders::defaults(),
                })?
            }
        };
        self.raw = OctetString(raw);
        self.status = ContainedStatus::Decoded;
        self.error.clear();
        self.dirty = false;
        Ok(())
    }
}

fn resolve(field: ContainedEncoding, outer: ContainedEncoding) -> ContainedEncoding {
    if field == ContainedEncoding::Outer {
        outer
    } else {
        field
    }
}

/// Read a `when` sibling's numeric value (ENUMERATED number, INTEGER, BOOLEAN 0/1).
fn sibling_value(m: MemberRef) -> Option<i64> {
    match m {
        MemberRef::Enumerated(slot, _) => Some(slot.enum_get()),
        MemberRef::Primitive(PrimitiveRef::Integer(v)) => Some(v.0),
        MemberRef::Primitive(PrimitiveRef::UInteger(v)) => Some(v.0 as i64),
        MemberRef::Primitive(PrimitiveRef::Boolean(v)) => Some(v.0 as i64),
        _ => None,
    }
}

/// Decode one contained field; returns the outcome and the decoded value.
#[allow(clippy::too_many_arguments)]
fn run_one(
    field: &dyn Contained,
    spec: &'static ContainedSpec,
    outer: Outer,
    outer_encoding: ContainedEncoding,
    depth: Depth,
    opts: Option<&ContainedOptions>,
    when_fail: Option<String>,
) -> (ContainedResult, Option<Box<dyn Any>>) {
    if !spec.eager || opts.is_some_and(|o| o.off) {
        return (ContainedResult::skipped("contained decoding off"), None);
    }
    if let Some(why) = when_fail {
        return (ContainedResult::skipped(why), None);
    }
    let reg = registry(opts);
    let Some(entry) = reg.find(spec.decoder) else {
        return (ContainedResult::failed(format!("unknown contained decoder '{}'", spec.decoder)), None);
    };
    let encoding = resolve(spec.encoding, outer_encoding);
    field.decode_detached(&mut |raw, inner| {
        let mut args = ContainedDecodeArgs { raw, spec, inner, outer, encoding, decoders: reg, depth, options: opts };
        (entry.decode)(&mut args)
    })
}

fn finish(name: &str, spec: &ContainedSpec, r: &ContainedResult) -> Result<(), String> {
    if r.status != ContainedStatus::Decoded && crate::debug::debug_flags() & crate::debug::DBG_BER_SEQ != 0 {
        eprintln!("[CONTAINED] {name}: {}", r.message);
    }
    if r.status == ContainedStatus::Failed && spec.fail_on_error {
        return Err(format!("{name}: {}", r.message));
    }
    Ok(())
}

/// @brief Decode the contained members of a decoded SEQUENCE/SET value
///        (all members are present, so `when` siblings can be read).
/// @return `Err` only for a failure on a field with `on_error: fail`.
/// @see X.682 §11.4
pub(crate) fn decode_contained_members(
    obj: &mut dyn Asn1Seq,
    outer_encoding: ContainedEncoding,
    depth: Depth,
    opts: Option<&ContainedOptions>,
) -> Result<(), String> {
    let spec = obj.spec();
    for &i in spec.contained_members {
        let meta = &spec.members[i];
        let Some(cspec) = meta.contained else { continue };
        let when_fail = (cspec.when_member >= 0).then(|| {
            let sib = cspec.when_member as usize;
            match sibling_value(obj.get_member(sib)) {
                Some(v) if v == cspec.when_value => None,
                _ => Some(format!("'{}' does not select decoding", spec.members[sib].name)),
            }
        }).flatten();
        let (r, v) = {
            let MemberRef::Contained(field, _) = obj.get_member(i) else { continue };
            if field.status() == ContainedStatus::Decoded {
                continue; // decoded from its inline XER/JER form already
            }
            run_one(field, cspec, Outer::Seq(&*obj), outer_encoding, depth, opts, when_fail)
        };
        finish(meta.name, cspec, &r)?;
        if let MemberRefMut::Contained(field, _) = obj.get_member_mut(i) {
            field.install(r, v);
        }
    }
    Ok(())
}

/// @brief Decode the active alternative of a decoded CHOICE value when it
///        is a contained field.
/// @return `Err` only for a failure on a field with `on_error: fail`.
pub(crate) fn decode_contained_alternative(
    obj: &mut dyn Asn1Choice,
    outer_encoding: ContainedEncoding,
    depth: Depth,
    opts: Option<&ContainedOptions>,
) -> Result<(), String> {
    let Some(idx) = obj.active_index() else { return Ok(()) };
    let meta = &obj.spec().alternatives[idx];
    let Some(cspec) = meta.contained else { return Ok(()) };
    let (r, v) = {
        let MemberRef::Contained(field, _) = obj.get_active() else { return Ok(()) };
        if field.status() == ContainedStatus::Decoded {
            return Ok(());
        }
        run_one(field, cspec, Outer::Choice(&*obj), outer_encoding, depth, opts, None)
    };
    finish(meta.name, cspec, &r)?;
    if let MemberRefMut::Contained(field, _) = obj.select_mut(idx) {
        field.install(r, v);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::Integer;

    static SPEC: ContainedSpec = ContainedSpec {
        encoding: ContainedEncoding::Ber,
        eager: true,
        decoder: "plain",
        when_member: -1,
        when_value: 0,
        fail_on_error: false,
        xer: ContainedText::Hex,
        jer: ContainedText::Hex,
    };

    struct NoSeq;
    static NO_SEQ_SPEC: crate::spec::object::SequenceSpec = crate::spec::object::SequenceSpec {
        name: "NoSeq",
        tag: crate::spec::sequence::SEQUENCE_TAG,
        members: &[],
        ext_at: -1,
        roms_count: 0,
        is_set: false,
        ext_units: &[],
        group_member_optional: &[],
        contained_members: &[],
    };
    impl Asn1Seq for NoSeq {
        fn spec(&self) -> &'static crate::spec::object::SequenceSpec {
            &NO_SEQ_SPEC
        }
        fn get_member(&self, _: usize) -> MemberRef<'_> {
            MemberRef::Absent
        }
        fn get_member_mut(&mut self, _: usize) -> MemberRefMut<'_> {
            MemberRefMut::Absent
        }
        fn set_default(&mut self, _: usize) {}
        fn is_default_equal(&self, _: usize) -> bool {
            false
        }
        fn validate(&self, _: usize) -> i64 {
            0
        }
    }

    fn run(decoder: &str, raw: &[u8], reg: &ContainedDecoders) -> (ContainedResult, i64) {
        let mut v = Integer(0);
        let r = {
            let mut args = ContainedDecodeArgs {
                raw,
                spec: &SPEC,
                inner: MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut v)),
                outer: Outer::Seq(&NoSeq),
                encoding: ContainedEncoding::Ber,
                decoders: reg,
                depth: Depth::default(),
                options: None,
            };
            (reg.find(decoder).unwrap().decode)(&mut args)
        };
        (r, v.0)
    }

    #[test]
    fn built_in_decoders() {
        let reg = ContainedDecoders::defaults();
        assert_eq!(run("plain", &[0x02, 0x02, 0x12, 0x34], reg), (ContainedResult::ok(), 0x1234));
        assert_eq!(run("plain", &[0x02, 0x02, 0x12, 0x34, 0x00], reg).0.status, ContainedStatus::Failed);
        assert_eq!(run("zero_padding", &[0x02, 0x02, 0x12, 0x34, 0, 0, 0], reg), (ContainedResult::ok(), 0x1234));
        // A value ending in 0x00 must not be cut: 02 02 12 00 is 0x1200.
        assert_eq!(run("zero_padding", &[0x02, 0x02, 0x12, 0x00, 0, 0], reg), (ContainedResult::ok(), 0x1200));
        let (r, v) = run("zero_padding", &[0x02, 0x02, 0x12, 0x34, 0x00, 0x07], reg);
        assert!(r.status == ContainedStatus::Decoded && !r.message.is_empty() && v == 0x1234);
        assert_eq!(run("pkcs7", &[0x02, 0x02, 0x12, 0x34, 4, 4, 4, 4], reg).1, 0x1234);
        assert_eq!(run("pkcs7", &[0x02, 0x02, 0x12, 0x34, 4, 3, 4, 4], reg).0.status, ContainedStatus::Failed);
        assert_eq!(run("pkcs7", &[0x02, 0x02, 0x12, 0x34, 0], reg).0.status, ContainedStatus::Failed);
        assert_eq!(run("pkcs7", &[], reg).0.status, ContainedStatus::Failed);
        assert_eq!(run("none", &[0x02, 0x01, 0x05], reg).0.status, ContainedStatus::Skipped);
    }

    #[test]
    fn pkcs7_encode_pads_to_the_block_size() {
        let i = Integer(0x1234);
        let mut reg = ContainedDecoders::default();
        let enc = |reg: &ContainedDecoders| {
            let args = ContainedEncodeArgs {
                inner: MemberRef::Primitive(PrimitiveRef::Integer(&i)),
                spec: &SPEC,
                encoding: ContainedEncoding::Ber,
                decoders: reg,
            };
            (reg.find("pkcs7").unwrap().encode.as_ref().unwrap())(&args).unwrap()
        };
        let out = enc(&reg);
        assert_eq!((out.len(), *out.last().unwrap()), (16, 12));
        reg.pkcs7_block_size = 4;
        let out = enc(&reg);
        assert_eq!((out.len(), *out.last().unwrap()), (8, 4));
    }

    #[test]
    fn application_decoder_overrides_a_built_in() {
        let mut reg = ContainedDecoders::default();
        reg.add(
            "plain",
            Box::new(|a| {
                let plain: Vec<u8> = a.raw.iter().map(|b| b ^ 0x5A).collect();
                decode_value_from(a, &plain, None)
            }),
            None,
        );
        assert_eq!(run("plain", &[0x02 ^ 0x5A, 0x01 ^ 0x5A, 0x07 ^ 0x5A], &reg), (ContainedResult::ok(), 7));
    }

    #[test]
    fn containing_value_semantics() {
        let mut c: Containing<Integer> = Containing::default();
        assert!(c.status() == ContainedStatus::NotDecoded && !c.has_value());
        c.set_value(Integer(42));
        assert!(c.dirty() && c.value() == Some(&Integer(42)));
        assert_eq!(c.wire_octets(&SPEC, ContainedEncoding::Ber).0, vec![0x02, 0x01, 42]);
        let copy = c.clone();
        assert_eq!(copy.value(), Some(&Integer(42)));
        c.set_raw(vec![0x02, 0x01, 0x09]);
        assert!(!c.has_value() && !c.dirty() && c.status() == ContainedStatus::NotDecoded);
        assert_eq!(c.wire_octets(&SPEC, ContainedEncoding::Ber).0, vec![0x02, 0x01, 0x09]);
    }
}
