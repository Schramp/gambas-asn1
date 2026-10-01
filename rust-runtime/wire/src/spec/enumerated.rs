//! ENUMERATED spec — X.680 §20. Read by BER/XER/PER (`enumerated.rs`,
//! `per::enumerated`).

/// One value/name pair — mirrors `EnumSpec::entries` (`TypeDescriptor.hpp`)
/// exactly: codegen emits one static table per ENUMERATED type
/// (`{TYPE}_MAP`), this module supplies the one generic name<->value
/// lookup both `Asn1Value::xer_encode`/`xer_decode_into` wrappers call —
/// same table-driven split every other construct in this crate uses (the
/// table is data, the lookup is the one shared piece of logic, not
/// per-type generated code).
pub struct EnumEntry {
    pub value: i64,
    pub name: &'static str,
}

/// One ENUMERATED's complete, codec-agnostic metadata (X.680 §20): BER
/// and PER read `value`, XER reads `name`. Codegen emits `entries` sorted
/// ascending by `value` (X.691 §22 — the PER ordinal is the position in
/// this order) and precomputes the root layout, so no walker recounts it.
#[derive(Clone, Copy)]
pub struct EnumSpec {
    pub entries: &'static [EnumEntry],
    /// True if the ENUMERATED has an extension marker (`...`).
    pub extensible: bool,
    /// Number of root entries (leading in `entries`); equals
    /// `entries.len()` when the type is not extensible.
    pub root_count: usize,
    /// X.691 §10.5.6 unaligned index width for `root_count` root values.
    pub root_bits: u32,
}

/// X.680 §20/§51 ENUMERATED validation (gambas-asn1#468) — mirrors
/// `EnumSpec::validate` (`runtime/include/asn1cpp/TypeDescriptor.hpp`)
/// exactly: not a range check like INTEGER/SIZE — `1` when `value` isn't
/// any known root or extension enumeration value, `0` otherwise. No
/// "nearest valid bound" delta concept applies (an unknown ENUMERATED
/// value has no natural distance metric), matching the C++ side's own
/// doc note. `EXTENSIBLE` gets no bypass here either (unlike INTEGER/
/// SIZE) — an extensible ENUMERATED still requires the decoded value to
/// be one of the *known* root/extension values; X.691 §22's own
/// extension-addition mechanism is how a *new* value becomes known, not
/// a blanket "anything goes" escape hatch.
///
/// In practice this can only ever return `0` through the normal decode
/// path: `read_enumerated_tagged`/`decode_enumerated_content` already
/// reject an unrecognized wire value via `T: TryFrom<i64>` before a Rust
/// enum instance can exist at all (`enumerated.rs`'s own module doc) — a
/// stronger, compile-time-enforced guarantee than C++'s runtime-only
/// check. Implemented anyway, reusing the same `{TYPE}_MAP` table BER/XER
/// already emit, for parity with the other constraint kinds and as a
/// defined behavior for the (currently unreachable) case a `T::default()`
/// or other non-decode construction path ever produces an out-of-table
/// discriminant.
pub fn validate_enum(v: i64, spec: &EnumSpec) -> i64 {
    if spec.entries.iter().any(|e| e.value == v) {
        0
    } else {
        1
    }
}
