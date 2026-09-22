//! X.680 §51 SubtypeConstraint data — the one shared
//! `Constraints` value both `asn1cpp_ber` and `asn1cpp_per` read, computed
//! once at codegen time (`Generator`'s backend-agnostic `IntegerSpec`/
//! `MemberTypeDescriptorSpec`) and emitted as a single static per
//! constrained member/element instead of two differently-shaped ones.
//!
//! Plain data only, no codec logic, no stream primitives — this crate is
//! not a third wire-encoding crate, just the metadata both existing ones
//! already computed from the same source and were duplicating. Mirrors
//! `asn1::Constraints` (`runtime/include/asn1cpp/codec/Constraints.hpp`)
//! — same field names, same flag bits.

pub const CONSTRAINED: u32 = 1;
pub const SEMI_CONSTRAINED: u32 = 2;
pub const EXTENSIBLE: u32 = 4;
pub const SIZE_CONSTRAINED: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Constraints {
    pub flags: u32,
    /// ceil(log2(upper_bound - lower_bound + 1)); 0 if unconstrained.
    /// PER-only (bit width for the wire shape); BER's TLV length is
    /// self-describing and never reads this.
    pub range_bits: u32,
    pub lower_bound: i64,
    pub upper_bound: i64,
    pub lower_u64: u64,
    pub upper_u64: u64,
    /// SIZE constraint (OCTET STRING, BIT STRING, character strings,
    /// SEQUENCE OF/SET OF element count). `size_range_bits == 0` with
    /// `SIZE_CONSTRAINED` set means a fixed SIZE(n) — PER emits no length
    /// field at all in that case.
    pub size_range_bits: u32,
    pub size_lower: i64,
    pub size_upper: i64,
    /// X.680 §51.4 PermittedAlphabet — `encode_table[b]` for byte `b`
    /// gives its position in the permitted alphabet, or `0xFFFF` if `b`
    /// isn't permitted at all. BER-only today (`validate_alphabet`); PER
    /// doesn't implement FROM-alphabet encoding yet.
    /// `None` means "no FROM constraint", checked before indexing at all.
    pub encode_table: Option<&'static [u16; 256]>,
}

/// The shared "no constraint at all" value — every field zero/`None`,
/// `flags == 0`. A single instance covers every unconstrained case codegen
/// needs a `&Constraints` reference for, so generated code references this
/// one runtime-owned constant instead of emitting an always-present
/// fallback static per use site (mirrors the C++ side's own equivalent:
/// falling back to a builtin type's already-existing generic descriptor,
/// e.g. `asn1::asn_DEF_Integer`, rather than emitting a new one).
pub const UNCONSTRAINED: Constraints = Constraints {
    flags: 0,
    range_bits: 0,
    lower_bound: 0,
    upper_bound: 0,
    lower_u64: 0,
    upper_u64: 0,
    size_range_bits: 0,
    size_lower: 0,
    size_upper: 0,
    encode_table: None,
};

impl Constraints {
    pub const CONSTRAINED: u32 = CONSTRAINED;
    pub const SEMI_CONSTRAINED: u32 = SEMI_CONSTRAINED;
    pub const EXTENSIBLE: u32 = EXTENSIBLE;
    pub const SIZE_CONSTRAINED: u32 = SIZE_CONSTRAINED;

    pub fn is_constrained(&self) -> bool {
        self.flags & CONSTRAINED != 0
    }
    pub fn is_semi_constrained(&self) -> bool {
        self.flags & SEMI_CONSTRAINED != 0
    }
    pub fn is_extensible(&self) -> bool {
        self.flags & EXTENSIBLE != 0
    }
    pub fn is_size_constrained(&self) -> bool {
        self.flags & SIZE_CONSTRAINED != 0
    }
}
