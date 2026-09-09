//! PER constraint metadata for one type or member (X.691 §10.5/§10.6/§10.9).
//!
//! Mirrors `asn1::Constraints` (`runtime/include/asn1cpp/codec/Constraints.hpp`)
//! — same flag bits, same field names — but only the subset needed so far
//! (signed/unsigned INTEGER encoding). Grows field-by-field as later
//! encode/decode kinds are ported (size constraints for strings/SEQUENCE OF,
//! wide-integer bounds), same incremental pattern the C++ struct itself
//! grew under.

pub const CONSTRAINED: u32 = 1;
pub const SEMI_CONSTRAINED: u32 = 2;
pub const EXTENSIBLE: u32 = 4;

/// flags == 0 means unconstrained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Constraints {
    pub flags: u32,
    /// ceil(log2(upper_bound - lower_bound + 1)); 0 if unconstrained.
    pub range_bits: u32,
    /// Signed 64-bit bounds — read by signed INTEGER encode/decode.
    pub lower_bound: i64,
    pub upper_bound: i64,
    /// Unsigned 64-bit bounds — read by unsigned INTEGER encode/decode.
    pub lower_u64: u64,
    pub upper_u64: u64,
}

impl Constraints {
    pub fn is_constrained(&self) -> bool {
        self.flags & CONSTRAINED != 0
    }
    pub fn is_semi_constrained(&self) -> bool {
        self.flags & SEMI_CONSTRAINED != 0
    }
    pub fn is_extensible(&self) -> bool {
        self.flags & EXTENSIBLE != 0
    }
}
