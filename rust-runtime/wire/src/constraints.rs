//! Generic X.680 §51 SubtypeConstraint validators — the Rust analogue of
//! `Integer::validate`/`UInteger::validate`/`OctetString::validate`/
//! `BitString::validate`/`AsnString<N>::validate` (`runtime/include/
//! asn1cpp/types/*.hpp`). The `Constraints` struct itself (below) is read
//! by both this module's callers and `per`'s — the exact same superset the
//! compiler already computes once (`Generator`'s backend-agnostic
//! `IntegerSpec`/`MemberTypeDescriptorSpec`) for both codecs.
//!
//! Constraints must be table data, never bespoke per-member code — a
//! parser/introspection tool has no way to extract a validation rule
//! that only exists as executable logic. So codegen emits a
//! `static Constraints` value (plain data, the same shape a C++/PER/XSD
//! tool could introspect without executing anything) per constrained
//! member/type, never a bespoke per-member function. The `validate_*`
//! functions here are the *only* code — generic, identical for every
//! member of a given value shape, exactly mirroring C++'s own "one
//! `validate(const Constraints&)` method per type, data varies per
//! member" shape (`TypeDescriptor.hpp`'s `MemberDescriptor`/`SeqOfSpec`
//! embed a `Constraints` value the same way).


pub const CONSTRAINED: u32 = 1;
pub const SEMI_CONSTRAINED: u32 = 2;
pub const EXTENSIBLE: u32 = 4;
pub const SIZE_CONSTRAINED: u32 = 8;
/// BIT STRING defined with a NamedBitList (X.680 §22.7): trailing 0 bits
/// carry no meaning and PER drops them (X.691 §15.2, §15.3).
pub const NAMED_BITS: u32 = 16;
/// REAL value range `real_lower..real_upper` (X.680 §47.4).
pub const REAL_RANGE: u32 = 32;
/// `real_lower` itself is excluded (`lo<..`).
pub const REAL_LOWER_OPEN: u32 = 64;
/// `real_upper` itself is excluded (`..<hi`).
pub const REAL_UPPER_OPEN: u32 = 128;
/// The JER-visible base constraint admits only base 10 (X.697 §23.1.4).
pub const REAL_BASE_10: u32 = 256;
/// `SIZE(lb..MAX)`: `size_lower` is a lower bound, no upper bound (X.680
/// §51.5). Read by `validate_size`/`validate_bit_string` only; PER encodes
/// such a length as unconstrained (X.691 §11.9.4.2), so `SIZE_CONSTRAINED`
/// stays clear. Mirrors `Constraints::SIZE_LOWER_BOUND` (`Constraints.hpp`).
pub const SIZE_LOWER_BOUND: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Constraints {
    pub flags: u32,
    pub range_bits: u32,
    pub lower_bound: i64,
    pub upper_bound: i64,
    pub lower_u64: u64,
    pub upper_u64: u64,
    pub size_range_bits: u32,
    pub size_lower: i64,
    pub size_upper: i64,
    pub encode_table: Option<&'static [u16; 256]>,
    /// X.691 §26.5.4 FROM (PermittedAlphabet) — bit width per character
    /// (`ceil(log2(alphabet_size))`); `0` means no FROM constraint (use
    /// the type's natural alphabet width instead). Mirrors
    /// `Constraints::alphabet_bits` (`Constraints.hpp`) exactly.
    pub alphabet_bits: u32,
    /// Decode-direction table: `alphabet[ordinal] -> character byte`,
    /// `alphabet_size` entries, sorted ascending (matches `encode_table`'s
    /// own encode-direction mapping, `byte -> ordinal`). `None` when
    /// `alphabet_bits == 0`.
    pub alphabet: Option<&'static [u8]>,
    pub alphabet_size: u8,
    /// For a SEQUENCE OF / SET OF: the element type's own constraints
    /// (X.691 §19/§20 — the collection's SIZE is this table's own
    /// `size_*` fields, each element is then encoded against `element`).
    /// Mirrors `SeqOfSpec`'s element descriptor on the C++ side. `None`
    /// for every non-collection type and for an unconstrained element.
    pub element: Option<&'static Constraints>,
    /// REAL value range, read by `validate_real` when `REAL_RANGE` is set.
    /// MIN / MAX / MINUS-INFINITY / PLUS-INFINITY endpoints are ±infinity.
    /// Mirrors `Constraints::real_lower`/`real_upper` (`Constraints.hpp`).
    pub real_lower: f64,
    pub real_upper: f64,
}

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
    encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,
    real_lower: 0.0, real_upper: 0.0,
};

impl Constraints {
    pub const CONSTRAINED: u32 = CONSTRAINED;
    pub const SEMI_CONSTRAINED: u32 = SEMI_CONSTRAINED;
    pub const EXTENSIBLE: u32 = EXTENSIBLE;
    pub const SIZE_CONSTRAINED: u32 = SIZE_CONSTRAINED;
    pub const NAMED_BITS: u32 = NAMED_BITS;
    pub const REAL_RANGE: u32 = REAL_RANGE;
    pub const REAL_LOWER_OPEN: u32 = REAL_LOWER_OPEN;
    pub const REAL_UPPER_OPEN: u32 = REAL_UPPER_OPEN;
    pub const REAL_BASE_10: u32 = REAL_BASE_10;
    pub const SIZE_LOWER_BOUND: u32 = SIZE_LOWER_BOUND;

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

/// X.680 §19 INTEGER value-range check, `i64` storage. Mirrors
/// `Integer::validate` (`runtime/include/asn1cpp/types/Integer.hpp`)
/// exactly: `0` valid; positive = below `lower_bound`; negative = above
/// `upper_bound`; `EXTENSIBLE` always `0`; `SEMI_CONSTRAINED` skips the
/// upper check.
pub fn validate_s64(v: i64, c: &Constraints) -> i64 {
    if c.flags & Constraints::EXTENSIBLE != 0 {
        return 0;
    }
    if c.flags & Constraints::CONSTRAINED != 0 {
        if v < c.lower_bound {
            return c.lower_bound - v;
        }
        if v > c.upper_bound {
            return c.upper_bound - v;
        }
        return 0;
    }
    if c.flags & Constraints::SEMI_CONSTRAINED != 0 && v < c.lower_bound {
        return c.lower_bound - v;
    }
    0
}

/// `u64`-storage counterpart of `validate_s64` — mirrors `UInteger::validate`'s
/// own saturating clamp to the `i64` delta range exactly (a `u64` bound can
/// be up to `u64::MAX`, not representable as an `i64` delta without
/// clamping).
pub fn validate_u64(v: u64, c: &Constraints) -> i64 {
    if c.flags & Constraints::EXTENSIBLE != 0 {
        return 0;
    }
    let clamp = |d: u64, sign: i64| -> i64 {
        if d > i64::MAX as u64 {
            if sign > 0 { i64::MAX } else { i64::MIN }
        } else {
            (d as i64) * sign
        }
    };
    if c.flags & Constraints::CONSTRAINED != 0 {
        if v < c.lower_u64 {
            return clamp(c.lower_u64 - v, 1);
        }
        if v > c.upper_u64 {
            return clamp(v - c.upper_u64, -1);
        }
        return 0;
    }
    if c.flags & Constraints::SEMI_CONSTRAINED != 0 && v < c.lower_u64 {
        return clamp(c.lower_u64 - v, 1);
    }
    0
}

/// X.680 §47.4 REAL value-range check. Mirrors `Real::validate`
/// (`runtime/include/asn1cpp/types/Real.hpp`) exactly: `0` inside the range,
/// with no `REAL_RANGE` bit, or `EXTENSIBLE`; otherwise the distance to the
/// nearest bound rounded away from zero to at least 1 and saturated at
/// `i64::MAX`, positive below the lower bound, negative above the upper
/// bound. NOT-A-NUMBER lies in no range and gives `1`.
pub fn validate_real(v: f64, c: &Constraints) -> i64 {
    if c.flags & REAL_RANGE == 0 || c.flags & EXTENSIBLE != 0 {
        return 0;
    }
    if v.is_nan() {
        return 1;
    }
    let distance = |d: f64| -> i64 {
        if !(d < 9.2e18) {
            return i64::MAX;
        }
        (d.ceil() as i64).max(1)
    };
    let lower_open = c.flags & REAL_LOWER_OPEN != 0;
    let upper_open = c.flags & REAL_UPPER_OPEN != 0;
    if v < c.real_lower || (lower_open && v == c.real_lower) {
        return distance(c.real_lower - v);
    }
    if v > c.real_upper || (upper_open && v == c.real_upper) {
        return -distance(v - c.real_upper);
    }
    0
}

/// X.680 §25/§26/§51 SIZE check, generic over what "size" means for the
/// caller's own kind (byte count for OCTET STRING, bit count for BIT
/// STRING, character count for a restricted character string, element
/// count for SEQUENCE OF/SET OF — same `n`, different unit, computed by
/// the caller before calling this). Mirrors `OctetString::validate`/
/// `BitString::validate`/`AsnString<N>::validate`'s SIZE half/
/// `SeqOfSpec::validate` exactly: `0` valid; positive = too short;
/// negative = too long; `EXTENSIBLE` always `0`; no `SIZE_CONSTRAINED` bit
/// set at all (unconstrained or FROM-alphabet-only) also always `0`.
/// `SIZE_LOWER_BOUND` (`SIZE(lb..MAX)`) checks the lower bound only.
pub fn validate_size(n: usize, c: &Constraints) -> i64 {
    if c.flags & SIZE_LOWER_BOUND != 0 && c.flags & EXTENSIBLE == 0 {
        let n = n as i64;
        return if n < c.size_lower { c.size_lower - n } else { 0 };
    }
    if c.flags & Constraints::SIZE_CONSTRAINED == 0 || c.flags & Constraints::EXTENSIBLE != 0 {
        return 0;
    }
    let n = n as i64;
    if n < c.size_lower {
        return c.size_lower - n;
    }
    if n > c.size_upper {
        return c.size_upper - n;
    }
    0
}

/// SIZE check of a BIT STRING value. A NamedBitList value satisfies the
/// constraint when adding or removing trailing 0 bits makes it fit (X.680
/// §22.7, X.691 §15.3), so only its significant bits are checked against the
/// upper bound; otherwise `validate_size` on the bit count. Mirrors
/// `BitString::validate` (`runtime/include/asn1cpp/types/BitString.hpp`).
pub fn validate_bit_string(v: &crate::bit_string::BitString, c: &Constraints) -> i64 {
    if c.flags & NAMED_BITS == 0 {
        return validate_size(v.bit_count(), c);
    }
    if c.flags & SIZE_CONSTRAINED == 0 || c.flags & EXTENSIBLE != 0 {
        return 0;
    }
    let sig = v.significant_bit_count() as i64;
    if sig > c.size_upper { c.size_upper - sig } else { 0 }
}

/// X.680 §51.4 PermittedAlphabet check. Mirrors the
/// alphabet half of `AsnString<N>::validate`
/// (`runtime/include/asn1cpp/types/Strings.hpp`) exactly: `0` when every
/// byte of `s` is in the permitted alphabet (or `c.encode_table` is
/// `None` — no FROM constraint at all); `1` — a sentinel, not a delta,
/// same as `validate_enum`'s own "no nearest-bound metric" case — the
/// moment any byte isn't. `EXTENSIBLE` is deliberately not consulted
/// here: X.680 §51.8.3 extensibility on a SIZE or value-range constraint
/// means "a future edition may widen the bound," but `FROM` has its own,
/// separate extension marker (`ast::FromConstraint::inner::extensible`,
/// `Generator::build_member_type_descriptor_spec`) that this crate
/// doesn't enforce differently yet — same scope the alphabet arrays
/// themselves don't distinguish (`Generator` builds one merged
/// permitted-character set either way).
pub fn validate_alphabet(s: &str, c: &Constraints) -> i64 {
    if let Some(table) = c.encode_table {
        for b in s.bytes() {
            if table[b as usize] == 0xFFFF {
                return 1;
            }
        }
    }
    0
}

/// Combined SIZE + FROM-alphabet check for a character-string member —
/// the single `MemberDescriptor::validate` slot a member can only wire to
/// one function, mirroring `AsnString<N>::validate`'s own combined body
/// exactly (SIZE checked first; only reached at all if SIZE passed or
/// wasn't constrained). OCTET STRING/BIT STRING never have alphabets
/// (X.680 §51.4 only applies to character string types), so those keep
/// calling `validate_size` directly — this wrapper is only for the 12
/// character-string builtins.
pub fn validate_string(s: &str, c: &Constraints) -> i64 {
    let delta = validate_size(s.len(), c);
    if delta != 0 {
        return delta;
    }
    validate_alphabet(s, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(flags: u32, lower_bound: i64, upper_bound: i64) -> Constraints {
        Constraints { flags, lower_bound, upper_bound, ..Default::default() }
    }

    #[test]
    fn s64_constrained_in_range_is_zero() {
        assert_eq!(validate_s64(50, &c(Constraints::CONSTRAINED, 0, 100)), 0);
    }

    #[test]
    fn s64_constrained_below_lower_is_positive() {
        assert_eq!(validate_s64(-5, &c(Constraints::CONSTRAINED, 0, 100)), 5);
    }

    #[test]
    fn s64_constrained_above_upper_is_negative() {
        assert_eq!(validate_s64(105, &c(Constraints::CONSTRAINED, 0, 100)), -5);
    }

    #[test]
    fn s64_semi_constrained_ignores_upper() {
        let c = c(Constraints::SEMI_CONSTRAINED, 0, 0);
        assert_eq!(validate_s64(1_000_000, &c), 0);
        assert_eq!(validate_s64(-1, &c), 1);
    }

    #[test]
    fn s64_extensible_is_always_zero() {
        let c = c(Constraints::EXTENSIBLE, 0, 100);
        assert_eq!(validate_s64(-1_000_000, &c), 0);
        assert_eq!(validate_s64(1_000_000, &c), 0);
    }

    #[test]
    fn s64_unconstrained_is_always_zero() {
        assert_eq!(validate_s64(-1_000_000, &Constraints::default()), 0);
    }

    fn cu(flags: u32, lower_u64: u64, upper_u64: u64) -> Constraints {
        Constraints { flags, lower_u64, upper_u64, ..Default::default() }
    }

    #[test]
    fn u64_constrained_in_range_is_zero() {
        assert_eq!(validate_u64(50, &cu(Constraints::CONSTRAINED, 0, 100)), 0);
    }

    #[test]
    fn u64_constrained_below_lower_is_positive() {
        assert_eq!(validate_u64(0, &cu(Constraints::CONSTRAINED, 10, 100)), 10);
    }

    #[test]
    fn u64_constrained_above_upper_is_negative() {
        assert_eq!(validate_u64(105, &cu(Constraints::CONSTRAINED, 0, 100)), -5);
    }

    #[test]
    fn u64_saturates_at_i64_bounds() {
        assert_eq!(validate_u64(0, &cu(Constraints::CONSTRAINED, u64::MAX, u64::MAX)), i64::MAX);
        assert_eq!(validate_u64(u64::MAX, &cu(Constraints::CONSTRAINED, 0, 0)), i64::MIN);
    }

    fn cs(flags: u32, size_lower: i64, size_upper: i64) -> Constraints {
        Constraints { flags, size_lower, size_upper, ..Default::default() }
    }

    #[test]
    fn size_in_range_is_zero() {
        let c = cs(Constraints::SIZE_CONSTRAINED, 1, 10);
        assert_eq!(validate_size(1, &c), 0);
        assert_eq!(validate_size(5, &c), 0);
        assert_eq!(validate_size(10, &c), 0);
    }

    #[test]
    fn size_too_short_is_positive() {
        assert_eq!(validate_size(0, &cs(Constraints::SIZE_CONSTRAINED, 1, 10)), 1);
    }

    #[test]
    fn size_too_long_is_negative() {
        assert_eq!(validate_size(12, &cs(Constraints::SIZE_CONSTRAINED, 1, 10)), -2);
    }

    #[test]
    fn size_extensible_is_always_zero() {
        let c = cs(Constraints::SIZE_CONSTRAINED | Constraints::EXTENSIBLE, 1, 10);
        assert_eq!(validate_size(0, &c), 0);
        assert_eq!(validate_size(1_000_000, &c), 0);
    }

    #[test]
    fn size_no_constraint_bit_is_always_zero() {
        assert_eq!(validate_size(1_000_000, &Constraints::default()), 0);
    }

    // Digits-only alphabet ('0'..'9' -> 0..9, everything else 0xFFFF) —
    // small enough to write by hand, same shape a real FROM("0".."9")
    // NumericString constraint would generate.
    fn digits_table() -> [u16; 256] {
        let mut t = [0xFFFFu16; 256];
        for (i, b) in (b'0'..=b'9').enumerate() {
            t[b as usize] = i as u16;
        }
        t
    }

    fn ca(table: &'static [u16; 256]) -> Constraints {
        Constraints { encode_table: Some(table), ..Default::default() }
    }

    #[test]
    fn alphabet_every_char_permitted_is_zero() {
        static TABLE: [u16; 256] = {
            let mut t = [0xFFFFu16; 256];
            let mut b = b'0';
            let mut i = 0u16;
            while b <= b'9' {
                t[b as usize] = i;
                i += 1;
                b += 1;
            }
            t
        };
        assert_eq!(validate_alphabet("12345", &ca(&TABLE)), 0);
    }

    #[test]
    fn alphabet_disallowed_char_is_one() {
        let table: &'static [u16; 256] = Box::leak(Box::new(digits_table()));
        assert_eq!(validate_alphabet("12a45", &ca(table)), 1);
    }

    #[test]
    fn alphabet_no_encode_table_is_always_zero() {
        assert_eq!(validate_alphabet("anything at all!", &Constraints::default()), 0);
    }

    /// X.680 §22.7: a NamedBitList value fits SIZE(8) whenever its
    /// significant bits do — '01'B and '0100000000'B both satisfy it.
    #[test]
    fn validate_real_closed_open_and_unbounded_ends() {
        let closed = Constraints { flags: REAL_RANGE, real_lower: 0.0, real_upper: 100.0, ..Default::default() };
        assert_eq!(validate_real(0.0, &closed), 0);
        assert_eq!(validate_real(100.0, &closed), 0);
        assert_eq!(validate_real(-0.5, &closed), 1);
        assert_eq!(validate_real(-2.5, &closed), 3);
        assert_eq!(validate_real(101.0, &closed), -1);
        assert_eq!(validate_real(f64::NAN, &closed), 1);
        assert_eq!(validate_real(f64::INFINITY, &closed), -i64::MAX);

        let finite = Constraints {
            flags: REAL_RANGE | REAL_LOWER_OPEN | REAL_UPPER_OPEN,
            real_lower: f64::NEG_INFINITY,
            real_upper: f64::INFINITY,
            ..Default::default()
        };
        assert_eq!(validate_real(1e300, &finite), 0);
        assert_eq!(validate_real(f64::INFINITY, &finite), -i64::MAX);
        assert_eq!(validate_real(f64::NEG_INFINITY, &finite), i64::MAX);

        let ext = Constraints { flags: REAL_RANGE | EXTENSIBLE, real_lower: 0.0, real_upper: 1.0, ..Default::default() };
        assert_eq!(validate_real(5.0, &ext), 0);
        assert_eq!(validate_real(5.0, &UNCONSTRAINED), 0);
    }

    #[test]
    fn validate_bit_string_named_bits_checks_significant_bits_only() {
        use crate::bit_string::BitString;
        let plain = cs(Constraints::SIZE_CONSTRAINED, 8, 8);
        let named = Constraints { flags: Constraints::SIZE_CONSTRAINED | Constraints::NAMED_BITS, ..plain };
        let short = BitString { bytes: vec![0x40], unused_bits: 6 };
        let long = BitString { bytes: vec![0x40, 0x00], unused_bits: 6 };
        let too_long = BitString { bytes: vec![0x00, 0x40], unused_bits: 6 };
        assert_eq!(validate_bit_string(&short, &plain), 6);
        assert_eq!(validate_bit_string(&short, &named), 0);
        assert_eq!(validate_bit_string(&long, &named), 0);
        assert_eq!(validate_bit_string(&too_long, &named), -2);
    }

    #[test]
    fn validate_string_checks_size_before_alphabet() {
        let table: &'static [u16; 256] = Box::leak(Box::new(digits_table()));
        // Too short (SIZE(2..5)) AND contains a disallowed char — SIZE
        // wins, matching AsnString<N>::validate's own check order.
        let c = Constraints { flags: Constraints::SIZE_CONSTRAINED, size_lower: 2, size_upper: 5, encode_table: Some(table), ..Default::default() };
        assert_eq!(validate_string("a", &c), 1); // size_lower(2) - len(1) = 1
    }

    #[test]
    fn validate_string_checks_alphabet_when_size_passes() {
        let table: &'static [u16; 256] = Box::leak(Box::new(digits_table()));
        let c = Constraints { flags: Constraints::SIZE_CONSTRAINED, size_lower: 2, size_upper: 5, encode_table: Some(table), ..Default::default() };
        assert_eq!(validate_string("1a3", &c), 1);
        assert_eq!(validate_string("123", &c), 0);
    }
}
