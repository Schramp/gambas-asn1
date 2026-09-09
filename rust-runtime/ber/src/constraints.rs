//! X.680 §51 SubtypeConstraint data + generic validators — the Rust
//! analogue of `runtime/include/asn1cpp/codec/Constraints.hpp` +
//! `Integer::validate`/`UInteger::validate`/`OctetString::validate`/
//! `BitString::validate`/`AsnString<N>::validate` (`runtime/include/
//! asn1cpp/types/*.hpp`).
//!
//! Per review on #473 ("all constraints should be table based, fix it in
//! the runtime. Never put it in code. By using code, there is no way to
//! extract the information by any of the parsers."): codegen emits a
//! `static Constraints` value (plain data, the same shape a C++/PER/XSD
//! tool could introspect without executing anything) per constrained
//! member/type, never a bespoke per-member function. The three
//! `validate_*` functions here are the *only* code — generic, identical
//! for every member of a given value shape, exactly mirroring C++'s own
//! "one `validate(const Constraints&)` method per type, data varies per
//! member" shape (`TypeDescriptor.hpp`'s `MemberDescriptor`/`SeqOfSpec`
//! embed a `Constraints` value the same way).
//!
//! Field subset: only what INTEGER range and SIZE validation actually use
//! today (`lower_bound`/`upper_bound`/`lower_u64`/`upper_u64`/
//! `size_lower`/`size_upper`) — `range_bits`/`int_kind`/the 128-bit
//! fields/the FROM-alphabet fields are C++-side PER/alphabet metadata this
//! crate doesn't consume yet (`FROM` is gambas-asn1#466, not this file);
//! adding them later is a field addition, not a shape change, so nothing
//! here forecloses it.

/// Mirrors `asn1::Constraints` (`Constraints.hpp`) — same field names
/// where the shape overlaps, so the same mental model (and the same
/// flag bits) applies whether reading a C++ or a Rust `Constraints` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Constraints {
    pub flags: u8,
    pub lower_bound: i64,
    pub upper_bound: i64,
    pub lower_u64: u64,
    pub upper_u64: u64,
    pub size_lower: i64,
    pub size_upper: i64,
    /// X.680 §51.4 PermittedAlphabet (gambas-asn1#466) — `encode_table[b]`
    /// for byte `b` gives its position in the permitted alphabet, or
    /// `0xFFFF` if `b` isn't permitted at all. Mirrors `Constraints::
    /// encode_table` (`Constraints.hpp`) exactly, minus the decode-direction
    /// `alphabet`/`alphabet_size` fields (PER-only; this crate's BER/XER
    /// codecs never need the reverse mapping, only `validate_alphabet`
    /// does the forward one). `None` — not `Some(&ALL_0XFFFF)` — means "no
    /// FROM constraint", checked before indexing at all.
    pub encode_table: Option<&'static [u16; 256]>,
}

impl Constraints {
    pub const CONSTRAINED: u8 = 1;
    pub const SEMI_CONSTRAINED: u8 = 2;
    pub const EXTENSIBLE: u8 = 4;
    pub const SIZE_CONSTRAINED: u8 = 8;
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

/// X.680 §25/§26/§51 SIZE check, generic over what "size" means for the
/// caller's own kind (byte count for OCTET STRING, bit count for BIT
/// STRING, character count for a restricted character string, element
/// count for SEQUENCE OF/SET OF — same `n`, different unit, computed by
/// the caller before calling this). Mirrors `OctetString::validate`/
/// `BitString::validate`/`AsnString<N>::validate`'s SIZE half/
/// `SeqOfSpec::validate` exactly: `0` valid; positive = too short;
/// negative = too long; `EXTENSIBLE` always `0`; no `SIZE_CONSTRAINED` bit
/// set at all (unconstrained or FROM-alphabet-only) also always `0`.
pub fn validate_size(n: usize, c: &Constraints) -> i64 {
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

/// X.680 §51.4 PermittedAlphabet check (gambas-asn1#466). Mirrors the
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

    fn c(flags: u8, lower_bound: i64, upper_bound: i64) -> Constraints {
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

    fn cu(flags: u8, lower_u64: u64, upper_u64: u64) -> Constraints {
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

    fn cs(flags: u8, size_lower: i64, size_upper: i64) -> Constraints {
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
