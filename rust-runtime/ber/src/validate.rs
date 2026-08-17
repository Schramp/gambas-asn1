//! Constraint-validation counter and wiring — the Rust analogue of
//! `runtime/include/asn1cpp/codec/ValidateCounter.hpp` +
//! `BerCodec.cpp`/`JerCodec.cpp`'s own `bump_validate_fail()`/
//! `record_validate_fail()` call sites.
//!
//! `Asn1Value::validate()` (`value.rs`) is a default-no-op, object-safe
//! method every generated type inherits; a type with a real constraint
//! (X.680 §51 SubtypeConstraint) overrides it with the actual per-kind
//! check (INTEGER range, OCTET/BIT STRING and character string SIZE,
//! FROM alphabet, SEQUENCE OF/SET OF SIZE, ENUMERATED unknown-value) —
//! separate, not-yet-implemented follow-on work, not this module. This
//! module is only the plumbing: a global failure counter
//! (`bump_validate_fail`/`validate_fail_count`, mirroring
//! the C++ side's `ValidateCounter.hpp` exactly — same relaxed-ordering
//! atomic, same reset/read/bump trio) plus the call site
//! (`ber_encode_tagged`/`ber_decode_into_tagged`'s default bodies, `value.rs`)
//! that actually invokes `validate()` and reacts to a nonzero delta.
//!
//! Gated by `debug::debug_flags()`, matching the C++ side's own
//! `DBG_NO_VALIDATE`/`DBG_VALIDATE_TRACE` bits (`debug.rs`) exactly —
//! validation runs by default; `DBG_NO_VALIDATE` opts out at runtime (no
//! rebuild needed, same contract every other `ASN1CPP_DEBUG` bit already
//! has); `DBG_VALIDATE_TRACE` additionally prints each failure. Unlike the
//! C++ side, there is no separate `ASN1CPP_VALIDATE` compile-time gate —
//! this crate has no cargo-feature equivalent wired up yet, and the
//! per-call `debug_flags()` check already makes the disabled case cheap
//! (one atomic load, correctly-predicted not-taken branch — the same
//! "hot path pays zero between report scopes" reasoning
//! `runtime/include/asn1cpp/codec/Validation.hpp` uses for its own
//! richer path-tracking layer, intentionally not ported here — this is
//! only the counter, not `ValidationReport`/`ValidatePathScope`).

use std::sync::atomic::{AtomicU64, Ordering};

static VALIDATE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Total constraint-validation failures observed since the last
/// `reset_validate_fail_count()` (or process start). Relaxed ordering —
/// this is a diagnostic counter, not a synchronization point.
pub fn validate_fail_count() -> u64 {
    VALIDATE_FAIL_COUNT.load(Ordering::Relaxed)
}

/// Zero the counter — tests call this between cases to isolate failure
/// counts per case, same usage pattern `ValidateCounter.hpp`'s C++
/// counterpart has.
pub fn reset_validate_fail_count() {
    VALIDATE_FAIL_COUNT.store(0, Ordering::Relaxed);
}

/// Record one constraint-validation failure. Called from
/// `Asn1Value::ber_encode_tagged`/`ber_decode_into_tagged`'s default
/// bodies (`value.rs`) whenever `self.validate()` returns nonzero.
pub fn bump_validate_fail() {
    VALIDATE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Runs `v.validate()` and reacts to a nonzero delta — the actual call
/// site `ber_encode_tagged`/`ber_decode_into_tagged` (`value.rs`) invoke.
/// `phase` is `"encode"` or `"decode"`, only used for the trace line.
///
/// A no-op unless `debug::DBG_NO_VALIDATE` is clear (checked first — one
/// atomic load, correctly-predicted not-taken branch when validation is
/// disabled, same "hot path pays zero" reasoning
/// `runtime/include/asn1cpp/codec/Validation.hpp` uses on the C++ side).
/// `debug::DBG_VALIDATE_TRACE` additionally prints each failure; without
/// it, failures are counted (`bump_validate_fail`) but silent — matching
/// `BerCodec.cpp`'s own `record_validate_fail`/`DBG_VALIDATE_TRACE` split
/// exactly.
pub fn check<T: crate::value::Asn1Value + ?Sized>(v: &T, phase: &str) {
    if crate::debug::debug_flags() & crate::debug::DBG_NO_VALIDATE != 0 {
        return;
    }
    report(v.validate(), std::any::type_name::<T>(), phase);
}

/// Gate + report a delta already computed by the caller — the same shape
/// as `check()` but for callers that don't have an `Asn1Value` to call
/// `.validate()` on. Used by `MemberDescriptor::validate`
/// (`sequence.rs`, X.680 §51 per-member constraint checks that can't hang
/// off `Asn1Value::validate()` because the member's own Rust type — e.g. a
/// bare `i64` INTEGER alias — is shared across every member regardless of
/// its individual bound): the generated per-member fn computes the delta,
/// this gates/counts/traces it exactly like `check()` does.
pub fn check_delta(delta: i64, name: &str, phase: &str) {
    if crate::debug::debug_flags() & crate::debug::DBG_NO_VALIDATE != 0 {
        return;
    }
    report(delta, name, phase);
}

fn report(delta: i64, name: &str, phase: &str) {
    if delta != 0 {
        bump_validate_fail();
        if crate::debug::debug_flags() & crate::debug::DBG_VALIDATE_TRACE != 0 {
            eprintln!("[VALIDATE-{}][BER] {} delta={}", phase.to_uppercase(), name, delta);
        }
    }
}

/// X.680 §25/§26 SIZE constraint check, generic over what "size" means for
/// the caller's own kind (byte count for OCTET STRING, bit count for BIT
/// STRING via `BitString::bit_count()`, character count for a restricted
/// character string — same `n`, different unit, computed by the caller
/// before calling this). Mirrors `OctetString::validate`/`BitString::validate`
/// (`runtime/include/asn1cpp/types/OctetString.hpp`/`BitString.hpp`)
/// exactly: `0` valid; positive = too short (below `lower`); negative = too
/// long (above `upper`, only when `bounded`); `extensible` (X.680 §51.8.3)
/// always `0`. `RustBackend::emit_member_type_descriptor`
/// (`compiler/src/codegen/RustBackend.cpp`) emits one call per constrained
/// member, same "generic runtime function, one-line codegen call" shape
/// `integer::range_delta_i64`/`range_delta_u64` already use.
pub fn size_delta(n: usize, extensible: bool, bounded: bool, lower: i64, upper: i64) -> i64 {
    if extensible {
        return 0;
    }
    let n = n as i64;
    if n < lower {
        return lower - n;
    }
    if bounded && n > upper {
        return upper - n;
    }
    0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::reader::Reader;
    use crate::tag::{universal, Tag};
    use crate::value::Asn1Value;
    use std::sync::Mutex;

    // VALIDATE_FAIL_COUNT is one process-global counter; cargo test runs
    // tests in parallel by default, so every test in this module that
    // reads/resets it needs to hold this lock for its whole body or two
    // tests interleaving would see each other's bumps.
    // pub(crate): sequence.rs's own MemberDescriptor::validate tests share
    // this same process-global counter and need to serialize against these
    // tests too, not just against each other.
    pub(crate) static COUNTER_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn bump_and_reset_round_trip() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        reset_validate_fail_count();
        assert_eq!(validate_fail_count(), 0);
        bump_validate_fail();
        bump_validate_fail();
        assert_eq!(validate_fail_count(), 2);
        reset_validate_fail_count();
        assert_eq!(validate_fail_count(), 0);
    }

    // A minimal dogfood type overriding `validate()` — proves the wiring
    // (ber_encode_tagged/ber_decode_into_tagged's default bodies, value.rs)
    // actually reaches a real override, not just the counter functions in
    // isolation. Always-INTEGER-tagged, "valid" iff non-negative — not a
    // real X.680 constraint kind (those are separate, not-yet-implemented
    // follow-on issues), just enough to drive `validate()` deterministically.
    #[derive(Default)]
    struct NonNegative(i64);

    impl Asn1Value for NonNegative {
        fn ber_natural_tag(&self) -> Tag {
            Tag::universal(universal::INTEGER, false)
        }
        fn ber_encode_content(&self, out: &mut Vec<u8>) {
            self.0.ber_encode_content(out);
        }
        fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), crate::reader::DecodeError> {
            self.0.ber_decode_content(content)
        }
        fn validate(&self) -> i64 {
            if self.0 < 0 {
                -self.0 // delta back to the nearest valid bound (0)
            } else {
                0
            }
        }
    }

    #[test]
    fn encode_of_an_invalid_value_bumps_the_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        reset_validate_fail_count();
        let mut out = Vec::new();
        NonNegative(-5).ber_encode(&mut out);
        assert_eq!(validate_fail_count(), 1);
    }

    #[test]
    fn encode_of_a_valid_value_does_not_bump_the_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        reset_validate_fail_count();
        let mut out = Vec::new();
        NonNegative(5).ber_encode(&mut out);
        assert_eq!(validate_fail_count(), 0);
    }

    #[test]
    fn decode_of_an_invalid_value_bumps_the_counter() {
        let _guard = COUNTER_LOCK.lock().unwrap();
        reset_validate_fail_count();
        let mut bytes = Vec::new();
        (-5i64).ber_encode(&mut bytes); // valid encode: only the *decoded* NonNegative is checked
        let mut r = Reader::new(&bytes);
        let mut v = NonNegative::default();
        v.ber_decode_into(&mut r).unwrap();
        assert_eq!(validate_fail_count(), 1);
    }

    // ---- size_delta ---------------------------------------------------

    #[test]
    fn size_delta_in_range_is_zero() {
        assert_eq!(size_delta(5, false, true, 1, 10), 0);
        assert_eq!(size_delta(1, false, true, 1, 10), 0);
        assert_eq!(size_delta(10, false, true, 1, 10), 0);
    }

    #[test]
    fn size_delta_too_short_is_positive() {
        assert_eq!(size_delta(0, false, true, 1, 10), 1);
    }

    #[test]
    fn size_delta_too_long_is_negative() {
        assert_eq!(size_delta(12, false, true, 1, 10), -2);
    }

    #[test]
    fn size_delta_unbounded_ignores_upper() {
        assert_eq!(size_delta(1_000_000, false, false, 1, 10), 0);
        assert_eq!(size_delta(0, false, false, 1, 10), 1);
    }

    #[test]
    fn size_delta_extensible_is_always_zero() {
        assert_eq!(size_delta(0, true, true, 1, 10), 0);
        assert_eq!(size_delta(1_000_000, true, true, 1, 10), 0);
    }
}
