//! Constraint-validation counter and wiring — the Rust analogue of
//! `runtime/include/asn1cpp/codec/ValidateCounter.hpp` +
//! `BerCodec.cpp`/`JerCodec.cpp`'s own `bump_validate_fail()`/
//! `record_validate_fail()` call sites.
//!
//! The per-kind X.680 §51 checks themselves (INTEGER range, SIZE, FROM
//! alphabet, ENUMERATED unknown-value) are table-driven functions in
//! `constraints`/`spec::enumerated`, called from per-member VALIDATE rows
//! and `encode_pdu`'s top-level SIZE check. This
//! module is only the plumbing: a global failure counter
//! (`bump_validate_fail`/`validate_fail_count`, mirroring
//! the C++ side's `ValidateCounter.hpp` exactly — same relaxed-ordering
//! atomic, same reset/read/bump trio) plus `check_delta`, the funnel every
//! one of those callers reports a nonzero delta through.
//!
//! Gated by `debug::debug_flags()`, matching the C++ side's own
//! `DBG_NO_VALIDATE`/`DBG_VALIDATE_TRACE` bits (`debug.rs`) exactly —
//! validation runs by default; `DBG_NO_VALIDATE` opts out at runtime (no
//! rebuild needed, same contract every other `ASN1CPP_DEBUG` bit already
//! has); `DBG_VALIDATE_TRACE` additionally prints each failure. Unlike the
//! C++ side, there is no separate `ASN1CPP_VALIDATE` compile-time gate —
//! this crate has no cargo-feature equivalent wired up yet, and the
//! valid case is already cheap: `check_delta` inlines to one `delta != 0`
//! test at the call site and only a nonzero delta reaches the cold,
//! out-of-line `debug_flags()` gate and report (the same "hot path pays
//! zero between report scopes" reasoning
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

/// Record one constraint-validation failure (via `check_delta`).
pub fn bump_validate_fail() {
    VALIDATE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Gate + report a constraint-check delta computed by the caller —
/// the shared funnel for every X.680 §51 check: per-member rows
/// (`ber::object`'s `Asn1Seq::validate`) and a named SEQUENCE OF's
/// top-level SIZE check (`ber::object::encode_pdu_into`). `phase` is
/// `"encode"` or `"decode"`, only used for the trace line.
///
/// Inlined so a valid value (`delta == 0`) costs one compare at the call
/// site; everything else lives in the cold [`report`].
#[inline]
pub fn check_delta(delta: i64, name: &str, phase: &str) {
    if delta != 0 {
        report(delta, name, phase);
    }
}

/// Out-of-line slow path of [`check_delta`]. A no-op when
/// `debug::DBG_NO_VALIDATE` is set; `debug::DBG_VALIDATE_TRACE`
/// additionally prints each failure; without it, failures are counted
/// (`bump_validate_fail`) but silent — matching `BerCodec.cpp`'s own
/// `record_validate_fail`/`DBG_VALIDATE_TRACE` split.
#[cold]
#[inline(never)]
fn report(delta: i64, name: &str, phase: &str) {
    if crate::debug::debug_flags() & crate::debug::DBG_NO_VALIDATE != 0 {
        return;
    }
    bump_validate_fail();
    if crate::debug::debug_flags() & crate::debug::DBG_VALIDATE_TRACE != 0 {
        eprintln!("[VALIDATE-{}][BER] {} delta={}", phase.to_uppercase(), name, delta);
    }
}

// X.680 §51 SIZE constraint checking lives in `constraints::validate_size`
// — a static Constraints table per member, not a generated per-member
// function (see `constraints`'s own module doc for why).

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
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
}
