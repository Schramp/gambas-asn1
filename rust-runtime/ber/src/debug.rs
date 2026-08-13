//! Runtime debug tracing — the Rust analogue of
//! `runtime/include/asn1cpp/codec/Debug.hpp`. `ASN1CPP_DEBUG=<hex>` enables
//! the same bit-numbered traces on either runtime; a bit not yet wired here
//! is simply inert (no trace emitted), never an error.

use std::sync::OnceLock;

pub const DBG_BER_CHOICE: u32 = 1 << 0; // CHOICE tag miss / alternative dispatch (decode)
pub const DBG_BER_SEQ: u32 = 1 << 1; // SEQUENCE EXPLICIT wrap/unwrap, tag mismatches (decode)
pub const DBG_XER: u32 = 1 << 2; // XER parse / emit
pub const DBG_PER: u32 = 1 << 3; // PER bit-level ops
pub const DBG_BER_WRITE: u32 = 1 << 4; // BER encode: each member/alt written
pub const DBG_NO_VALIDATE: u32 = 1 << 5; // Suppress validate() at runtime
pub const DBG_VALIDATE_TRACE: u32 = 1 << 6; // Constraint validation failures

/// Read `ASN1CPP_DEBUG` once and cache it — same one-shot-read contract as
/// `asn1::debug_flags()` (Debug.hpp): no rebuild/recompile needed to change
/// tracing, just re-run with a different env var value.
pub fn debug_flags() -> u32 {
    static FLAGS: OnceLock<u32> = OnceLock::new();
    *FLAGS.get_or_init(|| {
        std::env::var("ASN1CPP_DEBUG")
            .ok()
            .and_then(|s| {
                let s = s.trim();
                let (s, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Some(hex) => (hex, 16),
                    None => (s, 10),
                };
                u32::from_str_radix(s, radix).ok()
            })
            .unwrap_or(0)
    })
}
