//! Decode nesting limit, shared by every codec's walker. Each SEQUENCE/SET,
//! CHOICE and SEQUENCE OF/SET OF level a decoder descends into holds one
//! [`DepthGuard`]; past [`MAX_DECODE_DEPTH`] levels the decode fails instead
//! of recursing further, so a forged deeply nested input (a self-referential
//! type, X.680 §29) cannot exhaust the stack. The C++ runtime applies the
//! same limit (`DecodeDepthGuard`, `runtime/include/asn1cpp/codec/DecodeDepth.hpp`).

use std::cell::Cell;

/// Constructed nesting levels a decode may descend; well above any real
/// schema's depth, well below what an 8 MiB stack survives.
pub const MAX_DECODE_DEPTH: u32 = 256;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// One level of decode nesting, released on drop.
pub(crate) struct DepthGuard(());

impl DepthGuard {
    /// @brief Enters one nesting level.
    /// @return `None` when the decode is already [`MAX_DECODE_DEPTH`] levels deep.
    pub(crate) fn enter() -> Option<DepthGuard> {
        DEPTH.with(|d| {
            let n = d.get();
            if n >= MAX_DECODE_DEPTH {
                return None;
            }
            d.set(n + 1);
            Some(DepthGuard(()))
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Error message for a decode that exceeded [`MAX_DECODE_DEPTH`].
pub(crate) fn too_deep() -> String {
    format!("nesting deeper than {MAX_DECODE_DEPTH} levels")
}
