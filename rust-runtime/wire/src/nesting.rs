//! Decode nesting limit, shared by every codec's walker. Each codec's
//! reader carries a [`Depth`]; every SEQUENCE/SET, CHOICE and SEQUENCE
//! OF/SET OF level a decoder descends into enters one level, and past
//! [`MAX_DECODE_DEPTH`] levels the decode fails instead of recursing
//! further, so a forged deeply nested input (a self-referential type,
//! X.680 §29) cannot exhaust the stack. A reader opened over a nested
//! value's bytes (a BER TLV's contents, a PER open type) starts at its
//! parent's depth. The C++ runtime applies the same limit
//! (`DecodeDepth`, `runtime/include/asn1cpp/codec/DecodeDepth.hpp`).

/// Constructed nesting levels a decode may descend; well above any real
/// schema's depth, well below what an 8 MiB stack survives.
pub const MAX_DECODE_DEPTH: u32 = 256;

/// Constructed levels the decode holding this reader has descended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Depth(u32);

impl Depth {
    /// @brief Enters one nesting level.
    /// @return False, leaving the depth unchanged, when the decode is
    ///         already [`MAX_DECODE_DEPTH`] levels deep.
    pub(crate) fn enter(&mut self) -> bool {
        if self.0 >= MAX_DECODE_DEPTH {
            return false;
        }
        self.0 += 1;
        true
    }

    /// @brief Leaves the level the matching [`Depth::enter`] entered.
    pub(crate) fn leave(&mut self) {
        self.0 -= 1;
    }
}

/// Error message for a decode that exceeded [`MAX_DECODE_DEPTH`].
pub(crate) fn too_deep() -> String {
    format!("nesting deeper than {MAX_DECODE_DEPTH} levels")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_stops_at_the_limit_and_leave_restores() {
        let mut d = Depth::default();
        for _ in 0..MAX_DECODE_DEPTH {
            assert!(d.enter());
        }
        assert!(!d.enter());
        d.leave();
        assert!(d.enter());
    }
}
