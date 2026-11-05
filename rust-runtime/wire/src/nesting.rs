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

/// Item count above which a PER SEQUENCE OF/SET OF may not hold an element
/// encoded in zero bits (NULL, X.691 §18; an INTEGER or ENUMERATED with a
/// single value, §11.1.3). Such elements cost no input, so a few octets of
/// length determinant (X.691 §11.9.3.8) would otherwise allocate millions
/// of them. asn1c applies the same rule with 200 (`constr_SET_OF_uper.c`).
/// Change it here and rebuild. The C++ runtime uses the same limit
/// (`kMaxZeroWidthItems`, `ASN1CPP_MAX_ZERO_WIDTH_ITEMS`).
pub const MAX_ZERO_WIDTH_ITEMS: usize = 200;

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
