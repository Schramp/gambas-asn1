//! X.691 unaligned PER (UPER) — bit-level `reader`/`writer` and
//! per-construct encode/decode. Nested under the crate root (rather than
//! flat, like BER/XER's own modules) purely to avoid name collisions:
//! `per::reader`/`per::sequence`/etc. share names with the root-level BER/
//! XER modules of the same construct but have unrelated (bit-level, not
//! TLV) representations. `constraints` (X.680 §51 SubtypeConstraint data)
//! is the one exception, read from the crate root (`crate::constraints`)
//! rather than duplicated here — plain data both this module and the root
//! BER/XER modules read, computed once at codegen time.

pub mod bit_string;
pub mod choice;
pub mod enumerated;
pub mod integer;
pub mod length;
pub mod octet_string;
pub mod reader;
pub mod seq_of;
pub mod sequence;
pub mod strings;
pub mod uinteger;
pub mod writer;
