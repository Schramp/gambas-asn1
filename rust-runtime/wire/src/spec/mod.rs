//! Codec-agnostic table types: the per-type specs codegen emits and every
//! codec (BER, XER, PER) walks. A spec holds schema facts and typed
//! accessors only; wire framing and stream I/O live in the codec modules.

pub mod choice;
pub mod enumerated;
pub mod object;
pub mod primitive;
pub mod sequence;
