//! X.691 §14: contributes zero bits to the encoding either direction —
//! mirrors `NullPerHandler` (`runtime/src/PerCodec.cpp`) exactly.

use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode(_w: &mut Writer) {}

pub fn decode(_r: &mut Reader) -> Result<(), DecodeError> {
    Ok(())
}
