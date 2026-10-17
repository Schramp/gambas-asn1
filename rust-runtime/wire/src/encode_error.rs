//! Encode failure, the encode-side counterpart of `ber::reader::DecodeError`.
//! Every codec's walker returns it (`ber::object`, `xer::object`,
//! `jer::object`, `per::object`), so a value the runtime cannot encode — a
//! member codegen marked unsupported, a PER constraint violation — fails
//! that one encode and leaves the process running. The C++ runtime reports
//! the same failures through `PerEncodeStream::encode_failed()`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    pub message: String,
}

impl EncodeError {
    pub fn new(message: impl Into<String>) -> EncodeError {
        EncodeError { message: message.into() }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EncodeError {}
