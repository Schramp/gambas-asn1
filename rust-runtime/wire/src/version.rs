//! The runtime's version: the crate version, which the CMake configure step
//! keeps equal to the top-level `VERSION` file and so to the compiler's.
//! Generated code uses the runtime API of the compiler that produced it;
//! every generated `lib.rs` checks its compiler's version against this
//! runtime with `runtime_version_is` in a `const` assertion, so generated
//! code does not compile against a runtime of another version.

/// The runtime version, `X.Y.Z`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAJOR: u32 = parse(env!("CARGO_PKG_VERSION_MAJOR"));
const MINOR: u32 = parse(env!("CARGO_PKG_VERSION_MINOR"));
const PATCH: u32 = parse(env!("CARGO_PKG_VERSION_PATCH"));

/// A decimal version component, at compile time.
const fn parse(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut n = 0u32;
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    n
}

/// Whether this runtime is version `major.minor.patch`, the version of the
/// compiler that generated the code calling it.
pub const fn runtime_version_is(major: u32, minor: u32, patch: u32) -> bool {
    major == MAJOR && minor == MINOR && patch == PATCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_match_version_string() {
        assert_eq!(VERSION, format!("{MAJOR}.{MINOR}.{PATCH}"));
        assert!(runtime_version_is(MAJOR, MINOR, PATCH));
        assert!(!runtime_version_is(MAJOR, MINOR, PATCH + 1));
    }
}
