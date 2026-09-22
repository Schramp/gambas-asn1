//! PER constraint metadata for one type or member (X.691 §10.5/§10.6/§10.9).
//! The `Constraints` data itself is shared with `asn1cpp_ber`
//! — see `asn1cpp_constraints` — since both crates need
//! the exact same superset the compiler already computes once
//! (`Generator`'s backend-agnostic `IntegerSpec`/`MemberTypeDescriptorSpec`).

pub use asn1cpp_constraints::{Constraints, CONSTRAINED, EXTENSIBLE, SEMI_CONSTRAINED, SIZE_CONSTRAINED, UNCONSTRAINED};
