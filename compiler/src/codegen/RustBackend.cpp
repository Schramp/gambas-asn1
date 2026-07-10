#include "RustBackend.hpp"

namespace asn1::codegen {

// Rust ENUMERATED emission — real Rust enum codegen, not a placeholder. No
// encode/decode runtime wiring yet (the native BER runtime is separate,
// still to come); this only needs to compile as Rust for a representative
// schema.
//
// C++'s hpp/cpp split doesn't map cleanly onto Rust (no header/impl
// separation) — kept anyway for interface symmetry with CppBackend:
// emit_enumerated_hpp emits the `enum` type itself (the primary artifact,
// analogous to C++'s class declaration); emit_enumerated_cpp emits the
// value-lookup `impl TryFrom<i64>` (analogous to C++'s
// EnumSpec::asn_MAP_value2enum — the piece a future BER/PER decoder needs
// to turn a wire value back into a variant).
// Rust convention wants UpperCamelCase enum variants (rustc lints
// non_camel_case_types otherwise — a warning, not a compile error, but
// worth doing idiomatically since it's free: ASN.1 ENUMERATED value names
// are lowercase-first by convention, X.680 §11.2, so this needs an explicit
// capitalize where CppBackend's C++ constant-in-class-scope style doesn't).
static std::string variant_name(const RustBackend& backend, const std::string& asn1_name) {
    return backend.escape(capitalize_first(backend.type_name(asn1_name)));
}

void RustBackend::emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n";
    os << "#[repr(i64)]\n";
    os << std::format("pub enum {} {{\n", tname);
    for (const auto& v : spec.values) {
        os << std::format("    {} = {},\n", variant_name(*this, v.asn1_name), v.value);
    }
    if (spec.extensible)
        os << "    // extensible\n";
    os << "}\n\n";
}

void RustBackend::emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    // Fully-qualified path, not `use`d — keeps this edition-agnostic
    // (TryFrom is only in the 2021+ prelude; pre-2021 crates need the
    // explicit path regardless, so this works everywhere).
    os << std::format("impl std::convert::TryFrom<i64> for {} {{\n", tname);
    os << "    type Error = ();\n";
    os << "    fn try_from(v: i64) -> Result<Self, Self::Error> {\n";
    os << "        match v {\n";
    for (const auto& v : spec.values) {
        os << std::format("            {} => Ok({}::{}),\n",
                           v.value, tname, variant_name(*this, v.asn1_name));
    }
    os << "            _ => Err(()),\n";
    os << "        }\n";
    os << "    }\n";
    os << "}\n\n";
}

// Rust INTEGER emission — pairs with CppBackend::emit_integer_hpp/cpp.
//
// Unlike CppBackend, native_int_type() is reused directly for the top-level
// type alias here: Rust's i128 is a real primitive (no C++-style stub with
// a deleted constructor blocking its use), and Vec<u8> works fine as an
// alias target too, so there's no need for CppBackend's dual-mapping
// workaround (see its emit_integer_hpp note).
//
// emit_integer_hpp emits the type alias + named constants (i64, matching
// CppBackend's constant type regardless of storage_kind — same convention,
// carried over). emit_integer_cpp emits a range-check function using the
// resolved constraint bounds — the Rust analogue of the bounds baked into
// C++'s Constraints struct, and the piece a future decoder would call to
// validate a wire value before accepting it.
void RustBackend::emit_integer_hpp(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << std::format("pub type {} = {};\n\n", tname, native_int_type(spec.storage_kind));

    for (const auto& v : spec.named_values)
        os << std::format("pub const {}: i64 = {};\n", value_name(v.asn1_name), v.value);
    if (!spec.named_values.empty()) os << "\n";
}

void RustBackend::emit_integer_cpp(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;
    std::string fname = escape(to_snake_case(tname) + "_in_range");

    os << std::format("pub fn {}(v: i64) -> bool {{\n", fname);
    if (!spec.has_constraint) {
        os << "    let _ = v;\n    true // unconstrained\n";
    } else if (spec.semi_constrained || spec.hi_is_large) {
        // hi_is_large's upper bound may exceed i64::MAX (X.691 §10.5.6,
        // e.g. UINT64_MAX) and isn't exactly representable in an i64
        // parameter — treated the same as semi-constrained (lower-bound-only
        // check) rather than emitting an incorrect upper comparison.
        os << std::format("    v >= {} // {}\n", spec.lower_s64,
                           spec.hi_is_large ? "upper bound exceeds i64 range, not checked"
                                             : "semi-constrained, no upper cap");
    } else {
        os << std::format("    v >= {} && v <= {}\n", spec.lower_s64, spec.upper_s64);
    }
    os << "}\n\n";
}

/// @brief Map a builtin type to its Rust native type.
/// @param bt Built-in type tag (never SEQUENCE/CHOICE/TypeRef/INTEGER/
///           ENUMERATED — same precondition as CppBackend's equivalent).
/// @return Rust type name, e.g. `"Vec<u8>"`, `"String"`, `"bool"`.
/// @note Deliberately simple mappings (`String` for every text type
///       regardless of alphabet, `Vec<u8>` for OCTET STRING/BIT STRING/OID/
///       Any, `String` for UtcTime/GeneralizedTime rather than a real
///       timestamp type) — matches this pairing's scope (compiles as real
///       Rust, no runtime wiring yet). A real BER/PER runtime would likely
///       want tighter types (e.g. `[u32]` arcs for OID); revisit then.
static std::string native_builtin_type(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Boolean:          return "bool";
    case BT::Real:             return "f64";
    case BT::Null:             return "()";
    case BT::BitString:        return "Vec<u8>";
    case BT::OctetString:      return "Vec<u8>";
    case BT::ObjectIdentifier: return "Vec<u64>";
    case BT::RelativeOid:      return "Vec<u64>";
    case BT::Utf8String:       return "String";
    case BT::NumericString:    return "String";
    case BT::PrintableString:  return "String";
    case BT::T61String:        return "String";
    case BT::Ia5String:        return "String";
    case BT::VisibleString:    return "String";
    case BT::GeneralString:    return "String";
    case BT::GraphicString:    return "String";
    case BT::UniversalString:  return "String";
    case BT::BmpString:        return "String";
    case BT::VideotexString:   return "String";
    case BT::ObjectDescriptor: return "String";
    case BT::UtcTime:          return "String";
    case BT::GeneralizedTime:  return "String";
    case BT::Any:              return "Vec<u8>";
    default:                   return "Vec<u8>";  // Integer/Enumerated: unreachable here
    }
}

/// @brief Emit the Rust type alias (and size-check function, if constrained)
///        for a builtin-alias type.
/// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
/// @param os   Output stream to write to.
/// @note Only one emit method exists on Backend for this construct (no
///       separate hpp/cpp split, matching the C++ side: the alias itself is
///       a one-line type declaration, not worth two methods). Emits the
///       type alias, plus a size-check function when a SIZE constraint is
///       present — the Rust analogue of the bounds baked into C++'s
///       Constraints struct. FROM-alphabet constraints are not validated by
///       the generated function (same "no runtime wiring yet" scope as the
///       INTEGER pairing's hi_is_large note).
void RustBackend::emit_builtin_alias_cpp(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << std::format("pub type {} = {};\n\n", tname, native_builtin_type(spec.builtin_type));

    if (!spec.has_size_constraint) return;

    std::string fname = escape(to_snake_case(tname) + "_size_ok");
    os << std::format("pub fn {}(v: &{}) -> bool {{\n", fname, native_builtin_type(spec.builtin_type));
    if (spec.size_bounded) {
        os << std::format("    (v.len() as i64) >= {} && (v.len() as i64) <= {}\n",
                           spec.size_lower, spec.size_upper);
    } else {
        // Semi-constrained (SIZE(n..MAX)) — no upper cap, same rationale as
        // IntegerSpec's semi_constrained handling.
        os << std::format("    (v.len() as i64) >= {} // semi-constrained, no upper cap\n",
                           spec.size_lower);
    }
    os << "}\n\n";
}

} // namespace asn1::codegen
