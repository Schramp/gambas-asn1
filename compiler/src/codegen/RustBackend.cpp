#include "RustBackend.hpp"

namespace asn1::codegen {

// Rust ENUMERATED emission (#234, pairs with CppBackend's #226) — real Rust
// enum codegen, not a placeholder. No encode/decode runtime wiring yet
// (that's #218/#219, the native BER runtime); this only needs to compile
// as Rust for a representative schema.
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

} // namespace asn1::codegen
