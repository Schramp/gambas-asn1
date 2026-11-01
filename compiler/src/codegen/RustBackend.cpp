#include "RustBackend.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace asn1::codegen {

/// @brief The `XerInstruction` of a SEQUENCE/SET member or CHOICE
///        alternative row: the X.693 §21 BASE64/UTF8 instruction on its
///        own OCTET STRING, or on the named OCTET STRING type it references.
///        Table data, not a distinct `MemberRef` shape: either way the
///        value unwraps to a plain `OctetString`, so the XER walker reads
///        the instruction off the row (`MemberMeta`/`AltMeta`).
/// @param m  The member or alternative.
/// @return The Rust path of the `XerInstruction` variant.
static const char* rust_xer_instruction(const TaggedMemberSpec& m) {
    ast::XerEncoding enc = ast::XerEncoding::Default;
    if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::OctetString) enc = m.xer_encoding;
    else if (!m.mbuiltin && m.ref_builtin_alias && *m.ref_builtin_alias == ast::BuiltinType::OctetString) enc = m.ref_xer_encoding;
    switch (enc) {
    case ast::XerEncoding::Base64: return "asn1cpp_wire::spec::object::XerInstruction::Base64";
    case ast::XerEncoding::Utf8:   return "asn1cpp_wire::spec::object::XerInstruction::Utf8";
    default:                       return "asn1cpp_wire::spec::object::XerInstruction::Default";
    }
}

// Rust ENUMERATED emission — real Rust enum codegen, not a placeholder. No
// encode/decode runtime wiring yet (the native BER runtime is separate,
// still to come); this only needs to compile as Rust for a representative
// schema.
//
// C++'s hpp/cpp split doesn't map cleanly onto Rust (no header/impl
// separation) — kept anyway for interface symmetry with CppBackend:
// emit_enumerated_declaration emits the `enum` type itself (the primary artifact,
// analogous to C++'s class declaration); emit_enumerated_definition emits the
// value-lookup `impl TryFrom<i64>` (analogous to C++'s
// EnumSpec::asn_MAP_value2enum — the piece a future BER/PER decoder needs
// to turn a wire value back into a variant).
// Minimal transliteration (to_cpp_name: hyphen -> underscore only, case
// preserved) — not a real word-split recase (to_upper_camel_case), and
// deliberately NOT capitalize_first either. Naming-fidelity rule, same
// as for type_name/member_name/synthetic_name/value_name: two distinct
// ASN.1 value names (e.g. "eight-bit-binary" and "eightBitBinary") must
// not fold to the same Rust variant, which real recasing risks and
// minimal transliteration avoids. capitalize_first would reintroduce exactly that
// risk for free — two values differing only in first-letter case (e.g.
// "foo"/"Foo") would fold — for no benefit: unlike make_synthetic_name's
// parent+member concatenation (where capitalize_first at least marks a
// boundary, albeit a weaker one than inserting a separator would), a
// variant name has no prefix to concatenate with, so there's no boundary
// to mark at all. Any resulting non_camel_case_types lint is already
// suppressed at the enclosing `pub enum`'s own #[allow(...)]
// (emit_enumerated_declaration/emit_choice_declaration), same as every
// other naming surface — rustc has no hard syntax requirement that a
// variant start uppercase, only a style lint.
static std::string variant_name(const RustBackend& backend, const std::string& asn1_name) {
    return backend.escape(to_cpp_name(asn1_name));
}

// `ChoiceAlternativeSpec::accessor_name` is escaped as a raw identifier
// (`r#present`) when the ASN.1 alternative name collides with a reserved
// word from `emit_choice_declaration`'s own extra-list ("present",
// "set_present", ...) — correct when the name is used standalone
// (CppBackend's own `accessor_name`-as-a-method-name use), but every
// RustBackend use instead splices it into a larger compound identifier
// (`{prefix}_get_{accessor_name}`, `asn_TYP_{type}_{accessor_name}`).
// `r#` is only valid Rust syntax as a standalone token — gluing it into a
// longer name produces an "unknown prefix" parse error (`..._get_r#present`
// gets lexed as identifier `..._get_r` followed by `#present`). The plain
// snake_case text alone can't collide with a keyword once other text
// surrounds it, so strip the escape before splicing.
static std::string unescape_raw_ident(const std::string& s) {
    return s.starts_with("r#") ? s.substr(2) : s;
}

// Per-builtin-kind lookup tables shared by
// emit_sequence_definition (SEQUENCE members, SEQUENCE OF elements) and
// emit_choice_definition (CHOICE alternatives), file-scoped so there's
// exactly one switch per question asked, not one per caller.

/// @brief Per-builtin-kind BER tag constant. See TaggedMemberSpec::mbuiltin's
///        doc comment (Backend.hpp) for why native storage type alone can't
///        drive this (e.g. BIT STRING/OBJECT IDENTIFIER/Any all map to
///        `Vec<u8>`, but need different tags).
/// @note The `mtype` parameter's own Integer case (`mtype == "i64"`) is
///       unreachable in practice — every caller (`rust_tag_for_builtin_or_alias`,
///       used at both member/alt level and, via `ElemShape`, SEQUENCE OF/SET
///       OF element level) intercepts Integer via `storage_kind` before ever
///       reaching this switch. Kept as a defensive fallback, not dead-code-
///       deleted, since a future direct caller could still reach it.
static const char* builtin_ber_tag(ast::BuiltinType bt, const std::string& mtype) {
    switch (bt) {
    case ast::BuiltinType::Integer:     return mtype == "asn1cpp_wire::integer::Integer" ? "asn1cpp_wire::integer::INTEGER_TAG" : nullptr;
    case ast::BuiltinType::Boolean:     return "asn1cpp_wire::boolean::BOOLEAN_TAG";
    case ast::BuiltinType::OctetString: return "asn1cpp_wire::octet_string::OCTET_STRING_TAG";
    case ast::BuiltinType::Null:        return "asn1cpp_wire::null::NULL_TAG";
    case ast::BuiltinType::Real:        return "asn1cpp_wire::real::REAL_TAG";
    case ast::BuiltinType::BitString:   return "asn1cpp_wire::bit_string::BIT_STRING_TAG";
    case ast::BuiltinType::ObjectIdentifier: return "asn1cpp_wire::oid::OBJECT_IDENTIFIER_TAG";
    case ast::BuiltinType::RelativeOid: return "asn1cpp_wire::relative_oid::RELATIVE_OID_TAG";
    case ast::BuiltinType::Ia5String:   return "asn1cpp_wire::strings::IA5_STRING_TAG";
    // The other 11 restricted-character-string kinds
    // (native_builtin_type maps each to its own rust-runtime/wire::strings
    // newtype, not plain String) — each newtype's own TypeTag carries its
    // own tag, matching the constant named here.
    case ast::BuiltinType::Utf8String:       return "asn1cpp_wire::strings::UTF8_STRING_TAG";
    case ast::BuiltinType::NumericString:    return "asn1cpp_wire::strings::NUMERIC_STRING_TAG";
    case ast::BuiltinType::PrintableString:  return "asn1cpp_wire::strings::PRINTABLE_STRING_TAG";
    case ast::BuiltinType::T61String:        return "asn1cpp_wire::strings::T61_STRING_TAG";
    case ast::BuiltinType::VisibleString:    return "asn1cpp_wire::strings::VISIBLE_STRING_TAG";
    case ast::BuiltinType::GeneralString:    return "asn1cpp_wire::strings::GENERAL_STRING_TAG";
    case ast::BuiltinType::GraphicString:    return "asn1cpp_wire::strings::GRAPHIC_STRING_TAG";
    case ast::BuiltinType::UniversalString:  return "asn1cpp_wire::strings::UNIVERSAL_STRING_TAG";
    case ast::BuiltinType::BmpString:        return "asn1cpp_wire::strings::BMP_STRING_TAG";
    case ast::BuiltinType::VideotexString:   return "asn1cpp_wire::strings::VIDEOTEX_STRING_TAG";
    case ast::BuiltinType::ObjectDescriptor: return "asn1cpp_wire::strings::OBJECT_DESCRIPTOR_TAG";
    case ast::BuiltinType::UtcTime:          return "asn1cpp_wire::strings::UTC_TIME_TAG";
    case ast::BuiltinType::GeneralizedTime:  return "asn1cpp_wire::strings::GENERALIZED_TIME_TAG";
    // An inline `ENUMERATED { ... }` member/element sets `mbuiltin` here
    // like any other builtin (a referenced top-level ENUMERATED type takes
    // the separate `!mbuiltin` TypeRef path instead, unaffected).
    case ast::BuiltinType::Enumerated:       return "asn1cpp_wire::ber::enumerated::ENUMERATED_TAG";
    // Not yet covered — no PrimitiveRef dispatch in rust-runtime/wire for
    // these kinds yet, so a member of any of them becomes an Unsupported
    // row.
    // Only ANY remains uncovered here.
    default:                                 return nullptr;
    }
}

/// @brief Same lookup as builtin_ber_tag, but for a member/alternative whose
///        own type may be a TypeRef alias rather than a direct builtin
///        (mbuiltin == nullopt) — the i64-native-INTEGER-alias case still
///        needs a tag despite carrying no mbuiltin.
/// @note The direct-builtin Integer case is intercepted here via
///       `storage_kind` (a real enum, not a string coincidence) before
///       ever reaching builtin_ber_tag's own `case Integer` — used at
///       member/alt level and, via `ElemShape` (Backend.hpp,
///       `element_shape_covered`), SEQUENCE OF/SET OF element level too,
///       both with a real `storage_kind` to intercept on. The `!mbuiltin`
///       TypeRef-alias fallback below is untouched: `SequenceMemberSpec`/
///       `ChoiceAlternativeSpec` have no `storage_kind` for that case
///       either (`mbuiltin` itself is unset), so there's nothing to thread
///       through — same pre-existing string check.
static const char* rust_tag_for_builtin_or_alias(std::optional<ast::BuiltinType> mbuiltin,
                                                  IntStorageKind storage_kind,
                                                  const std::string& mtype) {
    if (!mbuiltin) return mtype == "asn1cpp_wire::integer::Integer" ? "asn1cpp_wire::integer::INTEGER_TAG" : nullptr;
    if (*mbuiltin == ast::BuiltinType::Integer)
        // Same INTEGER_TAG regardless of storage width — the Rust *type*
        // varies (i64/u64/i128/ArbitraryInteger), the wire tag never does.
        // ARBITRARY now has a real impl too (integer::ArbitraryInteger) —
        // no exclusion needed.
        return "asn1cpp_wire::integer::INTEGER_TAG";
    return builtin_ber_tag(*mbuiltin, mtype);
}

/// @brief True for the 12 character-string builtins X.680 §51 SIZE
///        validation covers — the same set
///        `Generator::build_member_type_descriptor_spec`'s
///        `sizeable_universal_tag` lambda maps to a universal tag, minus
///        OCTET STRING/BIT STRING (their own row-loop branch already
///        handles those). Every one of these newtypes
///        (or, for IA5String, bare `String`) `Deref`s to `String`
///        (`rust-runtime/wire/src/strings.rs`'s own module doc), so the
///        member-row loop's own `v.{mname}.len()` — byte length, matching
///        C++'s own `AsnString<N>::validate`, whose own doc notes this is
///        byte count "not characters for multi-byte encodings like
///        UTF-8", the same simplification carried over here — already
///        works uniformly across the set with no per-kind runtime code.
/// @brief Extracts a Rust type path's last `::`-separated segment —
///        e.g. `"asn1cpp_wire::strings::Utf8String"` -> `"Utf8String"`.
/// @note Every `spec::primitive::PrimitiveRef`/`PrimitiveRefMut` variant
///       name is exactly a builtin leaf type's own Rust type name, so
///       this is all that's needed to pick the right one —
///       `m.mtype`/`a.mtype` already resolve to that fully-qualified path.
static std::string primitive_variant(const std::string& rust_type) {
    auto pos = rust_type.rfind("::");
    return pos == std::string::npos ? rust_type : rust_type.substr(pos + 2);
}

/// @brief Format a double as an exact Rust `f64` literal: shortest
///        round-trip digits, or `f64::INFINITY` / `f64::NEG_INFINITY`.
/// @param d Finite or infinite value (never NaN).
/// @return Literal text; always contains `.`/`e` or names a constant.
static std::string rust_f64_literal(double d) {
    if (std::isinf(d)) return d > 0 ? "f64::INFINITY" : "f64::NEG_INFINITY";
    std::string f = std::format("{}", d);
    if (f.find_first_of(".e") == std::string::npos) f += ".0";
    return f;
}

/// @brief Emit a REAL's value range (X.680 §47.4) and JER base constraint
///        (X.697 §23.1.4) as a `Constraints` static, read by
///        `constraints::validate_real` and `jer::real`.
/// @param os    Output stream.
/// @param cname Static's identifier.
/// @param r     Range and base constraint; flags 0 when neither applies.
static void emit_real_constraints(std::ostream& os, const std::string& cname, const RealRangeSpec& r) {
    int flags = (r.present ? asn1::Constraints::REAL_RANGE : 0)
              | (r.base10_only ? asn1::Constraints::REAL_BASE_10 : 0)
              | (r.lower_open ? asn1::Constraints::REAL_LOWER_OPEN : 0)
              | (r.upper_open ? asn1::Constraints::REAL_UPPER_OPEN : 0)
              | (r.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    os << "#[allow(non_upper_case_globals)]\n";
    os << std::format(
        "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
        "    flags: {}, real_lower: {}, real_upper: {}, ..asn1cpp_wire::constraints::UNCONSTRAINED\n"
        "}};\n\n",
        cname, flags, rust_f64_literal(r.lower), rust_f64_literal(r.upper));
}

static bool is_sizeable_string_kind(ast::BuiltinType bt) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Utf8String:
    case BT::NumericString:
    case BT::PrintableString:
    case BT::T61String:
    case BT::Ia5String:
    case BT::VisibleString:
    case BT::GeneralString:
    case BT::GraphicString:
    case BT::UniversalString:
    case BT::BmpString:
    case BT::VideotexString:
    case BT::ObjectDescriptor:
        return true;
    default:
        return false;
    }
}

void RustBackend::emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    // Doc comment ties the generated name back to its ASN.1 source —
    // matters most at the edges variant_name's word-split conversion can
    // erase (e.g. "utf-8"/"utf8" both -> "Utf8", "a-b"/"ab" both -> "Ab").
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    os << "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n";
    os << "#[repr(i64)]\n";
    // type_name/synthetic_name preserve the ASN.1 identifier as closely as
    // Rust syntax allows (hyphen -> underscore only, no word-split recase)
    // rather than reflowing it to dodge style lints — a real-world schema's
    // own naming (X.680 §11.2 allows ALL-CAPS, mixed case, etc.) routinely
    // trips non_camel_case_types; suppressed per-item here instead of
    // distorting the name, same tradeoff this backend already makes for
    // `#[path = "..."]` module names (see finalize_output's own #[allow]).
    os << "#[allow(non_camel_case_types)]\n";
    os << std::format("pub enum {} {{\n", tname);
    // variant_name's word-split conversion discards
    // whichever separator distinguished two ASN.1 value names (e.g. "a-b"
    // and "ab" both become "Ab") — a collision sema's own duplicate check
    // never catches, since that only compares the raw ASN.1 identifiers.
    // Guard locally (Rust only needs uniqueness within one enum) rather
    // than let two values silently emit the same variant (E0428).
    std::unordered_map<std::string, std::string> seen_variants;  // variant name -> first asn1_name
    for (const auto& v : spec.values) {
        std::string vname = variant_name(*this, v.asn1_name);
        auto [it, inserted] = seen_variants.emplace(vname, v.asn1_name);
        if (!inserted)
            throw std::runtime_error(std::format(
                "RustBackend: ENUMERATED '{}' — values '{}' and '{}' both map to Rust variant '{}'",
                tname, it->second, v.asn1_name, vname));
        os << std::format("    /// ASN.1: `{}`\n", v.asn1_name);
        os << std::format("    {} = {},\n", vname, v.value);
    }
    if (spec.extensible)
        os << "    // extensible\n";
    os << "}\n\n";
}

/// @brief Emit the definition half of an ENUMERATED type: its `EnumSpec`
///        value/name table, `TryFrom<i64>`, `TypeTag`, and the
///        `AsMemberRef` impl (`MemberRef::Enumerated`) every codec walker
///        dispatches through.
/// @param spec Resolved, backend-agnostic decision (see EnumeratedSpec).
/// @param os   Output stream to write to.
/// @see X.680 §20 (ENUMERATED), X.690 §8.4, X.691 §14.
void RustBackend::emit_enumerated_definition(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    // Fully-qualified path, not `use`d — keeps this edition-agnostic
    // (TryFrom is only in the 2021+ prelude; pre-2021 crates need the
    // explicit path regardless, so this works everywhere).
    os << std::format("impl std::convert::TryFrom<i64> for {} {{\n", tname);
    os << "    type Error = ();\n";
    // `()` written out directly, not `Self::Error` — an
    // ASN.1 ENUMERATED value literally named `Error` (real case on the
    // ETSI LI PS-PDU schema) makes `Self::Error` ambiguous: it could
    // mean either the enum variant `Self::Error` (i.e. `TypeName::Error`)
    // or the trait's own associated type. `type Error = ();` two lines up
    // is a fixed literal this backend always emits, never derived from
    // anything ASN.1-name-dependent, so there's no reason to look it up via
    // path at all — writing `()` directly sidesteps the ambiguity instead
    // of needing fully-qualified syntax (`<Self as
    // std::convert::TryFrom<i64>>::Error`) to resolve it.
    os << "    fn try_from(v: i64) -> Result<Self, ()> {\n";
    os << "        match v {\n";
    for (const auto& v : spec.values) {
        os << std::format("            {} => Ok({}::{}),\n",
                           v.value, tname, variant_name(*this, v.asn1_name));
    }
    os << "            _ => Err(()),\n";
    os << "        }\n";
    os << "    }\n";
    os << "}\n\n";

    // A manual Default impl (not #[derive(Default)] — no
    // stable "pick this variant" attribute exists for a plain fieldless
    // enum without unstable features) picking the first declared value, so
    // a SEQUENCE with a *required* (non-OPTIONAL) member of this type can
    // still derive Default itself. X.680 has no "default enumeration value"
    // concept to defer to (unlike a member's own DEFAULT clause, handled
    // separately by emit_default_setter) — first-declared is an arbitrary
    // but deterministic, harmless choice, same spirit as C's "first enum
    // constant is the zero value" convention. Skipped only if `values` is
    // empty, which isn't valid ASN.1 ENUMERATED syntax (X.680 §20.1
    // requires at least one enumeration) — defensive, not a real case.
    if (!spec.values.empty()) {
        os << std::format("impl Default for {} {{\n", tname);
        os << std::format("    fn default() -> Self {{ {}::{} }}\n",
                           tname, variant_name(*this, spec.values.front().asn1_name));
        os << "}\n\n";

        // One codec-agnostic table (X.680 §20): BER/PER read `value`, XER
        // reads `name`. Sorted ascending by value — the PER ordinal is the
        // sorted position (X.691 §22, matches asn1c and C++'s own sorted
        // EnumSpec::entries), already computed once in spec.sorted_values.
        // Root layout (count, index width) is precomputed here so no codec
        // walker recounts it.
        const auto& sorted_values = spec.sorted_values;
        size_t root_count = spec.root_count > 0 ? static_cast<size_t>(spec.root_count) : sorted_values.size();
        unsigned root_bits = 0;
        for (size_t r = root_count > 1 ? root_count - 1 : 0; r > 0; r >>= 1) ++root_bits;
        // No screaming-snake-case reflow here: tname is already a real,
        // deduped top-level type identifier (or empty-string-safe synthetic
        // one) — recasing it would risk folding two distinct type names
        // together the same way a recased type_name()/synthetic_name()
        // would (ASN.1 naming-fidelity convention; the resulting
        // non_upper_case_globals lint is suppressed below instead).
        std::string map_ident = std::format("{}_ENUM_SPEC", tname);
        os << "#[allow(non_upper_case_globals)]\n";
        // `pub`: a SEQUENCE/CHOICE member elsewhere (a different
        // generated module/file) that resolves to this ENUMERATED type
        // references this static by
        // its fully-qualified `crate::{}::` path for its `MemberRef::
        // Enumerated(.., &EnumSpec)` row; a private `static` would only
        // be visible within this type's own module.
        os << std::format("pub static {}: asn1cpp_wire::spec::enumerated::EnumSpec = asn1cpp_wire::spec::enumerated::EnumSpec {{\n    name: \"{}\",\n    entries: &[\n",
                           map_ident, spec.xer_name);
        for (const auto& v : sorted_values) {
            os << std::format("        asn1cpp_wire::spec::enumerated::EnumEntry {{ value: {}, name: \"{}\" }},\n",
                               v.value, v.asn1_name);
        }
        os << std::format("    ],\n    extensible: {}, root_count: {}, root_bits: {},\n}};\n\n",
                           spec.extensible ? "true" : "false", root_count, root_bits);

        // ENUMERATED's natural tag never varies by declaration.
        os << "\n";
        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", tname);
        os << "    const TAG: ::std::option::Option<asn1cpp_wire::Tag> = Some(asn1cpp_wire::ber::enumerated::ENUMERATED_TAG);\n";
        os << "}\n\n";

        // Reflective `EnumSlot` impl — purely a value<->i64 conversion,
        // no codec method at all; every
        // codec's own `MemberRef::Enumerated` dispatch (`spec::object`'s
        // own doc) reads/writes through this instead of a per-type
        // generated closure.
        os << std::format("impl asn1cpp_wire::spec::object::EnumSlot for {} {{\n", tname);
        os << "    fn enum_get(&self) -> i64 {\n";
        os << "        *self as i64\n";
        os << "    }\n\n";
        // A binding of the enum's own type shares the namespace rustc
        // checks against its variants (E0170), so it is named `__inner`:
        // no ASN.1 identifier contains two consecutive hyphens (X.680
        // §11.3), so no item transliterates to it.
        os << "    fn enum_set(&mut self, v: i64) -> bool {\n";
        os << "        match <Self as std::convert::TryFrom<i64>>::try_from(v) {\n";
        os << "            Ok(__inner) => { *self = __inner; true }\n";
        os << "            Err(_) => false,\n";
        os << "        }\n";
        os << "    }\n";
        os << "}\n\n";

        // Lets this ENUMERATED type appear as a SEQUENCE OF/SET OF
        // element (`SeqOf<T>`/`SetOf<T>`'s own `Asn1SeqOf` impl needs
        // `T: AsMemberRef`).
        os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", tname);
        os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRef::Enumerated(self, &{})\n", map_ident);
        os << "    }\n\n";
        os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRefMut::Enumerated(self, &{})\n", map_ident);
        os << "    }\n\n";
        os << std::format("    fn own_element_xer_name(&self) -> &'static str {{ {}.name }}\n", map_ident);
        os << ber_framing_const(spec);
        os << "}\n\n";
    }
}

void RustBackend::emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const {
    emit_enumerated_declaration(spec, session.buffer(declaration_extension()));
    emit_enumerated_definition(spec, session.buffer(definition_extension()));
}

// Rust INTEGER emission — pairs with CppBackend::emit_integer_declaration/cpp.
//
// Unlike CppBackend, native_int_type() is reused directly for the top-level
// type alias here: Rust's i128 is a real primitive (no C++-style stub with
// a deleted constructor blocking its use), and Vec<u8> works fine as an
// alias target too, so there's no need for CppBackend's dual-mapping
// workaround (see its emit_integer_declaration note).
//
// emit_integer_declaration emits the type alias + named constants (i64, matching
// CppBackend's constant type regardless of storage_kind — same convention,
// carried over). emit_integer_definition emits a range-check function using the
// resolved constraint bounds — the Rust analogue of the bounds baked into
// C++'s Constraints struct, and the piece a future decoder would call to
// validate a wire value before accepting it.
void RustBackend::emit_integer_declaration(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;
    bool newtype = spec.storage_kind == IntStorageKind::S64 || spec.storage_kind == IntStorageKind::U64;

    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    if (newtype) {
        // A real newtype, not a plain alias: every named INTEGER type needs
        // its own type identity to carry per-declaration trait impls
        // (`AsMemberRef` with its own XER element name, `TypeTag`) — the
        // same reason every other builtin except INTEGER already gets one
        // (OctetString/BitString/the 11 string kinds). A TypeRef member to
        // this type dispatches through the trait (Scalar) exactly like a
        // TypeRef to ENUMERATED or another SEQUENCE/CHOICE, with no
        // per-member closure. `Deref`/`DerefMut` to the underlying
        // primitive keep arithmetic/comparison ergonomic.
        os << std::format("#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]\n");
        os << "#[allow(non_camel_case_types)]\n";
        os << std::format("pub struct {}(pub {});\n\n", tname, native_int_type(spec.storage_kind));
        os << std::format("impl std::ops::Deref for {} {{\n    type Target = {};\n    fn deref(&self) -> &Self::Target {{ &self.0 }}\n}}\n\n",
                           tname, native_int_type(spec.storage_kind));
        os << std::format("impl std::ops::DerefMut for {} {{\n    fn deref_mut(&mut self) -> &mut Self::Target {{ &mut self.0 }}\n}}\n\n", tname);
    } else {
        // I128/ARBITRARY storage stays a plain alias — neither has a
        // Constraints-table/PerValue wiring at all yet (this spec's own
        // has_constraint fields go unused for these two kinds, same
        // pre-existing scope boundary as the BER-side `validate` gap:
        // MemberDescriptor.validate is None for I128/ARBITRARY members).
        // A future pairing extending constraint/PER support to these kinds
        // should give them the same newtype treatment above, not before.
        os << "#[allow(non_camel_case_types)]\n";
        os << std::format("pub type {} = {};\n\n", tname, native_int_type(spec.storage_kind));
    }

    for (const auto& v : spec.named_values) {
        os << std::format("/// ASN.1: `{}`\n", v.asn1_name);
        os << "#[allow(non_upper_case_globals)]\n";
        if (spec.storage_kind == IntStorageKind::ARBITRARY)
            os << std::format("pub const {}: {} = {};\n", value_name(v.asn1_name), native_int_type(spec.storage_kind), v.value);
        else
            os << std::format("pub const {}: {} = {}({});\n", value_name(v.asn1_name), native_int_type(spec.storage_kind), native_int_type(spec.storage_kind), v.value);
    }
    if (!spec.named_values.empty()) os << "\n";
}

/// @brief Emit the definition half of a named INTEGER type: its value-range
///        `Constraints` table, named-value constants, `TypeTag`, and the
///        `AsMemberRef` impl that unwraps it to `PrimitiveRef::Integer`.
/// @param spec Resolved, backend-agnostic decision (see IntegerSpec).
/// @param os   Output stream to write to.
/// @see X.680 §19 (INTEGER), X.691 §13 (PER constrained whole number).
void RustBackend::emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;
    bool newtype = spec.storage_kind == IntStorageKind::S64 || spec.storage_kind == IntStorageKind::U64;
    if (!newtype) return;  // I128/ARBITRARY: plain alias, no impl of its own (declaration's own doc).

    bool semi = spec.semi_constrained || spec.hi_is_large;
    int flags = (spec.has_constraint ? (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED) : 0)
              | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    // No recase — see emit_enumerated_definition's matching note.
    std::string cname = std::format("{}_CONSTRAINTS", tname);
    // One combined table (asn1cpp_wire::constraints::Constraints, same
    // shape emit_member_type_descriptor's Integer branch emits) — X.680
    // §19 value range for validation and X.691 §13 wire width for PER.
    // range_bits is -1 for a
    // semi-constrained/unbounded range (no fixed bit width, never read in
    // that case) but can't format as a negative u32 literal; clamp to 0.
    if (spec.storage_kind == IntStorageKind::S64) {
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: {}, lower_bound: {}, upper_bound: {}, lower_u64: 0, upper_u64: 0, "
            "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,\n"
            "}};\n\n",
            cname, flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64);
    } else {
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: {}, lower_bound: 0, upper_bound: 0, lower_u64: {}u64, upper_u64: {}u64, "
            "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,\n"
            "}};\n\n",
            cname, flags, std::max(spec.range_bits, 0), spec.lower_u64, spec.upper_u64);
    }

    // The wrapped primitive's own TAG — INTEGER_TAG regardless of storage
    // width (X.690 §8.3).
    os << "\n";
    os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", tname);
    os << std::format("    const TAG: ::std::option::Option<asn1cpp_wire::Tag> = <{} as asn1cpp_wire::type_tag::TypeTag>::TAG;\n", native_int_type(spec.storage_kind));
    os << "}\n\n";

    // Lets this named INTEGER type appear as a SEQUENCE OF/SET OF element
    // — same rationale as emit_builtin_alias_definition's own AsMemberRef
    // impl: `self.0` reaches the wrapped
    // `Integer`/`UInteger` value `PrimitiveRef` actually needs.
    {
        std::string variant = primitive_variant(native_int_type(spec.storage_kind));
        os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", tname);
        os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRef::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRef::{}(&self.0))\n", variant);
        os << "    }\n\n";
        os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{}(&mut self.0))\n", variant);
        os << "    }\n\n";
        os << std::format("    fn own_element_xer_name(&self) -> &'static str {{ \"{}\" }}\n", spec.xer_name);
        os << ber_framing_const(spec);
        os << "}\n\n";
    }
}

void RustBackend::emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const {
    emit_integer_declaration(spec, session.buffer(declaration_extension()));
    emit_integer_definition(spec, session.buffer(definition_extension()));
}

/// @brief Map a builtin type to its Rust native type.
/// @param bt Built-in type tag (never SEQUENCE/CHOICE/TypeRef/INTEGER/
///           ENUMERATED — same precondition as CppBackend's equivalent).
/// @return Rust type name, e.g. `"Vec<u8>"`, `"String"`, `"bool"`.
/// @note Every restricted-character-string kind maps to its own
///       `rust-runtime/wire::strings` newtype (`Ia5String`,
///       `NumericString`, ...) — a plain `String` could carry only one
///       `TypeTag`/`AsMemberRef` impl, so string kinds can't share it
///       without fighting over which tag to check/write (see `strings.rs`'s
///       module doc). `Vec<u8>` for OCTET
///       STRING/Any. BIT STRING/OBJECT IDENTIFIER/RELATIVE-OID each have
///       their own `bit_string::BitString`/`oid::ObjectIdentifier`/
///       `relative_oid::RelativeOid` structs — same
///       single-impl-per-concrete-type conflict: `Vec<u8>` alone can't
///       carry BIT STRING's unused-bits count, and OID/RELATIVE-OID would
///       fight over one `Vec<u64>` impl since they have different wire
///       encodings — same "distinct type per ASN.1 kind" convention as the
///       string newtypes, not primitive reuse. `UtcTime`/`GeneralizedTime`
///       are also `strings.rs` newtypes, via the same
///       `char_string_type!` macro — X.691 §23's own "character string
///       types" definition includes them, and their BER/XER wire shape is
///       byte-for-byte identical to any other string kind (see
///       `strings.rs`'s module doc); not real parsed timestamp types, just
///       the raw ASN.1 string (compiles as
///       real Rust, no runtime wiring yet for actual date/time semantics).
///       A real BER/PER runtime would likely want tighter types (e.g.
///       `[u32]` arcs for OID, an actual date/time type here); revisit then.
std::string RustBackend::native_builtin_type(ast::BuiltinType bt) const {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Boolean:          return "asn1cpp_wire::boolean::Boolean";
    case BT::Real:             return "asn1cpp_wire::real::Real";
    case BT::Null:             return "asn1cpp_wire::null::Null";
    case BT::BitString:        return "asn1cpp_wire::bit_string::BitString";
    case BT::OctetString:      return "asn1cpp_wire::octet_string::OctetString";
    case BT::ObjectIdentifier: return "asn1cpp_wire::oid::ObjectIdentifier";
    case BT::RelativeOid:      return "asn1cpp_wire::relative_oid::RelativeOid";
    case BT::Utf8String:       return "asn1cpp_wire::strings::Utf8String";
    case BT::NumericString:    return "asn1cpp_wire::strings::NumericString";
    case BT::PrintableString:  return "asn1cpp_wire::strings::PrintableString";
    case BT::T61String:        return "asn1cpp_wire::strings::T61String";
    case BT::Ia5String:        return "asn1cpp_wire::strings::Ia5String";
    case BT::VisibleString:    return "asn1cpp_wire::strings::VisibleString";
    case BT::GeneralString:    return "asn1cpp_wire::strings::GeneralString";
    case BT::GraphicString:    return "asn1cpp_wire::strings::GraphicString";
    case BT::UniversalString:  return "asn1cpp_wire::strings::UniversalString";
    case BT::BmpString:        return "asn1cpp_wire::strings::BmpString";
    case BT::VideotexString:   return "asn1cpp_wire::strings::VideotexString";
    case BT::ObjectDescriptor: return "asn1cpp_wire::strings::ObjectDescriptor";
    case BT::UtcTime:          return "asn1cpp_wire::strings::UtcTime";
    case BT::GeneralizedTime:  return "asn1cpp_wire::strings::GeneralizedTime";
    case BT::Any:              return "asn1cpp_wire::any::Any";
    default:                   return "Vec<u8>";  // Integer/Enumerated: unreachable here
    }
}

/// @brief Emits the `AsMemberRef::BER_FRAMING` override for a primitive or
///        ENUMERATED type assignment whose own tag is not its builtin's
///        universal tag (X.680 §31.2). A SEQUENCE OF / SET OF element has no
///        member row to carry that tag, so the element type itself must
///        say how its TLV is framed: IMPLICIT replaces the universal tag
///        (X.690 §8.14.3), EXPLICIT wraps it (X.690 §8.14.2).
/// @param spec The type assignment's tag decision.
/// @return One `const BER_FRAMING` line, or "" when the default
///         `BerTagging::Delegate` (the builtin's own tag) is right.
std::string RustBackend::ber_framing_const(const TaggedTypeSpec& spec) const {
    if (!spec.tag || (!spec.is_explicit && spec.tag->cls == ast::TagClass::Universal)) return "";
    return std::format("    const BER_FRAMING: asn1cpp_wire::spec::choice::BerTagging = asn1cpp_wire::spec::choice::BerTagging::{}({});\n",
                       spec.is_explicit ? "Explicit" : "Implicit", format_tag_literal(*spec.tag));
}

/// @brief `BerTagging::OfType` row framing that points at a referenced type
///        assignment's own `AsMemberRef::BER_FRAMING`.
/// @param type_path Rust path of the referenced type (a pure `pub type`
///        alias hop resolves to the same impl).
/// @return The framing expression for a member or alternative row.
/// @see X.680 §31.2 — the tag of a tagged type assignment belongs to the type.
static std::string of_type_framing(const std::string& type_path) {
    return std::format("asn1cpp_wire::spec::choice::BerTagging::OfType("
                       "&<{} as asn1cpp_wire::spec::object::AsMemberRef>::BER_FRAMING)", type_path);
}

/// @brief Format a resolved `TagSpec` as an `asn1cpp_wire::ber::tag::Tag` struct
///        literal. Mirrors `CppBackend::format_tag_literal`
///        — same input (backend-agnostic `TagSpec`), Rust struct-literal
///        syntax instead of C++'s. `Tag`/`TagClass` are both `pub` with
///        `pub` fields (`rust-runtime/wire/src/tag.rs`), constructible this
///        way from outside the crate; no named constant lookup needed
///        (unlike a covered builtin member's *natural* tag, which asks
///        the member's own Rust type via `type_tag::TypeTag` instead —
///        `emit_sequence_definition`'s own doc) since this covers arbitrary
///        class/number/
///        constructed combinations, including EXPLICIT/IMPLICIT/auto-tag
///        context tags that have no named constant.
std::string RustBackend::format_tag_literal(const TypeTagSpec& tag_spec) const {
    static constexpr const char* kTagClassLiterals[4] = {
        "asn1cpp_wire::ber::tag::TagClass::Universal", "asn1cpp_wire::ber::tag::TagClass::Application",
        "asn1cpp_wire::ber::tag::TagClass::Private", "asn1cpp_wire::ber::tag::TagClass::Context"};
    return std::format("asn1cpp_wire::ber::tag::Tag {{ class: {}, number: {}, constructed: {} }}",
                        kTagClassLiterals[tag_class_index(tag_spec.cls)], tag_spec.number,
                        tag_spec.constructed ? "true" : "false");
}

/// @brief Emit the definition half of a builtin-alias newtype (see
///        `emit_builtin_alias_declaration` for why it's a newtype): its
///        SIZE `Constraints` table when sizeable, `TypeTag`, and the
///        `AsMemberRef` impl that unwraps it to the wrapped primitive's
///        `PrimitiveRef` for every codec walker.
/// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
/// @param os   Output stream to write to.
/// @note No codec logic is emitted. The alias's own ASN.1 name and X.693
///       §21 BASE64/UTF8 override — the two things the bare wrapped type
///       can't carry per-alias — live on `AsMemberRef`
///       (`own_element_xer_name`/`XER_INSTRUCTION`).
/// @see X.680 §16.1 (type assignment), X.693 §21 (ENCODING-CONTROL).
void RustBackend::emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;
    using BT = ast::BuiltinType;
    bool is_bits = spec.builtin_type == BT::BitString;
    bool is_octets = spec.builtin_type == BT::OctetString;
    // SIZE-able kinds (X.691 §16/§17/§26.5): OCTET STRING/BIT STRING plus
    // every character-string kind, wide-char included — validate() is
    // pure byte-length checking either way, no PER-specific alphabet
    // concern. Table-driven throughout — constraints are always data,
    // never generated code — and always wired regardless of
    // has_size_constraint (flags: 0 when
    // unconstrained) so validate() and, when covered, PerValue both read
    // the exact same static — no generated per-type bounds-check function.
    bool sizeable = is_bits || is_octets || is_sizeable_string_kind(spec.builtin_type);
    // No recase — see emit_enumerated_definition's matching note.
    std::string cname = tname + "_CONSTRAINTS";
    if (sizeable) {
        int flags = (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
            | (spec.has_size_constraint && spec.extensible ? asn1::Constraints::EXTENSIBLE : 0)
            | (spec.named_bits ? asn1::Constraints::NAMED_BITS : 0);
        int64_t size_upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
            "size_range_bits: {}, size_lower: {}, size_upper: {}, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,\n"
            "}};\n\n",
            cname, flags, spec.size_range_bits, spec.size_lower, size_upper);
    } else if (spec.builtin_type == BT::Real) {
        // Always emitted so a member of this alias can reference it.
        emit_real_constraints(os, cname, spec.real_range);
    } else {
        // No constraint kind applies, but a SEQUENCE OF / SET OF of this
        // alias names `{Alias}_CONSTRAINTS` as its element table.
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format("pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::UNCONSTRAINED;\n\n", cname);
    }


    // Lets this named builtin-alias type appear as a SEQUENCE OF/SET OF
    // element, or as a plain SEQUENCE/CHOICE member via `MemberRef::
    // Primitive` — `self.0` reaches the
    // wrapped value `PrimitiveRef`'s closed 26-variant set actually
    // needs; the alias itself is never one of them.
    {
        std::string variant = primitive_variant(native_builtin_type(spec.builtin_type));
        os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", tname);
        os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRef::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRef::{}(&self.0))\n", variant);
        os << "    }\n\n";
        os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << std::format("        asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{}(&mut self.0))\n", variant);
        os << "    }\n\n";
        os << std::format("    fn own_element_xer_name(&self) -> &'static str {{ \"{}\" }}\n", spec.xer_name);
        if (spec.xer_encoding == ast::XerEncoding::Base64) {
            os << "    const XER_INSTRUCTION: asn1cpp_wire::spec::object::XerInstruction = asn1cpp_wire::spec::object::XerInstruction::Base64;\n";
        } else if (spec.xer_encoding == ast::XerEncoding::Utf8) {
            os << "    const XER_INSTRUCTION: asn1cpp_wire::spec::object::XerInstruction = asn1cpp_wire::spec::object::XerInstruction::Utf8;\n";
        }
        os << ber_framing_const(spec);
        os << "}\n\n";
    }
}

/// @brief Emit a Rust default-value accessor function for a SEQUENCE/SET
///        member's DEFAULT value (X.680 §25.1).
/// @param spec        Resolved, backend-agnostic decision (see DefaultValueSpec).
/// @param type_name   Storage type computed by Generator::native_member_type_for().
/// @param parent_name Enclosing SEQUENCE/SET type identifier.
/// @param member_name Member identifier (already backend-dispatched — snake_case).
/// @param os          Output stream to write to.
/// @note `type_name` is only genuinely backend-dispatched for Kind::Int
///       (via native_int_type) and Kind::EnumRef (via type_name()) — both
///       reused here directly. For Kind::Bool/Kind::String,
///       Generator::native_member_type_for() hardcodes a C++ runtime wrapper type
///       ("asn1::Boolean"/"asn1::Ia5String" etc.), so those two cases ignore
///       it and use "bool"/"String" instead.
void RustBackend::emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                                       const std::string& parent_name, const std::string& member_name,
                                       TypeOutputSession& session) const {
    std::ostream& os = session.buffer(definition_extension());
    using Kind = DefaultValueSpec::Kind;
    std::string rust_type, literal;
    switch (spec.kind) {
    case Kind::Bool:
        rust_type = "asn1cpp_wire::boolean::Boolean";
        literal = spec.bool_val ? "asn1cpp_wire::boolean::Boolean(true)" : "asn1cpp_wire::boolean::Boolean(false)";
        break;
    case Kind::Int: {
        rust_type = type_name;
        // Inline member: type_name is native_int_type()'s own text, which
        // already distinguishes the one bare-storage exception
        // (ArbitraryInteger's inner Vec<u8> can't take an int literal
        // either way — DEFAULT on that storage kind isn't really
        // supported, see rust-runtime/wire/src/integer.rs's own doc).
        // Named alias (e.g. `Int1 ::= INTEGER; member Int1 DEFAULT 3`):
        // type_name is the alias's own identifier, carrying no such
        // textual signal. Unlike the inline case, its inner field is
        // itself a newtype (`struct Int1(pub asn1cpp_wire::integer::
        // Integer)`, never a bare i64/u64/i128 — emit_integer_declaration
        // always wraps through native_int_type()) — needs double
        // construction: `Int1(Integer(3))`. Only ARBITRARY's Vec<u8>
        // payload can't take an int literal either way — so
        // spec.int_storage_kind (Generator::classify_integer_storage on
        // the member) decides.
        if (type_name.starts_with("asn1cpp_wire::integer::")) {
            literal = type_name.ends_with("ArbitraryInteger")
                ? std::format("{}", spec.int_val)
                : std::format("{}({})", type_name, spec.int_val);
        } else if (spec.int_storage_kind == IntStorageKind::ARBITRARY) {
            literal = std::format("{}", spec.int_val);
        } else {
            literal = std::format("{}({}({}))", type_name,
                                   native_int_type(spec.int_storage_kind), spec.int_val);
        }
        break;
    }
    case Kind::String:
        rust_type = "asn1cpp_wire::strings::Ia5String";
        literal = std::format("asn1cpp_wire::strings::Ia5String(\"{}\".to_string())", escape_string_literal(spec.string_val));
        break;
    case Kind::EnumRef:
        rust_type = type_name;
        literal = std::format("{}::{}", type_name, variant_name(*this, spec.enum_name));
        break;
    case Kind::Real: {
        // Inline member: type_name is the runtime's Real itself. Named alias
        // (`Temp ::= REAL`): a newtype around it, `Temp(Real(..))`.
        std::string f = rust_f64_literal(spec.real_val);
        rust_type = type_name;
        literal = type_name == "asn1cpp_wire::real::Real"
            ? std::format("asn1cpp_wire::real::Real::new({})", f)
            : std::format("{}(asn1cpp_wire::real::Real::new({}))", type_name, f);
        break;
    }
    case Kind::None:
    default:
        return;
    }
    std::string fname = escape(to_snake_case(parent_name) + "_" + member_name + "_default");
    os << std::format("pub fn {}() -> {} {{\n    {}\n}}\n\n", fname, rust_type, literal);
}

/// @brief Name of a contained field's `ContainedSpec` static, from the
///        field's descriptor base name (TaggedMemberSpec::contained_base).
static std::string contained_spec_ident(const std::string& base) {
    return to_screaming_snake_case(base) + "_CONTAINED";
}

/// @brief Emit a Rust bounds-check function for an inline-constrained
///        SEQUENCE/CHOICE member — INTEGER value range or SIZE-able-
///        primitive SIZE constraint.
/// @param spec Resolved, backend-agnostic decision (see MemberTypeDescriptorSpec).
/// @param os   Output stream to write to.
/// @note FROM-alphabet-only members and members whose only constraint is a
///       non-default XER encoding produce no Rust output — same "no runtime
///       wiring yet" scope as emit_builtin_alias_definition. Builds its own
///       constant-name base from `spec.parent_cname`/`spec.mname` via
///       member_descriptor_base_name() — its own naming convention,
///       independent of whatever text CppBackend's own implementation
///       of that method produces.
void RustBackend::emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const {
    std::ostream& os = session.buffer(definition_extension());
    using Kind = MemberTypeDescriptorSpec::Kind;
    std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(member_descriptor_base_name(spec.parent_cname, spec.mname)));
    if (spec.contained) {
        // Contained field (X.682 §11): its `ContainedSpec` row; the inner
        // type is the field's own `Containing<T>` parameter.
        const auto& f = *spec.contained;
        auto enc = [](sema::ContentsEncoding e) {
            switch (e) {
            case sema::ContentsEncoding::Ber:          return "Ber";
            case sema::ContentsEncoding::Cer:          return "Cer";
            case sema::ContentsEncoding::Der:          return "Der";
            case sema::ContentsEncoding::PerAligned:   return "PerAligned";
            case sema::ContentsEncoding::PerUnaligned: return "PerUnaligned";
            default:                                   return "Outer";
            }
        };
        auto text = [](sema::ContainedText t) {
            switch (t) {
            case sema::ContainedText::Inline:    return "Inline";
            case sema::ContainedText::InlineRaw: return "InlineRaw";
            default:                             return "Hex";
            }
        };
        os << std::format(
            "pub static {}: asn1cpp_wire::containing::ContainedSpec = asn1cpp_wire::containing::ContainedSpec {{ "
            "encoding: asn1cpp_wire::containing::ContainedEncoding::{}, eager: {}, decoder: \"{}\", when_member: {}, "
            "when_value: {}, fail_on_error: {}, xer: asn1cpp_wire::containing::ContainedText::{}, "
            "jer: asn1cpp_wire::containing::ContainedText::{}, builtin: {} }};\n\n",
            contained_spec_ident(member_descriptor_base_name(spec.parent_cname, spec.mname)), enc(f.encoding),
            f.decode == sema::ContainedDecode::Eager ? "true" : "false", f.decoder, spec.contained_when_index,
            f.when ? f.when->value : 0, f.on_error == sema::ContainedOnError::Fail ? "true" : "false",
            text(f.xer), text(f.jer), sema::builtin_decoder_index(f.decoder));
    }
    if (spec.kind == Kind::Integer) {
        // Plain `static` data, not a generated per-member function — all
        // constraints are table based, never in code, so a parser/tool can
        // read the bound straight off this table without executing
        // anything. Delta
        // convention, EXTENSIBLE handling, and the saturating i64 clamp
        // for U64 storage all live in `constraints::validate_s64`/
        // `validate_u64` (rust-runtime/wire/src/constraints.rs) — the only
        // code, identical for every member. Only INT_S64/INT_U64 storage
        // gets a table — INT_I128/INT_ARBITRARY are skipped (the member's
        // MemberDescriptor.validate is `None`), matching or exceeding the
        // C++ side's own correctness rather than replicating its latent
        // I128/ARBITRARY static_cast bug (Validate.hpp) in Rust too.
        // One combined table (BER + PER fields,
        // asn1cpp_wire::constraints::Constraints) serves both legs: BER's
        // `constraints::validate_s64`/`validate_u64` (rust-runtime/wire)
        // read flags/lower_bound/upper_bound/lower_u64/upper_u64 only;
        // PER's `integer::encode_int`/`uinteger::encode_uint`
        // (rust-runtime/wire/src/per) additionally read range_bits, and are the
        // only reason a member of this shape needs its row's `constraints`
        // reference at all — a shared native type like `i64` can't carry
        // per-declaration PER shape via its own type-level trait impl,
        // since two different members of that same native type can have
        // different range constraints. Emitted as `asn1cpp_wire::
        // constraints::Constraints` text — the same type both the BER/XER
        // and PER legs read, one shared module.
        if (spec.storage_kind == IntStorageKind::S64) {
            // hi_is_large's upper bound may exceed i64::MAX (X.691 §10.5.6,
            // e.g. UINT64_MAX) and isn't exactly representable as an i64
            // bound — treated as semi-constrained (lower-bound-only check)
            // rather than storing an incorrect upper bound.
            bool semi = spec.semi_constrained || spec.hi_is_large;
            int flags = (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0) |
                        (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED);
            os << std::format(
                "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
                "    flags: {}, range_bits: {}, lower_bound: {}, upper_bound: {}, lower_u64: 0, upper_u64: 0, "
                "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,\n"
                "}};\n\n",
                cname, flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64);
        } else if (spec.storage_kind == IntStorageKind::U64) {
            int flags = (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0) |
                        (spec.semi_constrained ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED);
            os << std::format(
                "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
                "    flags: {}, range_bits: {}, lower_bound: 0, upper_bound: 0, lower_u64: {}u64, upper_u64: {}u64, "
                "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,\n"
                "}};\n\n",
                cname, flags, std::max(spec.range_bits, 0), spec.lower_u64, spec.upper_u64);
        }
        return;
    }
    if (spec.kind == Kind::Real) {
        emit_real_constraints(os, cname, spec.real_range);
        return;
    }
    // Always emitted (not gated on has_size_constraint) whenever this
    // function runs at all — this spec can also get built for a
    // FROM-alphabet-only or custom-XER-only member with no SIZE constraint
    // (Generator::build_member_type_descriptor_spec's Sizeable branch:
    // `if (sr || !alphabet.empty() || needs_xer)`), and RustBackend's own
    // member-row loop only has `tdref` being non-empty to tell
    // whether *some* spec was built for this member — not whether the
    // SIZE constraint within it is real. Keeping this table unconditional
    // (flags=0 when unconstrained, same as `Constraints::default()`) keeps
    // that one signal reliable for every Sizeable member uniformly,
    // matching the C++ side's own "always reference a Constraints value,
    // flags=0 makes it a no-op" pattern (Validate.hpp) — no second gate
    // needed, and `validate_size` already treats a missing
    // SIZE_CONSTRAINED bit as always-valid.
    // SIZE_CONSTRAINED means "size_lower..size_upper is a finite range"
    // (Constraints.hpp), the same bit C++ emits: a semi-constrained
    // SIZE(n..MAX) leaves it clear and PER encodes its length as an
    // unconstrained length determinant (X.691 §11.9.4.2).
    int flags = (spec.size_bounded ? asn1::Constraints::SIZE_CONSTRAINED : 0)
        | (spec.has_size_constraint && spec.extensible ? asn1::Constraints::EXTENSIBLE : 0)
        | (spec.named_bits ? asn1::Constraints::NAMED_BITS : 0);
    int64_t size_upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
    // X.680 §51.4 PermittedAlphabet — `spec.alphabet` is
    // the resolved, sorted, deduplicated permitted-character set
    // (`Generator::extract_from_alphabet`); emitted as a plain 256-entry
    // lookup table (data, not code, same as the Constraints table above),
    // `encode_table[byte] = index in alphabet` or `0xFFFF` if
    // `byte` isn't permitted. `constraints::validate_alphabet`/
    // `validate_string` (rust-runtime/wire/src/constraints.rs) are the only
    // code, identical for every alphabet-constrained member.
    std::string encode_table_expr = "None";
    std::string alphabet_expr = "None";
    int alphabet_bits = 0;
    if (!spec.alphabet.empty()) {
        alphabet_bits = Backend::alphabet_bits_for(static_cast<int>(spec.alphabet.size()));
        std::string enc_ident = std::format("{}_ENC", to_screaming_snake_case(member_descriptor_base_name(spec.parent_cname, spec.mname)));
        std::array<uint16_t, 256> table;
        table.fill(0xFFFFu);
        for (size_t i = 0; i < spec.alphabet.size(); ++i) table[spec.alphabet[i]] = static_cast<uint16_t>(i);
        os << std::format("static {}: [u16; 256] = [\n", enc_ident);
        for (int i = 0; i < 256; ++i) {
            if (i % 16 == 0) os << "    ";
            os << table[i];
            os << (i < 255 ? "," : "");
            os << (i % 16 == 15 ? "\n" : " ");
        }
        os << "];\n\n";
        encode_table_expr = std::format("Some(&{})", enc_ident);
        // Decode-direction counterpart (X.691 §26.5.4/§26.5.7 decode:
        // ordinal -> character) — `per::strings::decode_string`'s own
        // table, `spec.alphabet` already sorted ascending by
        // `extract_from_alphabet` (its own doc).
        std::string alpha_ident = std::format("{}_ALPHA", to_screaming_snake_case(member_descriptor_base_name(spec.parent_cname, spec.mname)));
        os << std::format("static {}: [u8; {}] = [", alpha_ident, spec.alphabet.size());
        for (size_t i = 0; i < spec.alphabet.size(); ++i)
            os << std::format("{}{}", spec.alphabet[i], i + 1 < spec.alphabet.size() ? ", " : "");
        os << "];\n\n";
        alphabet_expr = std::format("Some(&{})", alpha_ident);
    }
    // One combined table serves both legs: BER's `constraints::
    // validate_size`/`validate_alphabet` (rust-runtime/wire) read
    // flags/size_lower/size_upper/encode_table; PER's `strings::
    // encode_string`/`decode_string` (rust-runtime/wire/src/per)
    // additionally read size_range_bits and, for a FROM-constrained
    // member, alphabet_bits/encode_table/alphabet/alphabet_size (X.691
    // §26.5.4/§26.5.7 remapping).
    os << std::format(
        "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
        "    flags: {}, range_bits: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
        "size_range_bits: {}, size_lower: {}, size_upper: {}, encode_table: {}, "
        "alphabet_bits: {}, alphabet: {}, alphabet_size: {}, element: None, real_lower: 0.0, real_upper: 0.0,\n"
        "}};\n\n",
        cname, flags, spec.size_range_bits, spec.size_lower, size_upper, encode_table_expr,
        alphabet_bits, alphabet_expr, spec.alphabet.size());
}

/// @brief Emit the definition half of a named SEQUENCE OF/SET OF type: its
///        own SIZE `Constraints` table, the reflective `Asn1SeqOf`/
///        `AsMemberRef` impls every codec walker dispatches through, and the
///        `Asn1Pdu` root marker carrying that table as `PDU_CONSTRAINTS`.
/// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
/// @param os   Output stream to write to.
/// @note No codec logic is emitted for the type itself: BER/XER/JER/PER reach
///       it through `<codec>::object` (`encode_pdu`/`decode_pdu` at top
///       level, `MemberRef::SeqOf` as a member). The per-element X.693 §12
///       name / §21 BASE64-UTF8 instruction comes from the element type's
///       own `AsMemberRef::own_element_xer_name`/`XER_INSTRUCTION`.
/// @see X.680 §25/§26 (SEQUENCE OF/SET OF), X.691 §19/§20 (PER count).
void RustBackend::emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const {
    // Plain `static` data, not a generated per-type function
    // — always emitted, real bounds or not: every generated SEQUENCE
    // OF/SET OF type gets one, including an anonymous inline member's
    // synthetic promoted type (`Generator::emit_seq_of_definition` runs
    // identically for both — see this pairing's own doc), so the
    // containing SEQUENCE's member-row loop (`emit_sequence_definition`)
    // can always find `{TYPE}_CONSTRAINTS` by the same deterministic name
    // it already derives for the field type, no extra signal needed. A
    // semi-constrained SIZE (`size_upper` absent) leaves SIZE_CONSTRAINED
    // clear: the bit means a finite range (X.691 §20.6 constrained
    // count), as in the C++ table.
    // No recase — see emit_enumerated_definition's matching note.
    std::string cname = std::format("{}_CONSTRAINTS", spec.type_name);
    int flags = (spec.size_upper ? asn1::Constraints::SIZE_CONSTRAINED : 0)
        | (spec.has_size_constraint && spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    int64_t size_upper = spec.size_upper.value_or(std::numeric_limits<int64_t>::max());
    // `pub`, unlike the member-inline Constraints tables above — a
    // synthetic promoted type's own table is referenced cross-module by
    // the containing SEQUENCE's row-loop (an inline member never has this
    // type as its field type directly, only the generic SeqOf<T>/SetOf<T>
    // wrapper — see that reference's own doc).
    // One combined table serves both legs — the collection's own SIZE
    // constraint (X.691 §19/§20 combined with §10.9), read by a covered
    // SEQUENCE OF/SET OF member's row (emit_sequence_definition) via this
    // type's cross-module path, same
    // "always wire, real bounds or not" convention as everywhere else.
    // The element's own constraint table, when it has one: the element's
    // `emit_member_type_descriptor` output (MemberOwnTable — a bare base
    // name, empty when the element has no own table) sits in this same
    // module, so the collection's constraint can point at it (X.691
    // §19/§20 — each element is encoded against `element`, the count
    // against this table's own SIZE fields).
    std::string element_expr = "None";
    if (!spec.elem_ref.empty()) {
        // Two distinct shapes, per `format_type_descriptor_ref`'s own doc:
        // a bare base name (MemberOwnTable — an ad hoc same-module table,
        // built via `member_descriptor_base_name`'s SCREAMING_SNAKE_CASE
        // convention) or a `crate::{name}::{name}` path to another
        // top-level type's own `{name}_CONSTRAINTS` static (FreeStanding —
        // e.g. a SEQUENCE OF element promoted out to its own type),
        // which already carries its real (unscreamed)
        // name and must not be recased.
        if (spec.elem_ref.find("::") != std::string::npos) {
            element_expr = std::format("Some(&{}_CONSTRAINTS)", spec.elem_ref);
        } else {
            element_expr = std::format("Some(&{}_CONSTRAINTS)",
                to_screaming_snake_case(spec.elem_ref));
        }
    }
    os << "#[allow(non_upper_case_globals)]\n";
    os << std::format(
        "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
        "    flags: {}, range_bits: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
        "size_range_bits: {}, size_lower: {}, size_upper: {}, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: {}, real_lower: 0.0, real_upper: 0.0,\n"
        "}};\n\n",
        cname, flags, spec.range_bits, spec.size_lower, size_upper, element_expr);

    std::string natural_tag = std::format("asn1cpp_wire::spec::sequence::{}", spec.is_set_of ? "SET_TAG" : "SEQUENCE_TAG");
    // Honor a top-level [n] IMPLICIT/EXPLICIT tag on this type assignment
    // itself (X.690 §8.14) — same fix emit_sequence_definition already has.
    std::string tag_expr = spec.tag ? format_tag_literal(*spec.tag) : natural_tag;


    // Whole-document root marker (`spec::object::Asn1Pdu`), carrying
    // this type's own SIZE table for PER count encoding (X.691 §19/§20).
    os << std::format(
        "impl asn1cpp_wire::spec::object::Asn1Pdu for {} {{\n"
        "    const PDU_CONSTRAINTS: &'static asn1cpp_wire::constraints::Constraints = &{};\n"
        "}}\n\n",
        spec.type_name, cname);

    // Reflective `Asn1SeqOf` impl — the
    // element type's own `AsMemberRef` impl (emitted unconditionally
    // alongside every builtin/SEQUENCE/SET/CHOICE/ENUMERATED type) is all
    // this needs; no codec method here at all.
    os << std::format("impl asn1cpp_wire::spec::object::Asn1SeqOf for {} {{\n", spec.type_name);
    // `tag_expr`, not the bare `natural_tag` — a named top-level
    // SEQUENCE OF/SET OF type's own `[n]` override (`spec.tag`) must
    // apply here too, or this returns the wrong, un-overridden tag:
    // `ber_natural_tag` above already uses
    // `tag_expr` for the exact same reason, and the two must agree —
    // `ber::object`'s SeqOf-arm `Delegate` fallback (the one case this
    // method is still genuinely needed for: a SEQUENCE OF/SET OF
    // *element* that's itself a further-nested SEQUENCE OF/SET OF, which
    // carries no row of its own to read a literal tag from) calls this
    // method expecting the type's real natural tag, override included.
    os << std::format("    fn natural_tag(&self) -> asn1cpp_wire::Tag {{ {} }}\n", tag_expr);
    // This type's own X.693 §9.3 wrapper name, used when it appears
    // nested as another collection's element (`natural_xer_name_of`'s
    // own doc) -- `spec.xer_name` is this type's real ASN.1 name when it
    // has one, or the `xmlasn1typename` `"SEQUENCE_OF"`/`"SET_OF"` an
    // anonymous promoted collection gets (`Generator::synthetic->
    // xer_name`, X.680 Table 4) -- never the inline-member
    // form `ber::sequence::SeqOf<T>`/`SetOf<T>` use, since this type is
    // always independently named or promoted, never an inline member.
    os << std::format("    fn own_xer_name(&self) -> &'static str {{ \"{}\" }}\n", spec.xer_name);
    os << "    fn len(&self) -> usize { self.0.len() }\n";
    os << "    fn get(&self, index: usize) -> asn1cpp_wire::spec::object::MemberRef<'_> { self.0[index].as_member_ref() }\n";
    os << "    fn push_default_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
    os << "        self.0.push(Default::default());\n";
    os << "        self.0.last_mut().unwrap().as_member_ref_mut()\n";
    os << "    }\n";
    os << "    fn reserve(&mut self, additional: usize) {\n";
    os << "        self.0.reserve(additional);\n";
    os << "    }\n";
    // `self.0[index]`'s own un-unwrapped `AsMemberRef::
    // own_element_xer_name()`, not anything read back off `get(index)`'s
    // already-unwrapped `MemberRef` — an aliased element (e.g. a named
    // INTEGER alias, X.680 §19) needs its own real declared name, which
    // `get(index)`'s unwrap to a bare `PrimitiveRef` has already lost.
    os << "    fn elem_natural_xer_name(&self, index: usize) -> &'static str { self.0[index].own_element_xer_name() }\n";
    os << std::format(
        "    fn elem_xer_instruction(&self) -> asn1cpp_wire::spec::object::XerInstruction {{ <{} as asn1cpp_wire::spec::object::AsMemberRef>::XER_INSTRUCTION }}\n",
        spec.elem_type);
    os << std::format(
        "    fn elem_ber_framing(&self) -> asn1cpp_wire::spec::choice::BerTagging {{ <{} as asn1cpp_wire::spec::object::AsMemberRef>::BER_FRAMING }}\n",
        spec.elem_type);
    if (spec.elem_xer_name) {
        os << std::format("    fn elem_xer_name(&self) -> ::std::option::Option<&'static str> {{ Some(\"{}\") }}\n", *spec.elem_xer_name);
    }
    os << "}\n\n";

    // Lets this named SEQUENCE OF/SET OF type itself appear as a member
    // elsewhere (another SEQUENCE/CHOICE referencing it by name) or as an
    // element of a further-nested SEQUENCE OF/SET OF.
    os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", spec.type_name);
    os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
    os << "        asn1cpp_wire::spec::object::MemberRef::SeqOf(self)\n";
    os << "    }\n\n";
    os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
    os << "        asn1cpp_wire::spec::object::MemberRefMut::SeqOf(self)\n";
    os << "    }\n\n";
    os << "    fn own_element_xer_name(&self) -> &'static str {\n";
    os << std::format("        <Self as asn1cpp_wire::spec::object::Asn1SeqOf>::own_xer_name(self)\n");
    os << "    }\n";
    os << "}\n\n";
}

/// @brief Is `mtype` a `Vec<T>` (T != u8) reference — a type with no
///        reflective trait impls at all? Pure string check on the resolved Rust
///        type, order-independent (no registration/lookup-by-declaration-
///        name needed): a named top-level SEQUENCE OF/SET OF alias
///        (`m.mtype == "MySeqOf"`, e.g.) never has this shape at all —
///        `emit_seq_of_declaration` gives it a real newtype with its own
///        `Asn1SeqOf`/`AsMemberRef` impls, referenced by name, not resolved-through
///        `"Vec<...>"` text — but an anonymous inline
///        SEQUENCE OF/SET OF member (whose type Generator resolves
///        directly to the raw `"Vec<i64>"` text, never through a synthetic
///        alias name, even though it also generates one as a side artifact
///        for the size-check function) is only catchable this way. Only
///        `Vec<u8>` is excluded — OCTET STRING's own real impl.
static bool rust_mtype_is_unusable_vec(const std::string& mtype) {
    return mtype.rfind("Vec<", 0) == 0 && mtype != "Vec<u8>";
}

/// @brief A CHOICE alternative's payload type. An inline SEQUENCE OF /
///        SET OF alternative (`rust_mtype_is_unusable_vec`: Generator gives
///        it the placeholder `"Vec<...>"` text, identical for both kinds)
///        uses its promoted synthetic type, `synth_path`. That type carries
///        what the text can't: SEQUENCE OF vs SET OF identity
///        (`Asn1SeqOf::natural_tag`, which the PER encoder needs to sort a
///        SET OF per X.691 §21.1 and BER needs for an untagged alternative's
///        tag) and the collection's own `_CONSTRAINTS`. Every other `mtype`
///        passes through unchanged.
/// @param mtype      The alternative's Generator-provided type text.
/// @param synth_path Crate path of the alternative's promoted synthetic
///                   type (`crate::{Synth}::{Synth}`).
static std::string rust_alt_payload_type(const std::string& mtype, const std::string& synth_path) {
    return rust_mtype_is_unusable_vec(mtype) ? synth_path : mtype;
}

/// @brief The real nested-collection element type for a SEQUENCE OF/SET OF
///        member, built directly from `ElemShape` (Backend.hpp) — never
///        from `m.mtype` text, which `native_member_type_for`'s own
///        is_seq_of/is_set_of branches always flatten to the placeholder
///        `"Vec<...>"` shape regardless of nesting depth or SEQUENCE-OF-
///        vs-SET-OF kind at each level (the same placeholder
///        `rust_alt_payload_type` above replaces for a CHOICE alternative —
///        text alone can't tell them apart, which is exactly why
///        `ElemShape` exists; see its own doc).
/// @param shape This level's element shape — SeqOfKind::None is the base
///              case (leaf: `shape.leaf_native_type`, already correct,
///              never itself wrapped in a collection type — no text to
///              strip at any level).
static std::string rust_wrap_elem_shape(const ElemShape& shape) {
    if (shape.kind == SeqOfKind::None) return shape.leaf_native_type;
    std::string inner = shape.nested ? rust_wrap_elem_shape(*shape.nested) : shape.leaf_native_type;
    return std::format("asn1cpp_wire::ber::sequence::{}<{}>",
                        shape.kind == SeqOfKind::SeqOf ? "SeqOf" : "SetOf", inner);
}

static std::string rust_seqof_elem_mtype(const SequenceMemberSpec& m) {
    return rust_wrap_elem_shape(m.elem_shape);
}

/// @brief Recursive coverage check for a SEQUENCE OF/SET OF element's
///        shape (`ElemShape`, Backend.hpp) — real (covered) all the way
///        down to the leaf, or stubbed at the first genuinely uncovered
///        one. A nested collection element is covered iff its own element
///        is, to unbounded depth; a composite (TypeRef) leaf is always
///        real (same reasoning as a plain scalar composite reference —
///        `sequence_member_covered`'s own doc); a builtin leaf routes
///        through the same `rust_tag_for_builtin_or_alias` the member-level
///        path uses (the `mtype` parameter is only ever consulted there for
///        a TypeRef alias, which a builtin leaf never is, so an empty
///        placeholder is safe).
static bool element_shape_covered(const ElemShape& shape) {
    if (shape.kind != SeqOfKind::None)
        return shape.nested && element_shape_covered(*shape.nested);
    if (shape.builtin)
        return rust_tag_for_builtin_or_alias(shape.builtin, shape.storage_kind, "") != nullptr;
    return true;
}

/// @brief A SEQUENCE/SET member's own Rust field type, for a SEQUENCE
///        OF/SET OF member specifically — `SeqOf<ElemType>`/`SetOf<ElemType>`
///        (`rust-runtime/wire/src/sequence.rs`) instead of a raw
///        `Vec<ElemType>`, which has no reflective trait impls of its own
///        (coherence-blocked: neither the traits nor `Vec` are local to the
///        generated crate). Once the field itself implements `AsMemberRef`, the
///        member-table emission below needs no dedicated SeqOf-shaped
///        closures at all — it falls through to the same
///        Scalar/TaggedScalar/ExplicitScalar dispatch every other
///        composite member already uses. Every other member's `mtype`
///        passes through unchanged.
static std::string rust_seqof_member_field_type(const SequenceMemberSpec& m) {
    switch (m.seq_of_kind) {
    case SeqOfKind::SeqOf: return std::format("asn1cpp_wire::ber::sequence::SeqOf<{}>", rust_seqof_elem_mtype(m));
    case SeqOfKind::SetOf: return std::format("asn1cpp_wire::ber::sequence::SetOf<{}>", rust_seqof_elem_mtype(m));
    case SeqOfKind::None:  return m.mtype;
    }
    return m.mtype;
}

/// @brief Emit the Rust struct declaration for a SEQUENCE/SET type.
/// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
/// @param os   Output stream to write to.
/// @note `spec.members[i].mtype` is treated as an opaque, already-Rust-
///       shaped type name string, always a real `Generator::native_member_type_for()`
///       value under `--target=rust`. `ops`/`offset_expr` are C++-runtime-only
///       (per SequenceMemberSpec's own doc) and unused here; optional members
///       become `Option<T>` rather than C++'s `unique_ptr<T>`, Rust's
///       natural equivalent. `tdref`/`has_default_setter` are genuinely
///       backend-agnostic raw data, and are used.
/// @brief Is `m` a reference to a CHOICE type with no tag of its own?
///        Its BER encoding starts with the chosen alternative's tag
///        (X.690 §8.13), so presence of an OPTIONAL one is read from the
///        CHOICE's dispatch tags (`BerTagging::DelegateChoice`).
/// @param m  The member.
/// @return True for an untagged reference to a CHOICE type.
static bool is_untagged_choice_ref(const SequenceMemberSpec& m) {
    return !m.mbuiltin && !m.resolved_tag && m.ref_kind == TaggedMemberSpec::RefTargetKind::Other &&
           !m.ref_is_sequence_or_set && !m.ref_is_seq_of && !m.ref_builtin_alias;
}

/// @brief Does `m` get a real access closure (Scalar/TaggedScalar/
///        ExplicitScalar/SeqOf), or an `Unsupported` stub?
///        Every SEQUENCE/SET always gets a full table now regardless of the
///        answer (see `sequence::MemberAccess::Unsupported`'s doc,
///        rust-runtime/wire) — this only decides this one row's shape.
/// @note `mbuiltin` unset means the member's type is a TypeRef to
///       something else entirely — SEQUENCE/SET/CHOICE, ENUMERATED, or a
///       plain INTEGER subtype alias. Any such reference is always real:
///       the referenced type is guaranteed to implement `AsMemberRef`
///       regardless of processing order, so there's nothing to look up in
///       advance. Presence of an OPTIONAL member needs a tag to peek for:
///       an untagged CHOICE (X.680 §28) has none of its own, so its row
///       carries the CHOICE's alternative tags instead
///       (`is_untagged_choice_ref`, `BerTagging::DelegateChoice`). Any
///       other OPTIONAL reference without a tag stays `Unsupported` (a
///       per-record codec error). Every named
///       type — a top-level SEQUENCE OF/SET OF alias, an INTEGER of any
///       storage kind including ARBITRARY — gets its own real newtype with
///       real reflective trait impls (`emit_seq_of_declaration`,
///       `integer::ArbitraryInteger`), referenced by name, so there's no
///       remaining case here where a TypeRef reference is unsafe to treat
///       as real.
bool RustBackend::sequence_member_covered(const SequenceMemberSpec& m) const {
    // SEQUENCE OF/SET OF: covered iff the element's own shape is, to
    // unbounded nesting depth (element_shape_covered's own doc).
    if (m.seq_of_kind != SeqOfKind::None) return element_shape_covered(m.elem_shape);
    // ANY (X.208 legacy type) has no fixed tag of its own to drive the
    // ordinary Scalar/TaggedScalar/ExplicitScalar paths — Generator forces
    // EXPLICIT tagging on any tagged ANY member regardless of module tag
    // default (member_is_explicit, Generator.cpp), so that's the only shape
    // covered: a genuinely untagged `ANY` member has no tag to peek for
    // OPTIONAL detection or dispatch at all and stays a stub.
    if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any)
        return m.resolved_tag.has_value() && m.is_explicit;
    if (!m.mbuiltin)
        return !m.optional || m.resolved_tag.has_value() || is_untagged_choice_ref(m);
    return rust_tag_for_builtin_or_alias(m.mbuiltin, m.storage_kind, m.mtype) != nullptr;
}

/// @brief CHOICE alternative analogue of sequence_member_covered —
///        does `a` get a real access closure (vs an `Unsupported` stub)?
///        Only meaningful once `a` is already known to have a resolved
///        tag (`choice_alternative_has_tag`, checked separately) — a
///        row's own tag is what `decode_choice`'s linear tag scan uses to
///        even reach it at all, real or stub.
bool RustBackend::choice_alternative_covered(const ChoiceAlternativeSpec& a) const {
    // A SEQUENCE OF or SET OF alternative always covers here: its
    // payload is the promoted synthetic type at every emission site
    // (rust_alt_payload_type), so
    // the raw "Vec<T>" text rust_mtype_is_unusable_vec would otherwise flag
    // is never actually a problem for a CHOICE alternative.
    if (rust_mtype_is_unusable_vec(a.mtype)) return true;
    if (!a.mbuiltin) return true;
    return rust_tag_for_builtin_or_alias(a.mbuiltin, a.storage_kind, a.mtype) != nullptr;
}

/// @brief Does `a` have any resolved tag at all? Unlike a SEQUENCE member
///        (`sequence_member_covered`'s doc), a CHOICE alternative with
///        no tag can't even become an `Unsupported` stub row — `decode_choice`
///        needs a real `Tag` to know when to try a row at all, stub or not,
///        so an alternative failing this check gets no row whatsoever
///        (emit_choice_definition simply omits it from the generated
///        array — its Rust enum variant still exists, just unreachable via
///        the generated decode(), which never selects it). The one case this actually
///        excludes: an alternative whose own type is itself a genuinely
///        untagged CHOICE (X.680 §28, no AUTOMATIC TAGS, no fixed tag at
///        all) — CHOICE alternatives have no OPTIONAL concept to fall back
///        on the way a SEQUENCE member's presence-detection gap does.
bool RustBackend::choice_alternative_has_tag(const ChoiceAlternativeSpec& a) const {
    return a.resolved_tag.has_value();
}

void RustBackend::emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const {
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
    os << "#[allow(non_camel_case_types, non_snake_case)]\n";
    os << std::format("pub struct {} {{\n", spec.type_name);
    for (const auto& m : spec.members) {
        // A member whose class type cycles back to this enclosing type
        // needs `Box<T>` unconditionally (Rust gives a plain `T`/`Option<T>`
        // field no heap indirection at all, so a genuine ASN.1
        // self-referential/mutually-recursive type chain is an
        // infinite-size struct without it). A class-typed OPTIONAL member
        // that isn't on a cycle still gets boxed via `box_optional_member`
        // — see its doc on `SequenceMemberSpec` (Backend.hpp) for the
        // measured, size-driven reason.
        std::string mtype = rust_seqof_member_field_type(m);
        std::string ftype = m.member_type_in_cycle ? std::format("Box<{}>", mtype) : mtype;
        os << std::format("    /// ASN.1: `{}`\n", m.asn1_name);
        std::string field_type = ftype;
        if (m.optional) {
            field_type = m.box_optional_member ? std::format("::std::option::Option<Box<{}>>", ftype)
                                                : std::format("::std::option::Option<{}>", ftype);
        }
        os << std::format("    pub {}: {},\n", m.mname, field_type);
    }
    os << "}\n\n";
}

/// @brief Emit the definition half of a SEQUENCE/SET type: `new()`, the
///        member tables (`SequenceSpec` + getter/default/validate rows)
///        behind its reflective `Asn1Seq` impl, `TypeTag`/`AsMemberRef`,
///        and the `Asn1Pdu` root marker.
/// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
/// @param os   Output stream to write to.
/// @note Tables only — every codec reaches the type through its own
///       `<codec>::object` walker (`encode_pdu`/`decode_pdu` at top level).
/// @see X.680 §25 (SEQUENCE), §27 (SET).
void RustBackend::emit_sequence_definition(const SequenceSpec& spec, std::ostream& os) const {
    os << std::format("impl {} {{\n", spec.type_name);
    os << "    pub fn new() -> Self {\n";
    os << "        Self::default()\n";
    os << "    }\n";
    os << "}\n\n";

    // Table-driven, mirroring asn_MBR_/asn_SPC_ + the
    // generic SequenceBerHandler dispatch (runtime/src/BerCodec.cpp)
    // instead of a straight-line per-type encode()/decode() body. Every
    // SEQUENCE/SET with at least one member always gets a real descriptor
    // table + encode()/decode() now — a member whose type/tag/optionality
    // combination isn't (yet) representable gets an `Unsupported` stub row
    // instead of the whole type falling back to struct-only (see
    // `sequence::MemberAccess::Unsupported`'s doc, rust-runtime/wire, and
    // sequence_member_covered's doc for exactly which combinations
    // still need one).
    // mbuiltin is unset for TypeRef members (named INTEGER subtype aliases,
    // e.g. `MyByte ::= INTEGER (0..255)` used as a member type) — Generator
    // only populates it from the member's own AST node when that node
    // directly holds a builtin type (`std::get_if<ast::BuiltinType>`), not
    // for a reference that *resolves* to one — native_member_type_for's TypeRef branch
    // returns the alias's own type name ("MyByte"), never the resolved
    // native type, so a plain `mtype == "i64"` string check can never match
    // it — see sequence_member_covered's `!m.mbuiltin` branch.
    // `mbuiltin == Integer` only says the member *is* an INTEGER, not which
    // Rust storage type classify_integer_storage/native_int_type actually
    // picked for it (i64 default; u64/i128/ArbitraryInteger for wider
    // ranges — same IntStorageKind the C++ side also branches on).
    // Human-readable reason baked into an Unsupported row's codec error
    // message — best-effort diagnosability, not meant to be exhaustive.
    auto stub_reason = [](const SequenceMemberSpec& m) -> const char* {
        if (m.seq_of_kind != SeqOfKind::None) return "SEQUENCE OF/SET OF element type/tag/optionality combination not yet supported";
        if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) return "untagged ANY has no tag to detect presence";
        if (!m.mbuiltin) return "OPTIONAL member of an untagged type has no tag to detect presence";
        return "builtin type/storage combination not yet supported";
    };

        // Reflective `Asn1Seq` apparatus (see spec::object's own doc).
        // Emitted unconditionally for every
        // SEQUENCE/SET, member by member: each member's own type/tag/
        // optionality combination drives its own row (Primitive/
        // Enumerated/SeqOf/Choice/Composite/Base64), a not-yet-
        // representable member gets an `Unsupported` stub row (see
        // `stub_reason` above), never a whole-type fallback to a second
        // mechanism — there is only ever this one table-driven path.
        {
            std::string obj_members_ident = std::format("{}_MEMBERS", spec.type_name);
            std::string obj_spec_ident = std::format("{}_SPEC", spec.type_name);
            std::string getters_ident = std::format("{}_GETTERS", spec.type_name);
            std::string getters_mut_ident = std::format("{}_GETTERS_MUT", spec.type_name);
            std::string set_default_ident = std::format("{}_SET_DEFAULT", spec.type_name);
            std::string is_default_equal_ident = std::format("{}_IS_DEFAULT_EQUAL", spec.type_name);
            std::string validate_ident = std::format("{}_VALIDATE", spec.type_name);

            std::vector<std::string> meta_lines, getter_lines, getter_mut_lines,
                set_default_lines, is_default_equal_lines, validate_lines;

            // Per-member access kind: a
            // direct builtin leaf (except ENUMERATED), or a named INTEGER
            // alias (ref_kind == IntegerAlias — same closed `PrimitiveRef`
            // set, variant picked from the alias's own resolved storage
            // kind rather than `mtype` text, which names the alias not the
            // native type); ENUMERATED (inline or TypeRef, via `EnumSlot`);
            // a SEQUENCE OF/SET OF member (`seq_of_kind`, via `Asn1SeqOf`);
            // a BASE64-XER OCTET STRING (needs XER's own hook, not the
            // shared primitive dispatcher); a SEQUENCE/SET reference
            // (`ref_is_sequence_or_set`, via `Asn1Seq`); or — the
            // remaining TypeRef/inline-composite case — CHOICE (via
            // `Asn1Choice`). `RefTargetKind::Other` alone can't
            // distinguish SEQUENCE/SET from CHOICE (`ref_is_sequence_or_set`'s
            // own doc on `SequenceMemberSpec`), which is exactly why that
            // flag exists.
            enum class AccessKind { Primitive, Enumerated, SeqOf, Choice, Composite, Contained, Unsupported };
            auto classify = [](const SequenceMemberSpec& m) -> AccessKind {
                if (m.contained) return AccessKind::Contained;
                if (m.seq_of_kind != SeqOfKind::None) return AccessKind::SeqOf;
                if (m.mbuiltin) {
                    if (*m.mbuiltin == ast::BuiltinType::Enumerated) return AccessKind::Enumerated;
                    return AccessKind::Primitive;
                }
                if (m.ref_kind == TaggedMemberSpec::RefTargetKind::Enumerated) return AccessKind::Enumerated;
                if (m.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias) return AccessKind::Primitive;
                if (m.ref_is_sequence_or_set) return AccessKind::Composite;
                if (m.ref_is_seq_of) return AccessKind::SeqOf;
                if (m.ref_builtin_alias) return AccessKind::Primitive;
                return AccessKind::Choice;
            };
            for (const auto& m : spec.members) {
                bool covered = sequence_member_covered(m);
                AccessKind kind = covered ? classify(m) : AccessKind::Unsupported;

                std::string tag_text, ber_framing_expr;
                if (!covered) {
                    tag_text = "asn1cpp_wire::spec::sequence::SEQUENCE_TAG";
                    ber_framing_expr = std::format(
                        "asn1cpp_wire::spec::choice::BerTagging::Unsupported(\"{}\")", stub_reason(m));
                } else if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) {
                    // `[n] ANY` — always EXPLICIT (sequence_member_covered
                    // only lets this through when so).
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = std::format("asn1cpp_wire::spec::choice::BerTagging::Explicit({})", tag_text);
                } else if (m.resolved_tag && m.is_explicit && m.resolved_tag->tag_is_override) {
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = std::format("asn1cpp_wire::spec::choice::BerTagging::Explicit({})", tag_text);
                } else if (m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit) {
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = std::format("asn1cpp_wire::spec::choice::BerTagging::Implicit({})", tag_text);
                } else if ((kind == AccessKind::Primitive || kind == AccessKind::Contained)
                           && m.resolved_tag && m.is_explicit) {
                    // The EXPLICIT tag belongs to the referenced type
                    // assignment, not to this member (X.680 §31.2, e.g.
                    // `TExp ::= [APPLICATION 13] EXPLICIT INTEGER`). The row
                    // points at that type's own framing; the walker needs
                    // the pointer because `as_member_ref` unwraps the alias
                    // to its bare primitive, which only knows its universal
                    // tag. `m.resolved_tag` is the type's outer tag, which
                    // OPTIONAL presence detection peeks for.
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = of_type_framing(kind == AccessKind::Contained ? std::format("crate::{0}::{0}", m.ref_constraints_owner) : m.mtype);
                } else if ((kind == AccessKind::Primitive || kind == AccessKind::Enumerated
                            || kind == AccessKind::Contained) && m.resolved_tag && !m.is_explicit
                           && m.resolved_tag->cls != ast::TagClass::Universal) {
                    // IMPLICIT counterpart of the branch above: the tag comes
                    // from the referenced type assignment itself (X.680
                    // §31.2, e.g. `TBool ::= [APPLICATION 1] BOOLEAN`), not
                    // from this member. The unwrapped primitive (or the
                    // OCTET STRING of a contained field) only knows its
                    // universal tag, so `Implicit` framing substitutes the
                    // type assignment's tag (X.690 §8.14.2).
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = std::format("asn1cpp_wire::spec::choice::BerTagging::Implicit({})", tag_text);
                } else if (kind == AccessKind::SeqOf && m.resolved_tag && !m.is_explicit) {
                    // IMPLICIT substitution (or no override at all — same
                    // tag either way, X.680 §25/§26): `m.resolved_tag`
                    // already holds exactly the tag `Asn1SeqOf::
                    // natural_tag()` would return at runtime
                    // (`natural_tag_spec_for`'s seq-of branch, always
                    // populated), so there is no reason
                    // to ask the value for it via `BerTagging::Delegate`
                    // (which `ber::object`'s SeqOf arm resolves by calling
                    // `inner.natural_tag()`, a redundant vtable hop for
                    // information already sitting in this row). `Implicit`
                    // reproduces the identical wire shape `Delegate` would
                    // have for this case (both end up writing one TLV
                    // under this exact tag around the element content) —
                    // see `natural_tag()`'s own doc for the one case this
                    // deliberately does *not* cover (EXPLICIT framing's
                    // inner wrap still needs the dynamic lookup, since
                    // this row carries no second, "underlying" tag field).
                    tag_text = format_tag_literal(*m.resolved_tag);
                    ber_framing_expr = std::format("asn1cpp_wire::spec::choice::BerTagging::Implicit({})", tag_text);
                } else {
                    // Plain/natural tag. A direct builtin, a named
                    // INTEGER alias, or a SEQUENCE/SET reference all
                    // implement `type_tag::TypeTag` with `TAG: Some(_)`
                    // (the latter via the unconditional `impl TypeTag for
                    // {Type}` this same function emits for every
                    // SEQUENCE/SET), so `.unwrap()` is safe. A CHOICE
                    // reference's own `TypeTag::TAG` is unconditionally
                    // `None` (X.680 §28 — CHOICE has no universal tag at
                    // all, even when the CHOICE type itself carries an
                    // own `[n]` — that case is handled through
                    // `m.resolved_tag`/EXPLICIT above, never through
                    // `TypeTag`), so this branch reads the already-
                    // resolved tag (or the inert untagged-CHOICE
                    // placeholder, never consulted for a required member)
                    // instead of calling `TypeTag::TAG.unwrap()` on it.
                    tag_text = !m.mbuiltin
                        ? (m.resolved_tag ? format_tag_literal(*m.resolved_tag)
                                          : "asn1cpp_wire::spec::sequence::SEQUENCE_TAG /* untagged CHOICE member: no fixed tag */")
                        : std::format("<{} as asn1cpp_wire::type_tag::TypeTag>::TAG.unwrap()", m.mtype);
                    // An OPTIONAL untagged CHOICE is present when the peeked
                    // tag is one of its alternatives' tags (X.690 §8.13).
                    ber_framing_expr = is_untagged_choice_ref(m) && m.optional
                        ? std::format("asn1cpp_wire::spec::choice::BerTagging::DelegateChoice("
                                      "<{} as asn1cpp_wire::type_tag::TypeTag>::choice_ber_tags)", m.mtype)
                        : "asn1cpp_wire::spec::choice::BerTagging::Delegate";
                }

                // This member's own Constraints reference — same rule
                // `MemberAccess::Primitive` above uses; always
                // UNCONSTRAINED for a composite member (it owns its own
                // constraint internally).
                std::string constraints_ref = "&asn1cpp_wire::constraints::UNCONSTRAINED";
                bool own_table = !m.tdref.empty();
                bool is_integer_narrow = m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Integer &&
                    (m.storage_kind == IntStorageKind::S64 || m.storage_kind == IntStorageKind::U64);
                bool is_octet_or_bit_or_string = m.mbuiltin &&
                    (*m.mbuiltin == ast::BuiltinType::OctetString || *m.mbuiltin == ast::BuiltinType::BitString ||
                     is_sizeable_string_kind(*m.mbuiltin));
                bool is_real = m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Real;
                if (m.mbuiltin && own_table && (is_integer_narrow || is_octet_or_bit_or_string || is_real)) {
                    constraints_ref = std::format("&{}_CONSTRAINTS",
                        to_screaming_snake_case(member_descriptor_base_name(spec.type_name, m.mname)));
                } else if (!m.mbuiltin && m.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias &&
                           (m.ref_storage_kind == IntStorageKind::S64 || m.ref_storage_kind == IntStorageKind::U64)) {
                    // A named INTEGER alias's own range (X.680 §19) lives
                    // on its own type (emit_integer_definition's
                    // `{Alias}_CONSTRAINTS`), not a per-member table —
                    // the PER dispatcher for a Primitive-kind alias member
                    // (`ber::object`'s own doc) needs this passed through
                    // explicitly, unlike the old Composite-closure design
                    // where the alias's own `per_encode` silently ignored
                    // whatever constraints the caller passed and read its
                    // own static directly.
                    constraints_ref = std::format("&crate::{0}::{0}_CONSTRAINTS", m.mtype);
                } else if (!m.mbuiltin && m.ref_builtin_alias &&
                           (*m.ref_builtin_alias == ast::BuiltinType::OctetString ||
                            *m.ref_builtin_alias == ast::BuiltinType::BitString ||
                            *m.ref_builtin_alias == ast::BuiltinType::Real ||
                            is_sizeable_string_kind(*m.ref_builtin_alias))) {
                    // Same rationale for a named OCTET STRING/BIT STRING/
                    // sizeable-string/REAL alias (`emit_builtin_alias_definition`'s
                    // own `{Alias}_CONSTRAINTS`, only emitted for these
                    // kinds) — `ref_constraints_owner`, not
                    // `mtype`: a multi-hop *pure* alias chain (e.g. ETSI
                    // LI's own `LawfulInterceptionIdentifier ::= LIID`)
                    // generates every intermediate hop as a bare `pub
                    // type X = Y;` with no `_CONSTRAINTS` of its own —
                    // only the fully-resolved target has one
                    // (`ref_constraints_owner`'s own doc, Backend.hpp).
                    constraints_ref = std::format("&crate::{0}::{0}_CONSTRAINTS", m.ref_constraints_owner);
                } else if (m.seq_of_kind != SeqOfKind::None) {
                    // An inline SEQUENCE OF/SET OF member's own synthetic
                    // promoted type (`emit_seq_of_definition`'s own
                    // `{Synth}_CONSTRAINTS`, X.680 §25/§26 SIZE) — the PER
                    // `encode_seqof_content`/`decode_seqof_content_into`
                    // walker (`per::object`) reads this member's own
                    // `MemberMeta::constraints` for the collection's SIZE,
                    // not any per-element constraint.
                    std::string synth = synthetic_name(spec.type_name, m.asn1_name);
                    constraints_ref = std::format("&crate::{}::{}_CONSTRAINTS", escape(synth), synth);
                } else if (!m.mbuiltin && m.ref_is_seq_of) {
                    // Same rationale, for a *named* SEQUENCE OF/SET OF
                    // TypeRef member — its own SIZE constraint lives on
                    // its own type, not a per-member table.
                    constraints_ref = std::format("&crate::{0}::{0}_CONSTRAINTS", m.mtype);
                }

                auto field_place = [&]() {
                    return m.optional ? std::format("v.{}.as_ref().unwrap()", m.mname)
                                       : std::format("v.{}", m.mname);
                };
                std::string validate_expr = "None";
                if (m.mbuiltin && own_table && is_integer_narrow) {
                    const char* fn = m.storage_kind == IntStorageKind::S64 ? "validate_s64" : "validate_u64";
                    std::string int_deref = m.optional ? std::format("*{}", field_place()) : field_place();
                    validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::{}(*{}, {}))", fn, int_deref, constraints_ref);
                } else if (m.mbuiltin && own_table && is_real) {
                    validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::validate_real({}.value(), {}))", field_place(), constraints_ref);
                } else if (m.mbuiltin && own_table && *m.mbuiltin == ast::BuiltinType::OctetString) {
                    validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::validate_size({}.len(), {}))", field_place(), constraints_ref);
                } else if (m.mbuiltin && own_table && *m.mbuiltin == ast::BuiltinType::BitString) {
                    validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::validate_bit_string(&{}, {}))", field_place(), constraints_ref);
                } else if (m.mbuiltin && own_table && is_sizeable_string_kind(*m.mbuiltin)) {
                    bool wide = *m.mbuiltin == ast::BuiltinType::BmpString || *m.mbuiltin == ast::BuiltinType::UniversalString;
                    if (wide) {
                        validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::validate_size({}.len(), {}))", field_place(), constraints_ref);
                    } else {
                        std::string str_ref = m.optional ? field_place() : std::format("&v.{}", m.mname);
                        validate_expr = std::format("Some(|v| asn1cpp_wire::constraints::validate_string({}, {}))", str_ref, constraints_ref);
                    }
                }

                std::string set_default_expr = "None";
                std::string is_default_equal_expr = "None";
                if (m.has_default && m.has_default_setter) {
                    std::string fname = escape(std::format("{}_{}_default", to_snake_case(spec.type_name), m.mname));
                    set_default_expr = std::format("Some(|v| v.{} = Some({}()))", m.mname, fname);
                    is_default_equal_expr = std::format("Some(|v| v.{} == Some({}()))", m.mname, fname);
                } else if (m.optional && covered) {
                    // An OPTIONAL member's value when the encoding leaves
                    // it out is "absent" (X.680 §25.6). JER decode resets a
                    // member it already reached when the value is `null`
                    // (X.697 §27.3.4); BER/PER skip this entry, as the
                    // row's has_default is false.
                    set_default_expr = std::format("Some(|v| v.{} = None)", m.mname);
                }

                std::string get_expr, get_mut_expr;
                // `&v.{m}`/`&mut v.{m}` coerce to `&dyn Asn1Seq`/`&dyn
                // Asn1Choice` the same way whether the field is `T` or
                // `Box<T>` (the latter's own blanket impl forwards
                // transparently) — shared by Composite and Choice below.
                auto class_ref_exprs = [&](const char* ref_variant, const char* mut_variant) {
                    if (m.optional) {
                        get_expr = std::format(
                            "|v| match &v.{0} {{ Some(x) => asn1cpp_wire::spec::object::MemberRef::{1}(x), None => asn1cpp_wire::spec::object::MemberRef::Absent }}",
                            m.mname, ref_variant);
                        get_mut_expr = std::format(
                            "|v| asn1cpp_wire::spec::object::MemberRefMut::{1}(v.{0}.get_or_insert_with(Default::default))",
                            m.mname, mut_variant);
                    } else {
                        get_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRef::{1}(&v.{0})", m.mname, ref_variant);
                        get_mut_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRefMut::{1}(&mut v.{0})", m.mname, mut_variant);
                    }
                };
                switch (kind) {
                case AccessKind::Primitive: {
                    // Closed builtin leaf: the same
                    // `PrimitiveRef`/`PrimitiveRefMut` set a direct
                    // builtin uses. A named INTEGER alias (ref_kind ==
                    // IntegerAlias) or a named builtin-alias
                    // (ref_builtin_alias, e.g. `PartyNumber ::=
                    // UTF8String`) picks its variant from the alias's own
                    // *resolved* wrapped type (`ref_storage_kind`/
                    // `native_int_type` or `ref_builtin_alias`/
                    // `native_builtin_type`), never from `m.mtype` text —
                    // that names the alias ("MyByte"/"PartyNumber"), not
                    // one of `PrimitiveRef`'s 26 fixed variant names. Both
                    // alias shapes are a real newtype around their wrapped
                    // type (`emit_integer_declaration`/
                    // `emit_builtin_alias_declaration`'s own doc), so the
                    // field itself (`v.{m}`) is one level too shallow —
                    // `.0` reaches the wrapped value `PrimitiveRef`
                    // actually needs.
                    std::string variant = m.mbuiltin ? primitive_variant(m.mtype)
                                         : m.ref_builtin_alias ? primitive_variant(native_builtin_type(*m.ref_builtin_alias))
                                                       : primitive_variant(native_int_type(m.ref_storage_kind));
                    std::string dot0 = m.mbuiltin ? "" : ".0";
                    if (m.optional) {
                        get_expr = std::format(
                            "|v| match &v.{0} {{ Some(x) => asn1cpp_wire::spec::object::MemberRef::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRef::{1}(&x{2})), None => asn1cpp_wire::spec::object::MemberRef::Absent }}",
                            m.mname, variant, dot0);
                        // `get_or_insert_with` already returns `&mut T`
                        // directly — a bare field access needs no further
                        // `&mut` at all (taking `&mut` of an already-`&mut`
                        // *value* rather than a place is a dangling-
                        // temporary error); only the alias's `.0` case
                        // turns that returned reference back into a place
                        // that then needs re-borrowing.
                        get_mut_expr = dot0.empty()
                            ? std::format(
                                  "|v| asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{1}(v.{0}.get_or_insert_with(Default::default)))",
                                  m.mname, variant)
                            : std::format(
                                  "|v| asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{1}(&mut v.{0}.get_or_insert_with(Default::default){2}))",
                                  m.mname, variant, dot0);
                    } else {
                        get_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRef::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRef::{1}(&v.{0}{2}))", m.mname, variant, dot0);
                        get_mut_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{1}(&mut v.{0}{2}))", m.mname, variant, dot0);
                    }
                    break;
                }
                case AccessKind::Enumerated: {
                    // `m.mtype` is already the enum type's own Rust
                    // identifier, inline or TypeRef alike (the same
                    // synthetic-naming convention every inline
                    // SEQUENCE/CHOICE/ENUMERATED member uses) — so its
                    // `{mtype}_ENUM_SPEC` (emitted by
                    // emit_enumerated_definition for that exact type) is
                    // always the right static to pair with it.
                    std::string enum_spec = std::format("crate::{0}::{0}_ENUM_SPEC", m.mtype);
                    if (m.optional) {
                        get_expr = std::format(
                            "|v| match &v.{0} {{ Some(x) => asn1cpp_wire::spec::object::MemberRef::Enumerated(x, &{1}), None => asn1cpp_wire::spec::object::MemberRef::Absent }}",
                            m.mname, enum_spec);
                        get_mut_expr = std::format(
                            "|v| asn1cpp_wire::spec::object::MemberRefMut::Enumerated(v.{0}.get_or_insert_with(Default::default), &{1})",
                            m.mname, enum_spec);
                    } else {
                        get_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRef::Enumerated(&v.{0}, &{1})", m.mname, enum_spec);
                        get_mut_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRefMut::Enumerated(&mut v.{0}, &{1})", m.mname, enum_spec);
                    }
                    break;
                }
                case AccessKind::SeqOf:
                    // The field is already `SeqOf<V>`/`SetOf<V>`
                    // (`rust_seqof_member_field_type`) — both implement
                    // `Asn1SeqOf` generically.
                    class_ref_exprs("SeqOf", "SeqOf");
                    break;
                case AccessKind::Choice:
                    class_ref_exprs("Choice", "Choice");
                    break;
                case AccessKind::Composite:
                    class_ref_exprs("Composite", "Composite");
                    break;
                case AccessKind::Contained: {
                    // `Containing<T>` behind the type-erased `Contained`
                    // view, with its field's `ContainedSpec` row.
                    std::string cs = contained_spec_ident(m.contained_base);
                    if (m.optional) {
                        get_expr = std::format(
                            "|v| match &v.{0} {{ Some(x) => asn1cpp_wire::spec::object::MemberRef::Contained(x, &{1}), None => asn1cpp_wire::spec::object::MemberRef::Absent }}",
                            m.mname, cs);
                        get_mut_expr = std::format(
                            "|v| asn1cpp_wire::spec::object::MemberRefMut::Contained(v.{0}.get_or_insert_with(Default::default), &{1})",
                            m.mname, cs);
                    } else {
                        get_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRef::Contained(&v.{0}, &{1})", m.mname, cs);
                        get_mut_expr = std::format("|v| asn1cpp_wire::spec::object::MemberRefMut::Contained(&mut v.{0}, &{1})", m.mname, cs);
                    }
                    validate_expr = "None";
                    break;
                }
                case AccessKind::Unsupported: {
                    // The walkers turn `Unsupported` into a per-record
                    // encode/decode error carrying this message.
                    std::string reason = stub_reason(m);
                    get_expr = std::format("|_v| asn1cpp_wire::spec::object::MemberRef::Unsupported(\"member '{}' not supported: {}\")", m.asn1_name, reason);
                    get_mut_expr = std::format("|_v| asn1cpp_wire::spec::object::MemberRefMut::Unsupported(\"member '{}' not supported: {}\")", m.asn1_name, reason);
                    break;
                }
                }

                meta_lines.push_back(std::format(
                    "    asn1cpp_wire::spec::object::MemberMeta {{ name: \"{}\", tag: {}, optional: {}, ber: {}, constraints: {}, xer_instruction: {}, has_default: {}, contained: {} }},",
                    m.asn1_name, tag_text, m.optional ? "true" : "false", ber_framing_expr, constraints_ref,
                    covered ? rust_xer_instruction(m) : "asn1cpp_wire::spec::object::XerInstruction::Default",
                    m.has_default && m.has_default_setter ? "true" : "false",
                    m.contained ? std::format("Some(&{})", contained_spec_ident(m.contained_base)) : "None"));
                getter_lines.push_back(std::format("    {},", get_expr));
                getter_mut_lines.push_back(std::format("    {},", get_mut_expr));
                set_default_lines.push_back(std::format("    {},", set_default_expr));
                is_default_equal_lines.push_back(std::format("    {},", is_default_equal_expr));
                validate_lines.push_back(std::format("    {},", validate_expr));
            }

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [asn1cpp_wire::spec::object::MemberMeta; {}] = [\n", obj_members_ident, spec.members.size());
            for (const auto& l : meta_lines) os << l << "\n";
            os << "];\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: asn1cpp_wire::spec::object::SequenceSpec = asn1cpp_wire::spec::object::SequenceSpec {{\n", obj_spec_ident);
            os << std::format("    name: \"{}\",\n", spec.xer_name);
            os << std::format("    tag: {},\n",
                              spec.tag ? format_tag_literal(*spec.tag)
                                       : std::format("asn1cpp_wire::spec::sequence::{}", spec.is_set ? "SET_TAG" : "SEQUENCE_TAG"));
            os << std::format("    members: &{},\n", obj_members_ident);
            os << std::format("    ext_at: {},\n", spec.ext_at);
            os << std::format("    roms_count: {},\n", spec.roms_count);
            os << std::format("    is_set: {},\n", spec.is_set ? "true" : "false");
            // PER extension-addition units (X.691 §18.9); empty unless the
            // type has an extension addition group.
            std::string units, group_opt;
            for (std::size_t u = 0; u < spec.ext_unit_ends.size(); ++u)
                units += std::format("{}asn1cpp_wire::spec::object::ExtUnit {{ end: {}, group: {} }}",
                                     u ? ", " : "", spec.ext_unit_ends[u], spec.ext_unit_is_group[u] ? "true" : "false");
            for (std::size_t i = 0; i < spec.member_group_optional.size(); ++i)
                group_opt += std::format("{}{}", i ? ", " : "", spec.member_group_optional[i] ? "true" : "false");
            os << std::format("    ext_units: &[{}],\n", units);
            os << std::format("    group_member_optional: &[{}],\n", group_opt);
            std::string contained_idx;
            for (std::size_t i = 0; i < spec.members.size(); ++i)
                if (spec.members[i].contained)
                    contained_idx += std::format("{}{}", contained_idx.empty() ? "" : ", ", i);
            os << std::format("    contained_members: &[{}],\n", contained_idx);
            os << "};\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [fn(&{}) -> asn1cpp_wire::spec::object::MemberRef<'_>; {}] = [\n", getters_ident, spec.type_name, spec.members.size());
            for (const auto& l : getter_lines) os << l << "\n";
            os << "];\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [fn(&mut {}) -> asn1cpp_wire::spec::object::MemberRefMut<'_>; {}] = [\n", getters_mut_ident, spec.type_name, spec.members.size());
            for (const auto& l : getter_mut_lines) os << l << "\n";
            os << "];\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [::std::option::Option<fn(&mut {})>; {}] = [\n", set_default_ident, spec.type_name, spec.members.size());
            for (const auto& l : set_default_lines) os << l << "\n";
            os << "];\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [::std::option::Option<fn(&{}) -> bool>; {}] = [\n", is_default_equal_ident, spec.type_name, spec.members.size());
            for (const auto& l : is_default_equal_lines) os << l << "\n";
            os << "];\n\n";

            os << "#[allow(non_upper_case_globals)]\n";
            os << std::format("static {}: [::std::option::Option<fn(&{}) -> i64>; {}] = [\n", validate_ident, spec.type_name, spec.members.size());
            for (const auto& l : validate_lines) os << l << "\n";
            os << "];\n\n";

            os << std::format("impl asn1cpp_wire::spec::object::Asn1Seq for {} {{\n", spec.type_name);
            os << std::format("    fn spec(&self) -> &'static asn1cpp_wire::spec::object::SequenceSpec {{ &{} }}\n", obj_spec_ident);
            os << std::format("    fn get_member(&self, i: usize) -> asn1cpp_wire::spec::object::MemberRef<'_> {{ {}[i](self) }}\n", getters_ident);
            os << std::format("    fn get_member_mut(&mut self, i: usize) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {{ {}[i](self) }}\n", getters_mut_ident);
            os << std::format("    fn set_default(&mut self, i: usize) {{ if let Some(f) = {}[i] {{ f(self) }} }}\n", set_default_ident);
            os << std::format("    fn is_default_equal(&self, i: usize) -> bool {{ {}[i].map_or(false, |f| f(self)) }}\n", is_default_equal_ident);
            os << std::format("    fn validate(&self, i: usize) -> i64 {{ {}[i].map_or(0, |f| f(self)) }}\n", validate_ident);
            os << "}\n\n";

        // Whole-document root marker: every codec's top-level
        // `encode_pdu`/`decode_pdu` binds on it (`spec::object::Asn1Pdu`).
        os << std::format("impl asn1cpp_wire::spec::object::Asn1Pdu for {} {{}}\n\n", spec.type_name);

        // A member/alternative referencing this type by name asks for its
        // tag via `<T as TypeTag>::TAG`.
        os << "\n";
        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", spec.type_name);
        os << std::format("    const TAG: ::std::option::Option<asn1cpp_wire::Tag> = Some({}.tag);\n", obj_spec_ident);
        os << "}\n\n";
        // Lets this type appear as a SEQUENCE OF/SET OF element
        // (`SeqOf<T>`/`SetOf<T>`'s own `Asn1SeqOf` impl needs `T:
        // AsMemberRef`, `spec::object`'s own doc).
        os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", spec.type_name);
        os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        os << "        asn1cpp_wire::spec::object::MemberRef::Composite(self)\n";
        os << "    }\n\n";
        os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << "        asn1cpp_wire::spec::object::MemberRefMut::Composite(self)\n";
        os << "    }\n\n";
        os << std::format("    fn own_element_xer_name(&self) -> &'static str {{ {}.name }}\n", obj_spec_ident);
        os << "}\n\n";
    }
}

void RustBackend::emit_sequence(const SequenceSpec& spec, TypeOutputSession& session) const {
    emit_sequence_declaration(spec, session.buffer(declaration_extension()));
    emit_sequence_definition(spec, session.buffer(definition_extension()));
}

/// @brief Emit the Rust enum declaration for a CHOICE type.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
/// @note Deliberately does NOT port the C++ side's raw-buffer/`alignas`/
///       `std::launder`/`ChoiceOps<T>` storage design — that design exists only to dodge
///       `std::variant`'s O(N²) template-instantiation blowup on large
///       CHOICEs, a C++-template-specific failure mode. Rust's `enum` is a
///       native tagged union, not template-recursive, so the natural
///       mapping has no equivalent problem. No `#[derive(Default)]`: unlike
///       a struct, a CHOICE has no natural default variant.
void RustBackend::emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const {
    auto alt_payload_type = [&](const ChoiceAlternativeSpec& a) {
        std::string synth = synthetic_name(spec.type_name, a.asn1_name);
        return rust_alt_payload_type(a.mtype, std::format("crate::{}::{}", escape(synth), synth));
    };
    // Variant names use variant_name(), not the raw
    // a.pr_name. a.pr_name is
    // Generator's backend-agnostic "PR" name (mirrors the C++ side's
    // `enum class PR { NOTHING, num, flag, ... }`, ASN.1 member-name
    // casing verbatim — fine for C++, which has no naming-convention lint
    // on enum members). Real generated Rust CHOICEs almost always have
    // lowercase-first ASN.1 member names (X.680 §11.2's convention), so
    // using a.pr_name directly would emit e.g. `Selector::num(i64)` —
    // compiles, but rustc's non_camel_case_types lint flags it (a warning
    // by default; tests/rust/run_rust_tests.py's `-D warnings` would turn
    // it into a hard failure the moment that harness compiles real codegen
    // output instead of hand-written mirrors). Same fix ENUMERATED already
    // needed (variant_name(), just above emit_enumerated_declaration).
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    os << "#[derive(Debug, Clone, PartialEq)]\n";
    os << "#[allow(non_camel_case_types)]\n";
    os << std::format("pub enum {} {{\n", spec.type_name);
    // Same collision guard as emit_enumerated_declaration —
    // variant_name's word-split conversion can map two distinct alternative
    // names onto the same Rust variant (e.g. "a-b"/"ab" both -> "Ab").
    std::unordered_map<std::string, std::string> seen_variants;  // variant name -> first asn1_name
    for (const auto& a : spec.alternatives) {
        std::string vname = variant_name(*this, a.asn1_name);
        auto [it, inserted] = seen_variants.emplace(vname, a.asn1_name);
        if (!inserted)
            throw std::runtime_error(std::format(
                "RustBackend: CHOICE '{}' — alternatives '{}' and '{}' both map to Rust variant '{}'",
                spec.type_name, it->second, a.asn1_name, vname));
        // A directly self-referential alternative (a.mtype == the CHOICE's
        // own name, X.680 §28 permits this — e.g. a tree-shaped message)
        // needs a Box: an unboxed variant makes the enum an infinite-size
        // recursive type (rustc E0072). The C++ side hits the analogous
        // problem for a different reason (val_storage_'s sizeof/alignof on
        // its own still-incomplete type) and box for the same reason — see
        // CppBackend::emit_choice_declaration's val_storage_ comment.
        bool boxed = (a.mtype == spec.type_name);
        os << std::format("    /// ASN.1: `{}`\n", a.asn1_name);
        os << std::format("    {}({}{}{}),\n", vname,
                          boxed ? "Box<" : "", alt_payload_type(a), boxed ? ">" : "");
    }
    // A `...`-marked CHOICE (X.680 §29.6) promises a future schema revision
    // may add alternatives this compiler run never saw. Every real
    // alternative declared after `...` in *this* schema version is already
    // a normal AlternativeSpec row above — this variant covers only
    // genuinely-unknown-to-us content, captured as a raw TLV (tag + value
    // bytes) so decode->re-encode still round-trips byte-identically. See
    // rust-runtime/wire/src/choice.rs's UnknownExtensionOps doc comment for
    // the runtime side.
    if (spec.ext_at >= 0) {
        auto [it, inserted] = seen_variants.emplace("UnknownExtension", "...");
        if (!inserted)
            throw std::runtime_error(std::format(
                "RustBackend: CHOICE '{}' — alternative '{}' collides with the reserved "
                "'UnknownExtension' variant name",
                spec.type_name, it->second));
        os << std::format("    UnknownExtension(asn1cpp_wire::Tag, Vec<u8>),\n");
    }
    os << "}\n\n";
}

/// @brief Emit the definition half of a CHOICE type: the alternative
///        tables behind its reflective `Asn1Choice` impl, `TypeTag`/
///        `AsMemberRef`, and the `Asn1Pdu` root marker.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
/// @note Tables only — every codec reaches the type through its own
///       `<codec>::object` walker (`encode_pdu`/`decode_pdu` at top level).
/// @see X.680 §29 (CHOICE).
void RustBackend::emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const {
    auto alt_payload_type = [&](const ChoiceAlternativeSpec& a) {
        std::string synth = synthetic_name(spec.type_name, a.asn1_name);
        return rust_alt_payload_type(a.mtype, std::format("crate::{}::{}", escape(synth), synth));
    };
    std::string prefix = escape(to_snake_case(spec.type_name));
    // A CHOICE with exactly one alternative makes every
    // "does x match this variant" pattern provably always true — rustc
    // correctly flags a `_ => panic!(...)` wildcard arm as unreachable in
    // that case (and, below, an `if let` as irrefutable). Special-cased
    // for correct-by-construction output rather than suppressing real
    // compiler signal: a single-alternative CHOICE
    // uses a plain irrefutable `let` pattern instead of `match`/`if let`,
    // which needs no wildcard/`else` arm at all and warns on neither.
    // An extensible CHOICE (spec.ext_at >= 0) always gets a
    // second enum variant (UnknownExtension, see emit_choice_declaration) —
    // even when spec.alternatives itself has only one row, the enum as a
    // whole is never single-variant once extensible, so the single_alt
    // irrefutable-pattern special-case must not fire for it.
    bool single_alt = spec.alternatives.size() == 1 && spec.ext_at < 0;
    for (const auto& a : spec.alternatives) {
        std::string fname = escape(std::format("{}_get_{}", prefix, unescape_raw_ident(a.accessor_name)));
        os << std::format("pub fn {}(x: &mut {}) -> &mut {} {{\n", fname, spec.type_name, alt_payload_type(a));
        if (single_alt) {
            os << std::format("    let {}::{}(v) = x;\n    v\n",
                               spec.type_name, variant_name(*this, a.asn1_name));
        } else {
            os << std::format("    match x {{ {}::{}(v) => v, _ => panic!(\"wrong variant\") }}\n",
                               spec.type_name, variant_name(*this, a.asn1_name));
        }
        os << "}\n\n";
    }

    // Manual Default impl, first-declared alternative with
    // its own type's Default value — same rationale as ENUMERATED's Default
    // impl just above this call in the file (emit_enumerated_definition):
    // X.680 CHOICE (§28) has no "default alternative" concept at all (even
    // less than ENUMERATED's arbitrary-but-defensible "first value"), but
    // without *some* Default a SEQUENCE with a required (non-OPTIONAL)
    // CHOICE-typed member can't derive Default itself — the actual bug
    // found on the real ETSI LI PS-PDU schema (193 compile errors).
    // Requires the first alternative's own mtype to implement Default,
    // which recursively holds for every type this backend generates
    // (primitives, String, Vec<T>, and now every ENUMERATED/CHOICE too).
    if (!spec.alternatives.empty()) {
        const auto& first = spec.alternatives.front();
        os << std::format("impl Default for {} {{\n", spec.type_name);
        os << std::format("    fn default() -> Self {{ {}::{}(Default::default()) }}\n",
                           spec.type_name, variant_name(*this, first.asn1_name));
        os << "}\n\n";
    }

    // Reflective `Asn1Choice` apparatus (see `spec::object`'s own doc),
    // emitted unconditionally, mirroring
    // `emit_sequence_definition`'s per-member kind classification one
    // level over: each alternative is Primitive/Enumerated/SeqOf/
    // Composite(SEQUENCE/SET)/Choice (a nested CHOICE alternative), or
    // Unsupported. `rust_mtype_is_unusable_vec` is the SeqOf signal here
    // (the payload is then the promoted synthetic type, which knows
    // whether it is a SEQUENCE OF or a SET OF; `rust_alt_payload_type`).
    //
    // BER dispatch: wire tag -> alternative index, precomputed here.
    // `spec.ber_tags` (Backend.hpp) is populated by Generator whenever
    // `collect_ber_tags_for` produces anything (every tagged alternative,
    // flattened recursively through an untagged inner CHOICE per X.690
    // §8.13) — not only in the `has_ber_table` case (that flag is purely
    // CppBackend's own "do I need a separate asn_BER_X array" decision;
    // RustBackend's binary-search dispatch needs the full table
    // regardless). Already sorted by `ber_tag_class_rank` (Backend.hpp) —
    // the single ranking every BER-dispatch sort in this codebase shares,
    // matching the Rust runtime's own `Tag::identifier_key`
    // (`ber::tag.rs`) exactly. Only the AUTOMATIC-TAGS case (every
    // alternative already has its own distinct context tag, so Generator
    // doesn't bother building a table) needs a fallback built here, from
    // `spec.alternatives` directly. The one alternative shape that
    // genuinely can't get a row at all — real or stub — is one with no
    // resolved tag whatsoever (`choice_alternative_has_tag`'s own doc):
    // `decode_choice_dispatch`'s tag scan needs a real `Tag` to know when
    // to try a row, so that alternative is simply omitted from the table
    // entirely (its enum variant still exists, just unreachable via the
    // generated encode()/decode()).
    struct DispatchRow { int cls_rank; int64_t number; std::string tag_lit; size_t idx; };
    std::vector<DispatchRow> dispatch;
    if (!spec.ber_tags.empty()) {
        for (const auto& e : spec.ber_tags)
            dispatch.push_back({ber_tag_class_rank(e.cls), e.number, e.tag_literal, static_cast<size_t>(e.alt_index)});
    } else {
        for (size_t i = 0; i < spec.alternatives.size(); ++i)
            if (choice_alternative_has_tag(spec.alternatives[i])) {
                const auto& t = *spec.alternatives[i].resolved_tag;
                dispatch.push_back({ber_tag_class_rank(t.cls), t.number, format_tag_literal(t), i});
            }
        std::sort(dispatch.begin(), dispatch.end(), [](const DispatchRow& a, const DispatchRow& b) {
            return std::pair(a.cls_rank, a.number) < std::pair(b.cls_rank, b.number);
        });
    }
    if (!dispatch.empty()) {
        std::string alts_ident = std::format("{}_ALTS", spec.type_name);
        std::string tags_ident = std::format("{}_BER_TAGS", spec.type_name);
        std::string spec_ident = std::format("{}_SPEC", spec.type_name);
        std::string get_active_ident = std::format("{}_GET_ACTIVE", spec.type_name);
        std::string select_mut_ident = std::format("{}_SELECT_MUT", spec.type_name);

        enum class AltKind { Primitive, Enumerated, SeqOf, Choice, Composite, Contained, Unsupported };
        auto classify_alt = [](const ChoiceAlternativeSpec& a) -> AltKind {
            if (a.contained) return AltKind::Contained;
            if (rust_mtype_is_unusable_vec(a.mtype)) return AltKind::SeqOf;
            if (a.mbuiltin) {
                if (*a.mbuiltin == ast::BuiltinType::Enumerated) return AltKind::Enumerated;
                return AltKind::Primitive;
            }
            if (a.ref_kind == TaggedMemberSpec::RefTargetKind::Enumerated) return AltKind::Enumerated;
            if (a.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias) return AltKind::Primitive;
            if (a.ref_is_sequence_or_set) return AltKind::Composite;
            if (a.ref_is_seq_of) return AltKind::SeqOf;
            if (a.ref_builtin_alias) return AltKind::Primitive;
            return AltKind::Choice;
        };

        // Single-alternative, non-extensible CHOICE uses an irrefutable
        // `let` instead of `match` — same rustc-lint reasoning the
        // accessor functions above already apply.
        // Explicit `x: &Type`/`x: &mut Type` parameter annotations —
        // without one, rustc's closure-param inference fixes `x`'s type
        // from the *first* constraint it sees in the body (here, the
        // by-value-or-reference-ambiguous `matches!(x, Pattern)`/`match
        // x {...}` shape), which it picks as owned `Type`, not `&mut
        // Type`; the later `*x = ...`/call-site-argument constraints
        // then conflict instead of retroactively fixing it. An explicit
        // annotation pins it up front.
        // `bind`: the pattern variable `op` actually reads — "v" for
        // every real kind, "_" for `AltKind::Unsupported` (`op` there is
        // always a `MemberRef::Unsupported(...)`, never referencing the payload;
        // binding `v` there would warn unused on every build that
        // includes an Unsupported alternative, e.g. EXTERNAL's own
        // `single-ASN1-type`/ANY alternative).
        auto get_closure = [&](const std::string& variant_path, const std::string& op, const char* bind = "v") {
            return single_alt
                ? std::format("|x: &{2}| {{ let {0}({3}) = x; {1} }}", variant_path, op, spec.type_name, bind)
                : std::format("|x: &{2}| match x {{ {0}({3}) => {1}, _ => unreachable!() }}", variant_path, op, spec.type_name, bind);
        };
        auto select_closure = [&](const std::string& variant_path, const std::string& op, const char* bind = "v") {
            return single_alt
                ? std::format("|x: &mut {2}| {{ let {0}({3}) = x; {1} }}", variant_path, op, spec.type_name, bind)
                : std::format("|x: &mut {2}| {{ if !matches!(x, {0}(_)) {{ *x = {0}(Default::default()); }} match x {{ {0}({3}) => {1}, _ => unreachable!() }} }}", variant_path, op, spec.type_name, bind);
        };

        std::vector<std::string> meta_lines, get_active_arms, select_mut_arms;

        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format("static {}: [asn1cpp_wire::spec::object::AltMeta; {}] = [\n", alts_ident, spec.alternatives.size());
        for (const auto& a : spec.alternatives) {
            std::string vname = variant_name(*this, a.asn1_name);
            std::string variant_path = std::format("{}::{}", spec.type_name, vname);
            bool covered = choice_alternative_covered(a);
            AltKind kind = covered ? classify_alt(a) : AltKind::Unsupported;

            std::string ber;
            if (!covered) {
                ber = "asn1cpp_wire::spec::choice::BerTagging::Unsupported(\"alternative not yet supported\")";
            } else if (a.resolved_tag && a.is_explicit && a.resolved_tag->tag_is_override) {
                // EXPLICIT (X.690 §8.14.3): an outer TLV around the payload.
                ber = std::format("asn1cpp_wire::spec::choice::BerTagging::Explicit({})", format_tag_literal(*a.resolved_tag));
            } else if (a.resolved_tag && a.is_explicit && (kind == AltKind::Primitive || kind == AltKind::Contained)) {
                // A bare reference to an EXPLICIT-tagged type assignment
                // whose payload unwraps to a bare primitive (or the plain
                // OCTET STRING of a contained field): the row points at
                // the type's own framing (X.680 §31.2, X.690 §8.14.2).
                ber = of_type_framing(kind == AltKind::Contained ? std::format("crate::{0}::{0}", a.ref_constraints_owner) : a.mtype);
            } else if (a.resolved_tag && a.is_explicit) {
                // A bare reference to an EXPLICIT-tagged type: it wraps
                // itself, a second wrap here would double it (X.680 §30).
                ber = "asn1cpp_wire::spec::choice::BerTagging::Delegate";
            } else if (a.resolved_tag) {
                // IMPLICIT retag, or the natural tag when they coincide.
                ber = std::format("asn1cpp_wire::spec::choice::BerTagging::Implicit({})", format_tag_literal(*a.resolved_tag));
            } else {
                // No tag of its own (an untagged CHOICE payload, X.680 §28):
                // the payload's own encoding already carries its tag.
                ber = "asn1cpp_wire::spec::choice::BerTagging::Delegate";
            }
            std::string alt_constraints = "&asn1cpp_wire::constraints::UNCONSTRAINED";
            if (a.mbuiltin && !a.tdref.empty()) {
                alt_constraints = "&" + to_screaming_snake_case(member_descriptor_base_name(spec.type_name, unescape_raw_ident(a.accessor_name))) + "_CONSTRAINTS";
            } else if (!a.mbuiltin && a.ref_kind == TaggedMemberSpec::RefTargetKind::IntegerAlias &&
                       (a.ref_storage_kind == IntStorageKind::S64 || a.ref_storage_kind == IntStorageKind::U64)) {
                // See the SEQUENCE-member AccessKind::Primitive case's
                // identical fix for why an alias needs its own
                // `{Alias}_CONSTRAINTS`, not UNCONSTRAINED.
                alt_constraints = std::format("&crate::{0}::{0}_CONSTRAINTS", a.mtype);
            } else if (!a.mbuiltin && a.ref_builtin_alias &&
                       (*a.ref_builtin_alias == ast::BuiltinType::OctetString ||
                        *a.ref_builtin_alias == ast::BuiltinType::BitString ||
                        *a.ref_builtin_alias == ast::BuiltinType::Real ||
                        is_sizeable_string_kind(*a.ref_builtin_alias))) {
                // `ref_constraints_owner`, not `mtype` — see the
                // SEQUENCE-member case's identical fix (Backend.hpp's
                // own doc on the field).
                alt_constraints = std::format("&crate::{0}::{0}_CONSTRAINTS", a.ref_constraints_owner);
            } else if (!a.mbuiltin && a.ref_is_seq_of) {
                // Named SEQUENCE OF/SET OF alternative — same rationale
                // as the SEQUENCE-member AccessKind::SeqOf case.
                alt_constraints = std::format("&crate::{0}::{0}_CONSTRAINTS", a.mtype);
            } else if (kind == AltKind::SeqOf) {
                // Inline SEQUENCE OF/SET OF alternative (`classify_alt`;
                // the named case is the branch above): its SIZE (X.680
                // §25/§26) and element constraints live on the promoted
                // synthetic type's `{Synth}_CONSTRAINTS`, which the PER
                // SEQUENCE OF walker reads from this row — same as the
                // SEQUENCE-member inline case.
                std::string synth = synthetic_name(spec.type_name, a.asn1_name);
                alt_constraints = std::format("&crate::{}::{}_CONSTRAINTS", escape(synth), synth);
            }
            meta_lines.push_back(std::format(
                "    asn1cpp_wire::spec::object::AltMeta {{ name: \"{}\", ber: {}, constraints: {}, xer_instruction: {}, contained: {} }},",
                a.asn1_name, ber, alt_constraints, rust_xer_instruction(a),
                a.contained ? std::format("Some(&{})", contained_spec_ident(a.contained_base)) : "None"));

            std::string get_op, get_mut_op;
            switch (kind) {
            case AltKind::Primitive: {
                // See the SEQUENCE-member AccessKind::Primitive case's own
                // doc for why an alias needs `.0` (one newtype level) and
                // a variant derived from the wrapped type, not `a.mtype`.
                std::string variant = a.mbuiltin ? primitive_variant(a.mtype)
                                     : a.ref_builtin_alias ? primitive_variant(native_builtin_type(*a.ref_builtin_alias))
                                                   : primitive_variant(native_int_type(a.ref_storage_kind));
                std::string v_expr = a.mbuiltin ? "v" : "&v.0";
                std::string v_mut_expr = a.mbuiltin ? "v" : "&mut v.0";
                get_op = std::format("asn1cpp_wire::spec::object::MemberRef::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRef::{}({}))", variant, v_expr);
                get_mut_op = std::format("asn1cpp_wire::spec::object::MemberRefMut::Primitive(asn1cpp_wire::spec::primitive::PrimitiveRefMut::{}({}))", variant, v_mut_expr);
                break;
            }
            case AltKind::Enumerated: {
                std::string enum_spec = std::format("crate::{0}::{0}_ENUM_SPEC", a.mtype);
                get_op = std::format("asn1cpp_wire::spec::object::MemberRef::Enumerated(v, &{})", enum_spec);
                get_mut_op = std::format("asn1cpp_wire::spec::object::MemberRefMut::Enumerated(v, &{})", enum_spec);
                break;
            }
            case AltKind::SeqOf:
                get_op = "asn1cpp_wire::spec::object::MemberRef::SeqOf(v)";
                get_mut_op = "asn1cpp_wire::spec::object::MemberRefMut::SeqOf(v)";
                break;
            case AltKind::Choice:
                get_op = "asn1cpp_wire::spec::object::MemberRef::Choice(v)";
                get_mut_op = "asn1cpp_wire::spec::object::MemberRefMut::Choice(v)";
                break;
            case AltKind::Composite:
                get_op = "asn1cpp_wire::spec::object::MemberRef::Composite(v)";
                get_mut_op = "asn1cpp_wire::spec::object::MemberRefMut::Composite(v)";
                break;
            case AltKind::Contained:
                get_op = std::format("asn1cpp_wire::spec::object::MemberRef::Contained(v, &{})", contained_spec_ident(a.contained_base));
                get_mut_op = std::format("asn1cpp_wire::spec::object::MemberRefMut::Contained(v, &{})", contained_spec_ident(a.contained_base));
                break;
            case AltKind::Unsupported:
                get_op = std::format("asn1cpp_wire::spec::object::MemberRef::Unsupported(\"alternative '{}' not supported\")", a.asn1_name);
                get_mut_op = std::format("asn1cpp_wire::spec::object::MemberRefMut::Unsupported(\"alternative '{}' not supported\")", a.asn1_name);
                break;
            }
            const char* bind = kind == AltKind::Unsupported ? "_" : "v";
            get_active_arms.push_back(get_closure(variant_path, get_op, bind));
            select_mut_arms.push_back(select_closure(variant_path, get_mut_op, bind));
            os << meta_lines.back() << "\n";
        }
        os << "];\n\n";

        // Table-of-fptr for `get_active` — `active_index()` already
        // identifies which row applies, so
        // `get_active` just indexes this instead of re-matching on `self`
        // a second time.
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format("static {}: [fn(&{}) -> asn1cpp_wire::spec::object::MemberRef<'_>; {}] = [\n",
                          get_active_ident, spec.type_name, get_active_arms.size());
        for (const auto& l : get_active_arms) os << "    " << l << ",\n";
        os << "];\n\n";

        // Same table-of-fptr shape for `select_mut` — besides matching
        // `get_active`'s own design, this sidesteps a closure-lifetime
        // limitation: an immediately-invoked closure like `(|x: &mut T|
        // {...})(self)` can't express "output borrows from input with
        // the input's own lifetime" (closures infer one fixed anonymous
        // lifetime for their whole body, not a per-call one — rustc
        // "lifetime may not live long enough"/invariance error); coercing
        // the same closure into a `fn(&mut T) -> MemberRefMut<'_>` array
        // element instead gives rustc the explicit higher-ranked
        // signature up front, which a plain `fn` pointer (unlike a
        // closure) can represent.
        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format("static {}: [fn(&mut {}) -> asn1cpp_wire::spec::object::MemberRefMut<'_>; {}] = [\n",
                          select_mut_ident, spec.type_name, select_mut_arms.size());
        for (const auto& l : select_mut_arms) os << "    " << l << ",\n";
        os << "];\n\n";

        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format("static {}: [asn1cpp_wire::spec::choice::BerDispatch; {}] = [\n", tags_ident, dispatch.size());
        for (const auto& row : dispatch)
            os << std::format("    asn1cpp_wire::spec::choice::BerDispatch {{ tag: {}, alt: {} }},\n", row.tag_lit, row.idx);
        os << "];\n\n";

        os << "#[allow(non_upper_case_globals)]\n";
        os << std::format(
            "static {}: asn1cpp_wire::spec::object::ChoiceSpec = asn1cpp_wire::spec::object::ChoiceSpec {{\n",
            spec_ident);
        os << std::format("    name: \"{}\",\n", spec.xer_name);
        os << std::format("    alternatives: &{},\n", alts_ident);
        os << std::format("    ber_tags: &{},\n", tags_ident);
        if (spec.tag) {
            // X.680 §30.6 — a CHOICE type assignment's own declared [n]
            // is always EXPLICIT.
            os << std::format("    own_tag: Some({}),\n", format_tag_literal(*spec.tag));
        } else {
            os << "    own_tag: None,\n";
        }
        os << std::format("    ext_at: {},\n", spec.ext_at);
        os << std::format("    range_bits: {},\n", spec.range_bits);
        os << std::format("    has_contained: {},\n",
                          std::any_of(spec.alternatives.begin(), spec.alternatives.end(),
                                      [](const ChoiceAlternativeSpec& a) { return a.contained != nullptr; })
                              ? "true" : "false");
        os << "};\n\n";

        os << std::format("impl asn1cpp_wire::spec::object::Asn1Choice for {} {{\n", spec.type_name);
        os << std::format("    fn spec(&self) -> &'static asn1cpp_wire::spec::object::ChoiceSpec {{ &{} }}\n", spec_ident);
        if (single_alt) {
            os << "    fn active_index(&self) -> ::std::option::Option<usize> { Some(0) }\n";
        } else {
            std::string arms;
            for (size_t i = 0; i < spec.alternatives.size(); ++i) {
                std::string vname = variant_name(*this, spec.alternatives[i].asn1_name);
                arms += std::format("{}::{}(_) => Some({}), ", spec.type_name, vname, i);
            }
            if (spec.ext_at >= 0) arms += "_ => None,";
            os << std::format("    fn active_index(&self) -> ::std::option::Option<usize> {{ match self {{ {} }} }}\n", arms);
        }
        os << "    fn get_active(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        // `None` only for an unrecognized extension (`UnknownExtension`);
        // the walkers check `active_index()` first, so this arm is a
        // fallback that still surfaces as a codec error, never a panic.
        os << std::format("        match self.active_index() {{ Some(i) => {}[i](self), None => asn1cpp_wire::spec::object::MemberRef::Unsupported(\"CHOICE {}: no alternative selected\") }}\n", get_active_ident, spec.xer_name);
        os << "    }\n";
        os << "    fn select_mut(&mut self, index: usize) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << std::format("        {}[index](self)\n", select_mut_ident);
        os << "    }\n";
        if (spec.ext_at >= 0) {
            os << "    fn construct_unknown_extension(&mut self, tag: asn1cpp_wire::Tag, bytes: Vec<u8>) {\n";
            os << std::format("        *self = {}::UnknownExtension(tag, bytes);\n", spec.type_name);
            os << "    }\n";
            os << "    fn extract_unknown_extension(&self) -> ::std::option::Option<(asn1cpp_wire::Tag, &[u8])> {\n";
            os << std::format("        match self {{ {}::UnknownExtension(tag, bytes) => Some((*tag, bytes.as_slice())), _ => None }}\n", spec.type_name);
            os << "    }\n";
        } else {
            os << "    fn construct_unknown_extension(&mut self, _tag: asn1cpp_wire::Tag, _bytes: Vec<u8>) {}\n";
            os << "    fn extract_unknown_extension(&self) -> ::std::option::Option<(asn1cpp_wire::Tag, &[u8])> { None }\n";
        }
        os << "}\n\n";

        // Whole-document root marker: every codec's top-level
        // `encode_pdu`/`decode_pdu` binds on it (`spec::object::Asn1Pdu`).
        os << std::format("impl asn1cpp_wire::spec::object::Asn1Pdu for {} {{}}\n\n", spec.type_name);

        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", spec.type_name);
        os << "    const TAG: ::std::option::Option<asn1cpp_wire::Tag> = None;\n";
        os << std::format("    fn choice_ber_tags() -> &'static [asn1cpp_wire::spec::choice::BerDispatch] {{ &{} }}\n", tags_ident);
        os << "}\n\n";
        os << std::format("impl asn1cpp_wire::spec::object::AsMemberRef for {} {{\n", spec.type_name);
        os << "    fn as_member_ref(&self) -> asn1cpp_wire::spec::object::MemberRef<'_> {\n";
        os << "        asn1cpp_wire::spec::object::MemberRef::Choice(self)\n";
        os << "    }\n\n";
        os << "    fn as_member_ref_mut(&mut self) -> asn1cpp_wire::spec::object::MemberRefMut<'_> {\n";
        os << "        asn1cpp_wire::spec::object::MemberRefMut::Choice(self)\n";
        os << "    }\n\n";
        os << std::format("    fn own_element_xer_name(&self) -> &'static str {{ {}.name }}\n", spec_ident);
        os << "}\n\n";
    }
}

void RustBackend::emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const {
    emit_choice_declaration(spec, session.buffer(declaration_extension()));
    emit_choice_definition(spec, session.buffer(definition_extension()));
}

/// @brief Emit the file-level doc comment for a generated module's
///        declaration output.
/// @param module_comment Pre-formatted "Module: X { oid }" text.
/// @param os Output stream to write to.
/// @note Rust has no include-guard/`#include` concept to replicate here —
///       unlike CppBackend's emit_declaration_preamble, this is a doc comment and
///       nothing else. The two-call (hpp preamble / cpp preamble) split this
///       method is part of bakes in C++'s header+impl file model, which
///       doesn't fit Rust — left as-is rather than redesigned, since
///       `declaration_extension()`/`definition_extension()` both resolving
///       to `"rs"` already makes both calls land in the same stream/file
///       for Rust, satisfying the contract without needing a separate split.
void RustBackend::emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const {
    auto& os = session.buffer(declaration_extension());
    os << "//! Module: " << module_comment << "\n\n";
    // Brings `AsMemberRef` into scope for the `self.0[i].as_member_ref()`
    // calls inside a named SEQUENCE OF/SET OF type's own `Asn1SeqOf` impl.
    // `as _` (no named binding) because some consumers `include!()` every
    // generated file into one flat module, where a repeated named `use`
    // would collide; `allow(unused_imports)` covers files with no such
    // call.
    os << "#[allow(unused_imports)]\nuse asn1cpp_wire::spec::object::AsMemberRef as _;\n\n";
}

/// @brief Emit the file-level preamble for a generated module's
///        implementation output.
/// @note Deliberately empty: Rust has nothing analogous to C++'s
///       `#include "X.hpp"` + GCC pragma pair here. See emit_declaration_preamble's
///       note — this is the concrete symptom of the two-file-model
///       mismatch, left unresolved by design
///       for this pairing.
void RustBackend::emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const {
    (void)declaration_filename;
    (void)session;
}

/// @brief Emit the opening of a `-fprefix` module wrapper.
/// @note Rust's module system (`mod`) is the natural analogue of C++'s
///       `namespace` here — real syntax, not a placeholder.
void RustBackend::emit_namespace_open(const std::string& name, TypeOutputSession& session) const {
    write_to_both(session, std::format("pub mod {} {{\n\n", name));
}

/// @brief Emit the closing of a `-fprefix` module wrapper.
void RustBackend::emit_namespace_close(const std::string& name, TypeOutputSession& session) const {
    (void)name;
    write_to_both(session, "\n}\n");
}

/// @brief Emit the declaration half of a builtin-alias type: a real newtype
///        wrapping the builtin's own native Rust type, not a plain `pub type
///        X = Y;` alias.
/// @note A plain alias is just another name for the same Rust type, and
///       trait impls are per-*type*, not per-alias — every named alias of
///       the same builtin (e.g. two different `::= OCTET STRING` aliases)
///       would share `Vec<u8>`'s own single `AsMemberRef` impl, whose
///       `own_element_xer_name()` can only ever return one fixed string,
///       losing each alias's own X.693 §12 per-element XER identity (found
///       on the real ETSI LI PS-PDU schema: `ProSeUEID ::= OCTET STRING`,
///       used as a `SET OF ProSeUEID` element, XER-encoded each element as
///       generic `<OCTET-STRING>` instead of `<ProSeUEID>`, diverging from
///       asn1c/C++ ground truth). A newtype is a genuinely distinct Rust
///       type, so it gets its own impl (`emit_builtin_alias_definition`) —
///       same reasoning `emit_seq_of_declaration`'s own doc gives for the
///       identical problem there. `Deref`/`DerefMut` to the native type
///       keep ergonomic access (`.len()`, indexing, ...) working without
///       needing `.0` everywhere.
void RustBackend::emit_builtin_alias_declaration(const BuiltinAliasSpec& spec, std::ostream& os) const {
    std::string native = native_builtin_type(spec.builtin_type);
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
    os << "#[allow(non_camel_case_types)]\n";
    os << std::format("pub struct {}(pub {});\n\n", spec.type_name, native);
    os << std::format("impl std::ops::Deref for {} {{\n", spec.type_name);
    os << std::format("    type Target = {};\n", native);
    os << "    fn deref(&self) -> &Self::Target { &self.0 }\n";
    os << "}\n\n";
    os << std::format("impl std::ops::DerefMut for {} {{\n", spec.type_name);
    os << "    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }\n";
    os << "}\n\n";
}

void RustBackend::emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const {
    emit_builtin_alias_declaration(spec, session.buffer(declaration_extension()));
    emit_builtin_alias_definition(spec, session.buffer(definition_extension()));
}

/// @brief Emit the declaration half of a SEQUENCE OF / SET OF type: a real
///        newtype wrapping `Vec<ElemType>`, not a plain alias.
/// @note `spec.elem_type` is treated as an opaque, already-Rust-shaped type
///       string — same "supplied by the caller" contract as every other
///       pairing (see e.g. emit_sequence_declaration's note). A newtype
///       (`pub struct X(pub Vec<ElemType>);`), not `pub type X =
///       Vec<ElemType>;`: a plain alias is just another name for the same
///       Rust type, and Rust trait impls are per-*type*, not per-alias —
///       `Vec<ElemType>` might be some *other* ASN.1 type's own native
///       storage too (OCTET STRING's `Vec<u8>`, another SEQUENCE OF with
///       the same element type), so it can't carry trait impls specific
///       to *this* ASN.1 type. A newtype is a genuinely distinct
///       Rust type, so it can — see emit_seq_of_definition's own doc for
///       that impl. `Deref`/`DerefMut` to `Vec<ElemType>` keep `.len()`/
///       `.iter()`/indexing working without needing `.0` everywhere.
void RustBackend::emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const {
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
    os << "#[allow(non_camel_case_types)]\n";
    os << std::format("pub struct {}(pub Vec<{}>);\n\n", spec.type_name, spec.elem_type);
    os << std::format("impl std::ops::Deref for {} {{\n", spec.type_name);
    os << std::format("    type Target = Vec<{}>;\n", spec.elem_type);
    os << "    fn deref(&self) -> &Self::Target { &self.0 }\n";
    os << "}\n\n";
    os << std::format("impl std::ops::DerefMut for {} {{\n", spec.type_name);
    os << "    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }\n";
    os << "}\n\n";
}

void RustBackend::emit_seq_of(const SeqOfSpec& spec, TypeOutputSession& session) const {
    emit_seq_of_declaration(spec, session.buffer(declaration_extension()));
    emit_seq_of_definition(spec, session.buffer(definition_extension()));
}

/// @brief Emit a plain type-reference alias (`MyType ::= OtherType`, X.680 §17).
void RustBackend::emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                          TypeOutputSession& session) const {
    session.buffer(declaration_extension()) << "#[allow(non_camel_case_types)]\n";
    session.buffer(declaration_extension()) << std::format("pub type {} = {};\n", type_name, target_type);
}

/// @brief Reference another generated type via its crate-relative module
///        path — assumes a generated crate root (main.cpp, --target=rust)
///        declares one module per generated file.
/// @note The module identifier is the type identifier itself, verbatim
///       (Backend::module_name's own doc — never snake_cased: that
///       would be a strictly more lossy transform than type_name's own,
///       letting two already-distinct type identifiers collide as
///       module names). `filename` here is
///       the on-disk file stem, always identical to `type_name` by
///       construction (see finalize_output's own `#[path = ...]`
///       declaration) — `escape()` still matters for the rare type
///       whose own name happens to match a Rust keyword exactly (not a
///       folded/lowercased collision, a literal one), same mechanism
///       member_name() already applies.
void RustBackend::emit_type_reference(const std::string& type_name, const std::string& filename,
                                       TypeOutputSession& session) const {
    session.buffer(declaration_extension())
        << std::format("use crate::{}::{};\n", escape(filename), type_name);
}

/// @brief Rust has no forward-declaration concept — a type is visible
///        regardless of declaration order once its module is `use`d.
void RustBackend::emit_forward_declaration(const std::string&, TypeOutputSession&) const {
}

/// @brief Rust's `Option<T>` needs no special member functions — no
///        equivalent of C++'s unique_ptr-deep-copy dance.
void RustBackend::emit_special_members(const std::string&, TypeOutputSession&) const {
}

/// @brief Rust's `Option<T>` needs no storage-ops helper type — same
///        rationale as emit_special_members.
void RustBackend::emit_optional_member_ops(const std::string&, const std::string&,
                                            const std::string&, TypeOutputSession&) const {
}

/// @brief Write the crate root: one module declaration per generated `.rs`
///        file, so the `use crate::<module>::<Type>;` paths
///        emit_type_reference emits actually resolve.
///        WIP: flat mod-per-file list, no module tree mirroring
///        ASN.1 modules.
/// @note The module *identifier* is the type identifier verbatim
///       (`pub mod ContactList;`), matching the on-disk PascalCase file
///       stem exactly — not a separately-folded snake_case name. The
///       resulting non_snake_case lint is suppressed per-declaration
///       below instead of reformatting the identifier (same ASN.1-
///       naming-fidelity convention as every other generated name).
///       emit_type_reference's `use` paths re-derive the same
///       `escape(stem)` so the two stay in sync without a second
///       source of truth.
void RustBackend::finalize_output(const std::string& out_dir) const {
    namespace fs = std::filesystem;
    fs::path lib_rs = fs::path(out_dir) / "lib.rs";
    std::ofstream lib(lib_rs);
    for (const auto& entry : fs::directory_iterator(out_dir)) {
        if (entry.path().extension() != ".rs" || entry.path() == lib_rs) continue;
        std::string stem = entry.path().stem().string();
        // Module identifiers are PascalCase (Backend::module_name's own
        // doc — the type identifier verbatim, not a separately-folded
        // name), which would otherwise trip rustc's non_snake_case lint.
        // An *outer* attribute per declaration, not a crate-level `#![...]`
        // inner attribute: this file isn't always literally the crate
        // root — some consumers `include!()` it into their own lib.rs
        // (e.g. the xval_sweep test harness), where an inner attribute at
        // this position is rejected outright ("an inner attribute is not
        // permitted in this context").
        lib << std::format("#[allow(non_snake_case)]\n#[path = \"{}.rs\"] pub mod {};\n", stem, escape(stem));
    }
}

} // namespace asn1::codegen
