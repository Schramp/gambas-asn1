#include "RustBackend.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <unordered_map>

namespace asn1::codegen {

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
// Rust convention wants UpperCamelCase enum variants (rustc lints
// non_camel_case_types otherwise — a warning, not a compile error, but
// worth doing idiomatically since it's free: ASN.1 ENUMERATED value names
// are lowercase-first by convention, X.680 §11.2, so this needs an explicit
// capitalize where CppBackend's C++ constant-in-class-scope style doesn't).
// to_upper_camel_case (real word-split conversion), not
// capitalize_first(type_name(...)) — the latter routes through
// to_cpp_name's hyphen->underscore substitution first, so a hyphenated
// multi-word value name (e.g. "eight-bit-binary") came out "Eight_bit_binary"
// instead of "EightBitBinary". Operates on the raw ASN.1 name directly,
// bypassing type_name(), so the hyphen is available to split on.
static std::string variant_name(const RustBackend& backend, const std::string& asn1_name) {
    return backend.escape(to_upper_camel_case(asn1_name));
}

// Per-builtin-kind lookup tables shared by
// emit_sequence_definition (SEQUENCE members, SEQUENCE OF elements) and
// emit_choice_definition (CHOICE alternatives) — previously three separate
// near-identical switches over ast::BuiltinType per function (six total).
// Hoisted to file scope so there's exactly one switch per question asked,
// not one per caller.

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
    case ast::BuiltinType::Integer:     return mtype == "i64" ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
    case ast::BuiltinType::Boolean:     return "asn1cpp_ber::boolean::BOOLEAN_TAG";
    case ast::BuiltinType::OctetString: return "asn1cpp_ber::octet_string::OCTET_STRING_TAG";
    case ast::BuiltinType::Null:        return "asn1cpp_ber::null::NULL_TAG";
    case ast::BuiltinType::Real:        return "asn1cpp_ber::real::REAL_TAG";
    case ast::BuiltinType::BitString:   return "asn1cpp_ber::bit_string::BIT_STRING_TAG";
    case ast::BuiltinType::ObjectIdentifier: return "asn1cpp_ber::oid::OBJECT_IDENTIFIER_TAG";
    case ast::BuiltinType::RelativeOid: return "asn1cpp_ber::relative_oid::RELATIVE_OID_TAG";
    case ast::BuiltinType::Ia5String:   return "asn1cpp_ber::strings::IA5_STRING_TAG";
    // The other 11 restricted-character-string kinds
    // (native_builtin_type maps each to its own rust-runtime/ber::strings
    // newtype, not plain String) — each newtype's Asn1Value impl checks its
    // own tag, matching the constant named here.
    case ast::BuiltinType::Utf8String:       return "asn1cpp_ber::strings::UTF8_STRING_TAG";
    case ast::BuiltinType::NumericString:    return "asn1cpp_ber::strings::NUMERIC_STRING_TAG";
    case ast::BuiltinType::PrintableString:  return "asn1cpp_ber::strings::PRINTABLE_STRING_TAG";
    case ast::BuiltinType::T61String:        return "asn1cpp_ber::strings::T61_STRING_TAG";
    case ast::BuiltinType::VisibleString:    return "asn1cpp_ber::strings::VISIBLE_STRING_TAG";
    case ast::BuiltinType::GeneralString:    return "asn1cpp_ber::strings::GENERAL_STRING_TAG";
    case ast::BuiltinType::GraphicString:    return "asn1cpp_ber::strings::GRAPHIC_STRING_TAG";
    case ast::BuiltinType::UniversalString:  return "asn1cpp_ber::strings::UNIVERSAL_STRING_TAG";
    case ast::BuiltinType::BmpString:        return "asn1cpp_ber::strings::BMP_STRING_TAG";
    case ast::BuiltinType::VideotexString:   return "asn1cpp_ber::strings::VIDEOTEX_STRING_TAG";
    case ast::BuiltinType::ObjectDescriptor: return "asn1cpp_ber::strings::OBJECT_DESCRIPTOR_TAG";
    case ast::BuiltinType::UtcTime:          return "asn1cpp_ber::strings::UTC_TIME_TAG";
    case ast::BuiltinType::GeneralizedTime:  return "asn1cpp_ber::strings::GENERALIZED_TIME_TAG";
    // An inline `ENUMERATED { ... }` member/element sets `mbuiltin` here
    // like any other builtin (a referenced top-level ENUMERATED type takes
    // the separate `!mbuiltin` TypeRef path instead, unaffected).
    case ast::BuiltinType::Enumerated:       return "asn1cpp_ber::enumerated::ENUMERATED_TAG";
    // Not yet covered — no Asn1Value impl in rust-runtime/ber for these
    // kinds yet, so a member of any of them falls back to struct-shape-only
    // codegen (no encode()/decode() at all if any member is uncovered).
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
    if (!mbuiltin) return mtype == "i64" ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
    if (*mbuiltin == ast::BuiltinType::Integer)
        // Same INTEGER_TAG regardless of storage width — the Rust *type*
        // varies (i64/u64/i128/ArbitraryInteger), the wire tag never does.
        // ARBITRARY now has a real impl too (integer::ArbitraryInteger) —
        // no exclusion needed.
        return "asn1cpp_ber::integer::INTEGER_TAG";
    return builtin_ber_tag(*mbuiltin, mtype);
}

// SIZE-check function generators (emit_builtin_alias_
// definition, emit_member_type_descriptor) generically emit `v.len()`
// for every SIZE-constrained builtin type, assuming a `Vec<T>`/`String`-
// like native storage type. BitString's own native type (`bit_string::
// BitString`) has no `.len()` — and even if it exposed one via `.bytes`,
// X.680's SIZE constraint on BIT STRING counts *bits*, not bytes
// (`asn1::BitString::validate` on the C++ side compares against
// `bit_count()`, never raw byte length) — so the expression itself has to
// differ, not just its spelling. Every other currently-SIZE-constrainable
// covered kind (OCTET STRING, the character-string kinds) genuinely does
// mean "length of the native storage" for its own native type, so `.len()`
// stays their correct expression.
static const char* size_check_len_expr(ast::BuiltinType bt) {
    return bt == ast::BuiltinType::BitString ? "v.bit_count()" : "v.len()";
}

/// @brief True for the 12 character-string builtins X.680 §51 SIZE
///        validation covers (gambas-asn1#465) — the same set
///        `Generator::build_member_type_descriptor_spec`'s
///        `sizeable_universal_tag` lambda maps to a universal tag, minus
///        OCTET STRING/BIT STRING (their own row-loop branch already
///        handles those, gambas-asn1#464). Every one of these newtypes
///        (or, for IA5String, bare `String`) `Deref`s to `String`
///        (`rust-runtime/ber/src/strings.rs`'s own module doc), so the
///        member-row loop's own `v.{mname}.len()` — byte length, matching
///        C++'s own `AsnString<N>::validate`, whose own doc notes this is
///        byte count "not characters for multi-byte encodings like
///        UTF-8", the same simplification carried over here — already
///        works uniformly across the set with no per-kind runtime code.
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

    os << "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n";
    os << "#[repr(i64)]\n";
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
        os << std::format("    {} = {},\n", vname, v.value);
    }
    if (spec.extensible)
        os << "    // extensible\n";
    os << "}\n\n";
}

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

        // Value/name table — mirrors CppBackend's asn_MAP_ (EnumSpec::entries,
        // TypeDescriptor.hpp) exactly: one static data table, consumed
        // generically by enumerated::xer_encode_enum/xer_decode_enum below
        // (no per-value logic in this generated file itself, table-driven
        // same as every SEQUENCE/CHOICE member table this backend emits).
        std::string map_ident = std::format("{}_MAP", to_screaming_snake_case(tname));
        os << std::format("static {}: [asn1cpp_ber::enumerated::EnumEntry; {}] = [\n",
                           map_ident, spec.values.size());
        for (const auto& v : spec.values) {
            os << std::format("    asn1cpp_ber::enumerated::EnumEntry {{ value: {}, name: \"{}\" }},\n",
                               v.value, v.asn1_name);
        }
        os << "];\n\n";

        // BER leg (matches every other Asn1Value impl this backend emits)
        // and XER leg (BASIC-XER EmptyElementBoolean-style content, same as
        // `bool`'s own Asn1Value impl above in this file — mirrors
        // EnumeratedXerHandler's member-embedded form,
        // runtime/src/XerCodec.cpp). Makes this type usable as a
        // SEQUENCE/CHOICE member the same way i64/bool/etc already are.
        // `as i64`/
        // TryFrom<i64> convert through the shared wire representation
        // (X.690 §8.4); the XER leg goes through {map_ident} instead —
        // BER's wire value and XER's value *name* are different
        // representations of the same table, not two independent lookups.
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", tname);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_ber::Tag {\n";
        os << "        asn1cpp_ber::enumerated::ENUMERATED_TAG\n";
        os << "    }\n\n";
        os << "    fn xer_element_name(&self) -> &'static str {\n";
        os << std::format("        \"{}\"\n", spec.xer_name);
        os << "    }\n\n";
        os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
        os << "        asn1cpp_ber::enumerated::encode_enumerated_content(out, *self as i64);\n";
        os << "    }\n\n";
        os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        *self = asn1cpp_ber::enumerated::decode_enumerated_content(content)?;\n";
        os << "        Ok(())\n";
        os << "    }\n\n";
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << std::format("        asn1cpp_ber::enumerated::xer_encode_enum(out, &{}, *self as i64);\n", map_ident);
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::enumerated::xer_decode_enum(r, &{})?;\n", map_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        // X.693 §9.3: as a SEQUENCE OF/SET OF element, ENUMERATED is a bare
        // `<value-name/>` with no type-name wrapper and no X.693 §12
        // identifier override — `xer_encode`/`xer_decode_into` above
        // already write/read exactly that shape (xer_encode_enum/
        // xer_decode_enum). Unlike CHOICE (see the generated CHOICE type's
        // own override further down), ENUMERATED still needs its own
        // leading `\n` + indent here — its `TypeDescriptor` isn't
        // CHOICE-shaped, so `SeqOfXerHandler`'s own `!edef.choice_spec`
        // check (`runtime/src/XerCodec.cpp`) still writes that leading
        // whitespace for it, same as any wrapped element.
        os << "    fn xer_encode_seqof_element(&self, out: &mut String, depth: usize, _name_override: std::option::Option<&str>) {\n";
        os << "        out.push('\\n');\n";
        os << "        out.push_str(&asn1cpp_ber::xer::indent(depth + 1));\n";
        os << "        self.xer_encode(out, depth + 1);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into_seqof_element(&mut self, r: &mut asn1cpp_ber::xer::XerReader, _name_override: std::option::Option<&str>) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        self.xer_decode_into(r)\n";
        os << "    }\n\n";
        // X.680 §20/§51 (gambas-asn1#468) — reuses {map_ident} (already
        // emitted above for BER/XER), same "table data, one generic
        // function, no per-type logic" shape #473's Constraints redesign
        // established. In practice unreachable through the normal decode
        // path (TryFrom<i64> already rejects an unrecognized wire value
        // before a Rust enum instance can exist — see
        // enumerated::validate_enum's own doc), but a real override, not
        // a stub, for parity with the other constraint kinds.
        os << "    fn validate(&self) -> i64 {\n";
        os << std::format("        asn1cpp_ber::enumerated::validate_enum(*self as i64, &{})\n", map_ident);
        os << "    }\n";
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

    os << std::format("pub type {} = {};\n\n", tname, native_int_type(spec.storage_kind));

    for (const auto& v : spec.named_values)
        os << std::format("pub const {}: i64 = {};\n", value_name(v.asn1_name), v.value);
    if (!spec.named_values.empty()) os << "\n";

    // `pub type X = i64/u64/i128;` is a real Rust type alias (not a
    // newtype) — X already has a real Asn1Value impl via whichever
    // primitive it resolves to, so a member typed via TypeRef to it is
    // fine to reference generically like any other composite type. ARBITRARY
    // storage resolves to `integer::ArbitraryInteger`, its own newtype with
    // a real BER impl (see that struct's own module doc) — same as every
    // other storage kind, no special-casing needed here.
}

void RustBackend::emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const {
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

void RustBackend::emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const {
    emit_integer_declaration(spec, session.buffer(declaration_extension()));
    emit_integer_definition(spec, session.buffer(definition_extension()));
}

/// @brief Map a builtin type to its Rust native type.
/// @param bt Built-in type tag (never SEQUENCE/CHOICE/TypeRef/INTEGER/
///           ENUMERATED — same precondition as CppBackend's equivalent).
/// @return Rust type name, e.g. `"Vec<u8>"`, `"String"`, `"bool"`.
/// @note `Ia5String` alone maps to plain `String` — it has its own
///       `Asn1Value for String` impl (`rust-runtime/ber/src/value.rs`),
///       kept as-is for ergonomics/backward compatibility.
///       The other 11 restricted-character-string kinds
///       map to their own `rust-runtime/ber::strings`
///       newtype (`NumericString`, `PrintableString`, ...) — a plain
///       `String` can only carry one `Asn1Value` impl, so a second string
///       kind can't reuse `Ia5String`'s without fighting over which tag to
///       check/write (see `strings.rs`'s module doc). `Vec<u8>` for OCTET
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
    case BT::Boolean:          return "bool";
    case BT::Real:             return "f64";
    case BT::Null:             return "()";
    case BT::BitString:        return "asn1cpp_ber::bit_string::BitString";
    case BT::OctetString:      return "asn1cpp_ber::octet_string::OctetString";
    case BT::ObjectIdentifier: return "asn1cpp_ber::oid::ObjectIdentifier";
    case BT::RelativeOid:      return "asn1cpp_ber::relative_oid::RelativeOid";
    case BT::Utf8String:       return "asn1cpp_ber::strings::Utf8String";
    case BT::NumericString:    return "asn1cpp_ber::strings::NumericString";
    case BT::PrintableString:  return "asn1cpp_ber::strings::PrintableString";
    case BT::T61String:        return "asn1cpp_ber::strings::T61String";
    case BT::Ia5String:        return "String";
    case BT::VisibleString:    return "asn1cpp_ber::strings::VisibleString";
    case BT::GeneralString:    return "asn1cpp_ber::strings::GeneralString";
    case BT::GraphicString:    return "asn1cpp_ber::strings::GraphicString";
    case BT::UniversalString:  return "asn1cpp_ber::strings::UniversalString";
    case BT::BmpString:        return "asn1cpp_ber::strings::BmpString";
    case BT::VideotexString:   return "asn1cpp_ber::strings::VideotexString";
    case BT::ObjectDescriptor: return "asn1cpp_ber::strings::ObjectDescriptor";
    case BT::UtcTime:          return "asn1cpp_ber::strings::UtcTime";
    case BT::GeneralizedTime:  return "asn1cpp_ber::strings::GeneralizedTime";
    case BT::Any:              return "Vec<u8>";
    default:                   return "Vec<u8>";  // Integer/Enumerated: unreachable here
    }
}

/// @brief Format a resolved `TagSpec` as an `asn1cpp_ber::tag::Tag` struct
///        literal. Mirrors `CppBackend::format_tag_literal`
///        — same input (backend-agnostic `TagSpec`), Rust struct-literal
///        syntax instead of C++'s. `Tag`/`TagClass` are both `pub` with
///        `pub` fields (`rust-runtime/ber/src/tag.rs`), constructible this
///        way from outside the crate; no named constant lookup needed
///        (unlike `rust_member_ber_tag` in `emit_sequence_definition`,
///        which picks a specific `..._TAG` constant per builtin type for
///        *natural* tags) since this covers arbitrary class/number/
///        constructed combinations, including EXPLICIT/IMPLICIT/auto-tag
///        context tags that have no named constant.
std::string RustBackend::format_tag_literal(const TypeTagSpec& tag_spec) const {
    static constexpr const char* kTagClassLiterals[4] = {
        "asn1cpp_ber::tag::TagClass::Universal", "asn1cpp_ber::tag::TagClass::Application",
        "asn1cpp_ber::tag::TagClass::Private", "asn1cpp_ber::tag::TagClass::Context"};
    return std::format("asn1cpp_ber::tag::Tag {{ class: {}, number: {}, constructed: {} }}",
                        kTagClassLiterals[tag_class_index(tag_spec.cls)], tag_spec.number,
                        tag_spec.constructed ? "true" : "false");
}

/// @brief Emit the `Asn1Value` impl for a builtin-alias newtype (see
///        `emit_builtin_alias_declaration`'s own doc for why it's a newtype
///        and not a plain alias), plus a size-check function if constrained.
/// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
/// @param os   Output stream to write to.
/// @note The impl delegates every method straight to the wrapped native
///       type's own `Asn1Value` impl (`self.0.method(...)`) except
///       `xer_element_name`, which returns this alias's own real ASN.1 name
///       (`spec.xer_name`) instead of the native type's fixed builtin
///       keyword — the one thing a bare `Vec<u8>`/`String`/etc. can't
///       provide per-alias. `spec.tag` (natural tag) is always present in
///       practice (see `BuiltinAliasSpec`'s own doc — never CHOICE). The
///       size-check function, when a SIZE constraint is present, is the
///       Rust analogue of the bounds baked into C++'s Constraints struct.
///       FROM-alphabet constraints are not validated by the generated
///       function (same "no runtime wiring yet" scope as the INTEGER
///       pairing's hi_is_large note).
void RustBackend::emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", tname);
    os << "    fn ber_natural_tag(&self) -> asn1cpp_ber::Tag {\n";
    os << std::format("        {}\n", spec.tag ? format_tag_literal(*spec.tag) : "self.0.ber_natural_tag()");
    os << "    }\n\n";
    os << "    fn xer_element_name(&self) -> &'static str {\n";
    os << std::format("        \"{}\"\n", spec.xer_name);
    os << "    }\n\n";
    os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
    os << "        self.0.ber_encode_content(out);\n";
    os << "    }\n\n";
    os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_ber::DecodeError> {\n";
    os << "        self.0.ber_decode_content(content)\n";
    os << "    }\n\n";
    // BASE64/utf8 (X.693 §21, ENCODING-CONTROL XER ... BASE64 <TypeName> /
    // legacy `<TypeName> OCTET STRING ::= base64`/`::= utf8`) replaces this
    // alias's own xer_encode/xer_decode_into with the matching helper
    // directly — OctetString itself has no per-instance encoding flag to
    // branch on (see octet_string.rs's own base64_encode/utf8_encode doc).
    if (spec.xer_encoding == ast::XerEncoding::Base64) {
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << "        out.push_str(&asn1cpp_ber::octet_string::base64_encode(&self.0));\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        self.0.0 = asn1cpp_ber::octet_string::base64_decode(&r.read_text_content());\n";
        os << "        Ok(())\n";
        os << "    }\n";
    } else if (spec.xer_encoding == ast::XerEncoding::Utf8) {
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << "        asn1cpp_ber::octet_string::utf8_encode(&self.0, out);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        self.0.0 = asn1cpp_ber::octet_string::utf8_decode(r)?;\n";
        os << "        Ok(())\n";
        os << "    }\n";
    } else {
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << "        self.0.xer_encode(out, depth);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        self.0.xer_decode_into(r)\n";
        os << "    }\n";
    }
    os << "}\n\n";

    if (!spec.has_size_constraint) return;

    std::string fname = escape(to_snake_case(tname) + "_size_ok");
    const char* len_expr = size_check_len_expr(spec.builtin_type);
    os << std::format("pub fn {}(v: &{}) -> bool {{\n", fname, native_builtin_type(spec.builtin_type));
    if (spec.size_bounded) {
        os << std::format("    ({0} as i64) >= {1} && ({0} as i64) <= {2}\n",
                           len_expr, spec.size_lower, spec.size_upper);
    } else {
        // Semi-constrained (SIZE(n..MAX)) — no upper cap, same rationale as
        // IntegerSpec's semi_constrained handling.
        os << std::format("    ({} as i64) >= {} // semi-constrained, no upper cap\n",
                           len_expr, spec.size_lower);
    }
    os << "}\n\n";
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
        rust_type = "bool";
        literal = spec.bool_val ? "true" : "false";
        break;
    case Kind::Int:
        rust_type = type_name;
        literal = std::format("{}", spec.int_val);
        break;
    case Kind::String:
        rust_type = "String";
        literal = std::format("\"{}\".to_string()", escape_string_literal(spec.string_val));
        break;
    case Kind::EnumRef:
        rust_type = type_name;
        literal = std::format("{}::{}", type_name, variant_name(*this, spec.enum_name));
        break;
    case Kind::None:
    default:
        return;
    }
    std::string fname = escape(to_snake_case(parent_name) + "_" + member_name + "_default");
    os << std::format("pub fn {}() -> {} {{\n    {}\n}}\n\n", fname, rust_type, literal);
}

/// @brief Emit a Rust bounds-check function for an inline-constrained
///        SEQUENCE/CHOICE member — INTEGER value range or SIZE-able-
///        primitive SIZE constraint.
/// @param spec Resolved, backend-agnostic decision (see MemberTypeDescriptorSpec).
/// @param os   Output stream to write to.
/// @note FROM-alphabet-only members and members whose only constraint is a
///       non-default XER encoding produce no Rust output — same "no runtime
///       wiring yet" scope as emit_builtin_alias_definition. `spec.tname` follows
///       CppBackend's static-variable naming convention
///       ("asn_TYP_Parent_member"); reused as the Rust fn name base via
///       to_snake_case, same coincidental-overlap rationale as type_name/
///       synthetic_name.
void RustBackend::emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const {
    std::ostream& os = session.buffer(definition_extension());
    using Kind = MemberTypeDescriptorSpec::Kind;
    std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(spec.tname));
    if (spec.kind == Kind::Integer) {
        // Plain `static` data, not a generated per-member function (#473
        // review: "all constraints should be table based ... never put it
        // in code" — a parser/tool should be able to read the bound
        // straight off this table without executing anything). Delta
        // convention, EXTENSIBLE handling, and the saturating i64 clamp
        // for U64 storage all live in `constraints::validate_s64`/
        // `validate_u64` (rust-runtime/ber/src/constraints.rs) — the only
        // code, identical for every member. Only INT_S64/INT_U64 storage
        // gets a table — INT_I128/INT_ARBITRARY are skipped (the member's
        // MemberDescriptor.validate is `None`), matching or exceeding the
        // C++ side's own correctness rather than replicating its latent
        // I128/ARBITRARY static_cast bug (Validate.hpp) in Rust too.
        if (spec.storage_kind == IntStorageKind::S64) {
            // hi_is_large's upper bound may exceed i64::MAX (X.691 §10.5.6,
            // e.g. UINT64_MAX) and isn't exactly representable as an i64
            // bound — treated as semi-constrained (lower-bound-only check)
            // rather than storing an incorrect upper bound.
            bool semi = spec.semi_constrained || spec.hi_is_large;
            int flags = (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0) |
                        (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED);
            os << std::format(
                "static {}: asn1cpp_ber::constraints::Constraints = asn1cpp_ber::constraints::Constraints {{\n"
                "    flags: {}, lower_bound: {}, upper_bound: {}, lower_u64: 0, upper_u64: 0, size_lower: 0, size_upper: 0, encode_table: None,\n"
                "}};\n\n",
                cname, flags, spec.lower_s64, spec.upper_s64);
        } else if (spec.storage_kind == IntStorageKind::U64) {
            int flags = (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0) |
                        (spec.semi_constrained ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED);
            os << std::format(
                "static {}: asn1cpp_ber::constraints::Constraints = asn1cpp_ber::constraints::Constraints {{\n"
                "    flags: {}, lower_bound: 0, upper_bound: 0, lower_u64: {}u64, upper_u64: {}u64, size_lower: 0, size_upper: 0, encode_table: None,\n"
                "}};\n\n",
                cname, flags, spec.lower_u64, spec.upper_u64);
        }
        return;
    }
    // Always emitted (not gated on has_size_constraint) whenever this
    // function runs at all — this spec can also get built for a
    // FROM-alphabet-only or custom-XER-only member with no SIZE constraint
    // (Generator::build_member_type_descriptor_spec's Sizeable branch:
    // `if (sr || !alphabet.empty() || needs_xer)`), and RustBackend's own
    // member-row loop only has `tdref`'s "&asn_TYP_..." prefix to tell
    // whether *some* spec was built for this member — not whether the
    // SIZE constraint within it is real. Keeping this table unconditional
    // (flags=0 when unconstrained, same as `Constraints::default()`) keeps
    // that one signal reliable for every Sizeable member uniformly,
    // matching the C++ side's own "always reference a Constraints value,
    // flags=0 makes it a no-op" pattern (Validate.hpp) — no second gate
    // needed, and `validate_size` already treats a missing
    // SIZE_CONSTRAINED bit as always-valid.
    // `size_bounded == false` (SIZE(n..MAX)) still gets SIZE_CONSTRAINED
    // set (unlike C++'s own Constraints, which only sets it for a finite
    // upper bound and so skips validation entirely for a semi-constrained
    // SIZE — see OctetString::validate/BitString::validate's own `if
    // (!(c.flags & SIZE_CONSTRAINED)) return 0;` gate) — the lower bound
    // is still real and worth checking; `size_upper` becomes `i64::MAX`
    // (via `INT64_MAX`) as a sentinel so `validate_size`'s upper check
    // never fires for a realistic element/byte/character count. A
    // deliberate, already-shipped (#464/#465) improvement over C++, not a
    // parity gap introduced here.
    int flags = spec.has_size_constraint
        ? (asn1::Constraints::SIZE_CONSTRAINED | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0))
        : 0;
    int64_t size_upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
    // X.680 §51.4 PermittedAlphabet (gambas-asn1#466) — `spec.alphabet` is
    // the resolved, sorted, deduplicated permitted-character set
    // (`Generator::extract_from_alphabet`); emitted as a plain 256-entry
    // lookup table (data, not code — same #473 review this whole redesign
    // follows), `encode_table[byte] = index in alphabet` or `0xFFFF` if
    // `byte` isn't permitted. `constraints::validate_alphabet`/
    // `validate_string` (rust-runtime/ber/src/constraints.rs) are the only
    // code, identical for every alphabet-constrained member.
    std::string encode_table_expr = "None";
    if (!spec.alphabet.empty()) {
        std::string enc_ident = std::format("{}_ENC", to_screaming_snake_case(spec.tname));
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
    }
    os << std::format(
        "static {}: asn1cpp_ber::constraints::Constraints = asn1cpp_ber::constraints::Constraints {{\n"
        "    flags: {}, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, size_lower: {}, size_upper: {}, encode_table: {},\n"
        "}};\n\n",
        cname, flags, spec.size_lower, size_upper, encode_table_expr);
}

/// @brief Emit a Rust size-check function for a SEQUENCE OF / SET OF type's
///        collection SIZE constraint (X.680 §25/26), plus its `Asn1Value` impl.
/// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
/// @param os   Output stream to write to.
/// @note `spec.elem_ref` is a C++ TypeDescriptor reference expression, not
///       usable by any other backend, so unused here. The size-check
///       function itself is generic over the element type (`Vec<T>`),
///       matching this issue's "likely Vec<T>" scoping note, and needs no
///       element type information to compile — even when unconstrained
///       (degenerates to a trivial `>= 0` check) rather than introducing a
///       has-constraint field SeqOfSpec doesn't otherwise need.
/// @note The `Asn1Value` impl always uses the real element type
///       (`spec.elem_type`), unlike the size-check function — every
///       generated SEQUENCE OF/SET OF newtype is always real now (same
///       "no gating, generic composite references are always safe"
///       reasoning `sequence_member_covered`'s own doc gives), so
///       `spec.elem_type: Asn1Value` is simply required to hold; a
///       genuinely uncoverable element type is out of this pairing's
///       scope (same as it always has been — this backend has never had a
///       gate for SEQUENCE OF *element* coverage at the top-level-type
///       granularity, only at the member-level SeqOf/TaggedSeqOf branches).
///       XER is always emitted too, unconditionally — encode_seq_of_xer/
///       decode_seq_of_xer (sequence.rs) derive the per-element X.693 §12
///       tag from each element's own `Asn1Value::xer_element_name()` at
///       runtime, so there's no per-type name to gate on here at all.
void RustBackend::emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const {
    // Plain `static` data, not a generated per-type function (#473 review)
    // — always emitted, real bounds or not: every generated SEQUENCE
    // OF/SET OF type gets one, including an anonymous inline member's
    // synthetic promoted type (`Generator::emit_seq_of_definition` runs
    // identically for both — see this pairing's own doc), so the
    // containing SEQUENCE's member-row loop (`emit_sequence_definition`)
    // can always find `{TYPE}_CONSTRAINTS` by the same deterministic name
    // it already derives for the field type, no extra signal needed. A
    // semi-constrained SIZE (`size_upper` absent) still gets
    // SIZE_CONSTRAINED set with `size_upper` as a sentinel `i64::MAX` —
    // `validate_size` (constraints.rs) then still checks the lower bound,
    // same already-shipped (#464/#465) improvement over C++'s own
    // Constraints (which skips validation entirely for a semi-constrained
    // SIZE — see OctetString::validate's own `SIZE_CONSTRAINED` gate).
    std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(spec.type_name));
    int flags = spec.has_size_constraint
        ? (asn1::Constraints::SIZE_CONSTRAINED | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0))
        : 0;
    int64_t size_upper = spec.size_upper.value_or(std::numeric_limits<int64_t>::max());
    // `pub`, unlike the member-inline Constraints tables above — a
    // synthetic promoted type's own table is referenced cross-module by
    // the containing SEQUENCE's row-loop (an inline member never has this
    // type as its field type directly, only the generic SeqOf<T>/SetOf<T>
    // wrapper — see that reference's own doc).
    os << std::format(
        "pub static {}: asn1cpp_ber::constraints::Constraints = asn1cpp_ber::constraints::Constraints {{\n"
        "    flags: {}, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, size_lower: {}, size_upper: {}, encode_table: None,\n"
        "}};\n\n",
        cname, flags, spec.size_lower, size_upper);

    std::string natural_tag = std::format("asn1cpp_ber::sequence::{}", spec.is_set_of ? "SET_TAG" : "SEQUENCE_TAG");
    // Honor a top-level [n] IMPLICIT/EXPLICIT tag on this type assignment
    // itself (X.690 §8.14) — same fix emit_sequence_definition already has.
    std::string tag_expr = spec.tag ? format_tag_literal(*spec.tag) : natural_tag;
    os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", spec.type_name);
    os << "    fn ber_natural_tag(&self) -> asn1cpp_ber::Tag {\n";
    os << std::format("        {}\n", tag_expr);
    os << "    }\n\n";
    os << "    fn xer_element_name(&self) -> &'static str {\n";
    os << std::format("        \"{}\"\n", spec.xer_name);
    os << "    }\n\n";
    os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
    os << "        asn1cpp_ber::sequence::encode_seq_of_content(out, &self.0);\n";
    os << "    }\n\n";
    os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_ber::DecodeError> {\n";
    os << "        self.0 = asn1cpp_ber::sequence::decode_seq_of_content(content)?;\n";
    os << "        Ok(())\n";
    os << "    }\n";
    // Always real now — encode_seq_of_xer/decode_seq_of_xer (sequence.rs)
    // derive the per-element X.693 §12 tag from each element's own
    // Asn1Value::xer_element_name() generically, same as the member-level
    // SeqOf/TaggedSeqOf emission (see that lambda's own doc). When this
    // type declared its own X.693 §12 element identifier
    // (`SEQUENCE OF id INTEGER`), spec.elem_xer_name carries it through to
    // the _named variant (ignored by ENUMERATED/CHOICE/NULL elements —
    // see Asn1Value::xer_encode_seqof_element's own doc, rust-runtime/ber).
    os << "\n";
    os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
    if (spec.elem_xer_name) {
        os << std::format("        asn1cpp_ber::sequence::encode_seq_of_xer_named(out, &self.0, depth, Some(\"{}\"));\n", *spec.elem_xer_name);
    } else {
        os << "        asn1cpp_ber::sequence::encode_seq_of_xer(out, &self.0, depth);\n";
    }
    os << "    }\n\n";
    os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
    if (spec.elem_xer_name) {
        os << std::format("        self.0 = asn1cpp_ber::sequence::decode_seq_of_xer_named(r, Some(\"{}\"))?;\n", *spec.elem_xer_name);
    } else {
        os << "        self.0 = asn1cpp_ber::sequence::decode_seq_of_xer(r)?;\n";
    }
    os << "        Ok(())\n";
    os << "    }\n";
    // `Asn1Value::validate()`'s default (`value.rs`) is `0` — this override
    // is only needed when there's a real SIZE constraint to check, unlike
    // `{cname}` above (always emitted, unconditionally, so the member-row
    // loop's name-derivation never has to guess whether it exists). Plain
    // trait override, not a MemberDescriptor fn-pointer: every named or
    // synthetic SEQUENCE OF/SET OF type is genuinely its own distinct Rust
    // type (unlike INTEGER's shared `i64`, #463), so it can carry its own
    // constraint directly, the way #462 originally intended.
    if (spec.has_size_constraint) {
        os << std::format("\n    fn validate(&self) -> i64 {{\n        asn1cpp_ber::constraints::validate_size(self.0.len(), &{})\n    }}\n", cname);
    }
    os << "}\n\n";
}

/// @brief Is `mtype` a `Vec<T>` (T != u8) reference — a type with no
///        `Asn1Value` impl at all? Pure string check on the resolved Rust
///        type, order-independent (no registration/lookup-by-declaration-
///        name needed): a named top-level SEQUENCE OF/SET OF alias
///        (`m.mtype == "MySeqOf"`, e.g.) never has this shape at all —
///        `emit_seq_of_declaration` gives it a real newtype with its own
///        `Asn1Value` impl, referenced by name, not resolved-through
///        `"Vec<...>"` text — but an anonymous inline
///        SEQUENCE OF/SET OF member (whose type Generator resolves
///        directly to the raw `"Vec<i64>"` text, never through a synthetic
///        alias name, even though it also generates one as a side artifact
///        for the size-check function) is only catchable this way. Only
///        `Vec<u8>` is excluded — OCTET STRING's own real impl.
static bool rust_mtype_is_unusable_vec(const std::string& mtype) {
    return mtype.rfind("Vec<", 0) == 0 && mtype != "Vec<u8>";
}

/// @brief A CHOICE alternative's `mtype`, rewritten to wrap a bare
///        `Vec<T>` — `rust_mtype_is_unusable_vec`'s own doc: the only
///        source of that shape is `native_member_type_for`'s is_seq_of/is_set_of
///        branches (both format identically via `wrap_collection_type`,
///        indistinguishable from the text alone — this covers a SET OF
///        alternative too, not just SEQUENCE OF; harmless, since a CHOICE
///        alternative always dispatches through its own resolved tag, see
///        `SeqOf<T>`'s own doc) — in the generic
///        `asn1cpp_ber::sequence::SeqOf<T>` (rust-runtime/ber/src/sequence.rs),
///        whose single blanket `impl<T: Asn1Value + Default> Asn1Value for
///        SeqOf<T>` gives it a real impl `Vec<T>` itself can't
///        (coherence-blocked). Only applies where `choice_alternative_covered`
///        consults it, CHOICE alternatives — a SEQUENCE/SET member's own
///        field type is computed separately, `rust_seqof_member_field_type`
///        below, since it needs to pick `SetOf<T>` over `SeqOf<T>` for a
///        real SET OF member (the CHOICE-alt case never needs to, per this
///        function's own doc). Every other mtype passes through unchanged.
static std::string rust_seqof_alt_mtype(const std::string& mtype) {
    if (!rust_mtype_is_unusable_vec(mtype)) return mtype;
    return std::format("asn1cpp_ber::sequence::SeqOf<{}>", mtype.substr(4, mtype.size() - 5));
}

/// @brief The unwrapped element type text for a SEQUENCE OF/SET OF member.
///        `m.mtype` is always exactly `"Vec<ElemType>"` for such a member —
///        `native_member_type_for`'s own is_seq_of/is_set_of branches always route
///        through `wrap_collection_type` (Backend.hpp) — the same shape
///        `rust_seqof_alt_mtype` above unwraps for a CHOICE alternative.
///        Recurses per `ElemShape` (Backend.hpp) when the element is
///        itself a nested SEQUENCE OF/SET OF, rewrapping each nesting
///        level in the *correct* `SeqOf<T>`/`SetOf<T>` — text alone can't
///        tell SEQUENCE OF from SET OF at any depth (both render
///        identically as `"Vec<...>"`), so `ElemShape` supplies the fact
///        the text itself can't.
/// @param mtype One level of raw placeholder text still to resolve.
/// @param shape This level's element shape — SeqOfKind::None is the base
///              case (leaf: builtin/composite text, already correct).
static std::string rust_wrap_elem_shape(const std::string& mtype, const ElemShape& shape) {
    if (shape.kind == SeqOfKind::None) return mtype;
    std::string inner_mtype = mtype.substr(4, mtype.size() - 5);  // strip this level's "Vec<...>"
    std::string inner = shape.nested ? rust_wrap_elem_shape(inner_mtype, *shape.nested) : inner_mtype;
    return std::format("asn1cpp_ber::sequence::{}<{}>",
                        shape.kind == SeqOfKind::SeqOf ? "SeqOf" : "SetOf", inner);
}

static std::string rust_seqof_elem_mtype(const SequenceMemberSpec& m) {
    return rust_wrap_elem_shape(m.mtype.substr(4, m.mtype.size() - 5), m.elem_shape);
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
///        (`rust-runtime/ber/src/sequence.rs`) instead of a raw
///        `Vec<ElemType>`, which has no `Asn1Value` impl of its own
///        (coherence-blocked, same reasoning `rust_seqof_alt_mtype`'s own
///        doc gives). Once the field itself implements `Asn1Value`, the
///        member-table emission below needs no dedicated SeqOf-shaped
///        closures at all — it falls through to the same
///        Scalar/TaggedScalar/ExplicitScalar dispatch every other
///        composite member already uses. Every other member's `mtype`
///        passes through unchanged.
static std::string rust_seqof_member_field_type(const SequenceMemberSpec& m) {
    switch (m.seq_of_kind) {
    case SeqOfKind::SeqOf: return std::format("asn1cpp_ber::sequence::SeqOf<{}>", rust_seqof_elem_mtype(m));
    case SeqOfKind::SetOf: return std::format("asn1cpp_ber::sequence::SetOf<{}>", rust_seqof_elem_mtype(m));
    case SeqOfKind::None:  return m.mtype;
    }
    return m.mtype;
}

/// @brief Emit the Rust struct declaration for a SEQUENCE/SET type.
/// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
/// @param os   Output stream to write to.
/// @note `spec.members[i].mtype` is treated as an opaque, already-Rust-
///       shaped type name string, always a real `Generator::native_member_type_for()`
///       value under `--target=rust`. `ops`/`tdref`/`def_setter`/`offset_expr` are
///       C++-runtime-only (per SequenceMemberSpec's own doc) and unused
///       here; optional members become `Option<T>` rather than C++'s
///       `unique_ptr<T>`, Rust's natural equivalent.
/// @brief Does `m` get a real access closure (Scalar/TaggedScalar/
///        ExplicitScalar/SeqOf/ExplicitAny), or an `Unsupported` stub?
///        Every SEQUENCE/SET always gets a full table now regardless of the
///        answer (see `sequence::MemberAccess::Unsupported`'s doc,
///        rust-runtime/ber) — this only decides this one row's shape.
/// @note `mbuiltin` unset means the member's type is a TypeRef to
///       something else entirely — SEQUENCE/SET/CHOICE, ENUMERATED, or a
///       plain INTEGER subtype alias. Any such reference is always real:
///       `Asn1Value` is object-safe, and the referenced type is guaranteed
///       to implement it (really or as a stub) regardless of processing
///       order, so there's nothing to look up in advance. The one
///       exception is presence detection, not trait coverage: an OPTIONAL
///       member whose type is a genuinely untagged CHOICE (X.680 §28, no
///       AUTOMATIC TAGS, no fixed tag at all) has no `Tag` to peek for at
///       all — that's a missing dispatch key, not a missing impl, and no
///       stub closure can safely guess presence, so it becomes
///       `Unsupported` too (unconditional panic, no attempted peek — see
///       the stub's own doc). A required member has no such problem
///       (nothing to peek for a required field either way). Every named
///       type — a top-level SEQUENCE OF/SET OF alias, an INTEGER of any
///       storage kind including ARBITRARY — gets its own real newtype with
///       a real `Asn1Value` impl (`emit_seq_of_declaration`,
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
        return !m.optional || m.resolved_tag.has_value();
    return rust_tag_for_builtin_or_alias(m.mbuiltin, m.storage_kind, m.mtype) != nullptr;
}

/// @brief CHOICE alternative analogue of sequence_member_covered —
///        does `a` get a real access closure (vs an `Unsupported` stub)?
///        Only meaningful once `a` is already known to have a resolved
///        tag (`choice_alternative_has_tag`, checked separately) — a
///        row's own tag is what `decode_choice`'s linear tag scan uses to
///        even reach it at all, real or stub.
bool RustBackend::choice_alternative_covered(const ChoiceAlternativeSpec& a) const {
    // A SEQUENCE OF or SET OF alternative always covers here
    // (rust_seqof_alt_mtype's own doc — both shapes format identically):
    // its mtype gets wrapped in SeqOf<T> at every emission site below, so
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
///        the generated encode()/decode(), same as `encode_choice`'s
///        existing "no alternative matched" panic already covers for any
///        other codegen/table mismatch). The one case this actually
///        excludes: an alternative whose own type is itself a genuinely
///        untagged CHOICE (X.680 §28, no AUTOMATIC TAGS, no fixed tag at
///        all) — CHOICE alternatives have no OPTIONAL concept to fall back
///        on the way a SEQUENCE member's presence-detection gap does.
bool RustBackend::choice_alternative_has_tag(const ChoiceAlternativeSpec& a) const {
    return a.resolved_tag.has_value();
}

void RustBackend::emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const {
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
    os << std::format("pub struct {} {{\n", spec.type_name);
    for (const auto& m : spec.members) {
        // A member whose class type cycles back to this
        // enclosing type needs `Box<T>` — Rust (unlike C++'s
        // pointer-by-default unique_ptr) gives a plain `T`/`Option<T>`
        // field no heap indirection at all, so a genuine ASN.1
        // self-referential/mutually-recursive type chain is an
        // infinite-size struct without it. Not applied to every class-typed
        // member (see SequenceMemberSpec::member_type_in_cycle's doc,
        // Backend.hpp, for why unconditional boxing — mirroring C++'s own
        // unrelated unique_ptr-everywhere convention — was rejected).
        std::string mtype = rust_seqof_member_field_type(m);
        std::string ftype = m.member_type_in_cycle ? std::format("Box<{}>", mtype) : mtype;
        os << std::format("    pub {}: {},\n", m.mname,
                           m.optional ? std::format("Option<{}>", ftype) : ftype);
    }
    os << "}\n\n";
}

/// @brief Emit an inherent `impl` block for a SEQUENCE/SET type.
/// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
/// @param os   Output stream to write to.
/// @note Scope is "struct + fields" per this pairing — no setter/validation
///       machinery (Rust's `pub` fields + `Option<T>` don't need C++'s
///       unique_ptr-based setter dance); a real `new()` that just delegates
///       to the struct's own `#[derive(Default)]`, not a stub.
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
    // `sequence::MemberAccess::Unsupported`'s doc, rust-runtime/ber, and
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
    // `rust_tag_for_builtin_or_alias` routes the Integer case through
    // `storage_kind` (a real enum) rather than `builtin_ber_tag`'s own
    // `mtype == "i64"` string check, which only ever matched the S64
    // default — Asn1Value now has real impls for i64/u64/i128/
    // ArbitraryInteger alike, so every storage kind gets the same
    // INTEGER_TAG unconditionally, no gating needed.
    auto rust_member_ber_tag = [](const SequenceMemberSpec& m) -> const char* {
        return rust_tag_for_builtin_or_alias(m.mbuiltin, m.storage_kind, m.mtype);
    };
    // Human-readable reason baked into an Unsupported row's stub panic
    // message — best-effort diagnosability, not meant to be exhaustive.
    auto stub_reason = [](const SequenceMemberSpec& m) -> const char* {
        if (m.seq_of_kind != SeqOfKind::None) return "SEQUENCE OF/SET OF element type/tag/optionality combination not yet supported";
        if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) return "untagged ANY has no tag to detect presence";
        if (!m.mbuiltin) return "OPTIONAL member of an untagged type has no tag to detect presence";
        return "builtin type/storage combination not yet supported";
    };
    {
        // Emitted unconditionally, even for an empty SEQUENCE {} (0
        // members, e.g. an ASN.1 extension-marker placeholder like
        // `criticalExtensions SEQUENCE {}` — X.680 §24 permits a SEQUENCE
        // with no components at all). A 0-length `[MemberDescriptor<T>; 0]`
        // is a perfectly ordinary Rust array; the real bug this guard used
        // to cause was withholding the whole Asn1Value impl below for a
        // 0-member type, which breaks the moment that type is used as a
        // composite member/alternative elsewhere (a deeply nested anonymous
        // CHOICE-in-CHOICE can promote exactly such a type — C++'s
        // CppBackend never had this guard).
        std::string members_ident = std::format("{}_MEMBERS", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::sequence::MemberDescriptor<{}>; {}] = [\n",
                          members_ident, spec.type_name, spec.members.size());
        for (const auto& m : spec.members) {
            os << "    asn1cpp_ber::sequence::MemberDescriptor {\n";
            os << std::format("        name: \"{}\",\n", m.asn1_name);
            // DEFAULT value (X.680 §25.1) — `m.has_default` alone doesn't
            // guarantee `Generator::emit_default_setter` actually emitted a
            // `_default()` function for it (a default value kind it can't
            // represent leaves `m.def_setter == "nullptr"`, same sentinel
            // CppBackend itself already gates on — see its own `has_default
            // && def_setter != "nullptr"` check); only the function-name
            // *text* is C++-only (`&_setdef_...`), so this reuses the
            // boolean signal without needing a new Generator.cpp field.
            // `emit_default_setter` (above) already emitted the real
            // `{parent}_{member}_default()` free function under this exact
            // name whenever this condition holds.
            std::string set_default_expr = "None";
            std::string is_default_equal_expr = "None";
            if (m.has_default && m.def_setter != "nullptr") {
                std::string fname = escape(std::format("{}_{}_default", to_snake_case(spec.type_name), m.mname));
                set_default_expr = std::format("Some(|v| v.{} = Some({}()))", m.mname, fname);
                // X.690 §11.5 — a member whose value equals the schema
                // DEFAULT must not be encoded (mirrors CppBackend's own
                // `_isdef_...` gate / MemberDescriptor::is_default_equal,
                // TypeDescriptor.hpp, consulted by SequenceBerHandler::
                // encode, BerCodec.cpp — real gap found only by an X2B/B2X
                // byte-identity check against the C++ runtime, not caught
                // by any XER-shaped verification).
                is_default_equal_expr = std::format("Some(|v| v.{} == Some({}()))", m.mname, fname);
            }
            if (!sequence_member_covered(m)) {
                os << "        tag: asn1cpp_ber::sequence::SEQUENCE_TAG,\n";
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_ber::sequence::MemberAccess::Unsupported {{ reason: \"{}\" }},\n", stub_reason(m));
            } else if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) {
                // `[n] ANY` — always EXPLICIT (sequence_member_covered
                // only lets this branch's precondition through when so).
                // Raw-capture pair, not the generic Asn1Value-based
                // ExplicitScalar path: the field is `Vec<u8>`, but holds an
                // unparsed captured TLV, not OCTET STRING content, so it
                // can't go through `Vec<u8>`'s own Asn1Value impl.
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                // value::encode_explicit_any_opt/encode_explicit_any keep
                // this closure a one-line call either way — the Some/None
                // presence check for the optional case lives in the
                // runtime function, not duplicated here (see
                // encode_explicit_opt's doc, value.rs).
                os << "        access: asn1cpp_ber::sequence::MemberAccess::ExplicitAny {\n";
                if (m.optional) {
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::value::encode_explicit_any_opt(out, {1}, &v.{0}),\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = Some(asn1cpp_ber::value::decode_explicit_any(r, {1})?); Ok(()) }},\n", m.mname, tag_lit);
                } else {
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::value::encode_explicit_any(out, {1}, &v.{0}),\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = asn1cpp_ber::value::decode_explicit_any(r, {1})?; Ok(()) }},\n", m.mname, tag_lit);
                }
                os << "        },\n";
            } else if (m.resolved_tag && m.is_explicit && m.resolved_tag->tag_is_override) {
                // EXPLICIT tagging (X.690 §8.14.3) — wraps the member's
                // natural Asn1Value encoding in a constructed outer TLV via
                // Asn1Value::ber_encode_explicit/ber_decode_into_explicit
                // (value.rs), rather than substituting the tag like the
                // IMPLICIT branch below. `MemberAccess::ExplicitScalar` has
                // no closures of its own (same as TaggedScalar just below)
                // — the walker calls those two generically using this row's
                // own `tag` field, one runtime pair covering every member
                // the natural Scalar path already covers. Only a real `[n]`
                // written on this member itself (tag_is_override) reaches
                // here — a bare type reference to an already-EXPLICIT-
                // tagged type (e.g. a member naming `T4 ::= [53] CHOICE
                // {...}` with no `[n]` of its own) falls through to the
                // plain-delegate `else` branch below instead: that type's
                // own Asn1Value impl already wraps itself, and a second
                // wrap here would double it (X.680 §30.1/30.3 — no
                // TaggedType construction on this member means no extra
                // layer).
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_ber::sequence::MemberAccess::ExplicitScalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
            } else if (m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit) {
                // IMPLICIT retag (X.690 §8.14.2) — same content,
                // different outer tag. `MemberAccess::TaggedScalar` has no
                // closures of its own (unlike before this comment): the
                // walker (encode_sequence_content/decode_sequence_content,
                // sequence.rs) calls `Asn1Value::ber_encode_tagged`/
                // `ber_decode_into_tagged` generically using this row's own
                // `tag` field — one runtime method covers every kind
                // (builtin scalar, SEQUENCE/SET, ENUMERATED, TypeRef-aliased
                // INTEGER), no per-kind dispatch needed in codegen at all.
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_ber::sequence::MemberAccess::TaggedScalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
            } else {
                // A member whose type is a TypeRef (mbuiltin unset)
                // reaches here either with its natural tag
                // (SEQUENCE_TAG/SET_TAG/ENUMERATED_TAG, or an
                // EXPLICIT-forced CHOICE tag already handled above) or —
                // required-only, per sequence_member_covered —
                // genuinely tagless (an untagged CHOICE, X.680 §28: no
                // AUTOMATIC TAGS, no universal tag). A required member's
                // MemberDescriptor.tag is never consulted at decode time
                // (only OPTIONAL presence-peek reads it), so the
                // placeholder in that last case is inert, not a claim
                // this member actually carries tag [0].
                std::string tag_text = !m.mbuiltin
                    ? (m.resolved_tag ? format_tag_literal(*m.resolved_tag)
                                       : "asn1cpp_ber::sequence::SEQUENCE_TAG /* untagged CHOICE member: no fixed tag, inert for required members */")
                    : rust_member_ber_tag(m);
                os << std::format("        tag: {},\n", tag_text);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_ber::sequence::MemberAccess::Scalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
            }
            os << std::format("        set_default: {},\n", set_default_expr);
            os << std::format("        is_default_equal: {},\n", is_default_equal_expr);
            // `emit_member_type_descriptor` (above) already emitted a
            // `static ... Constraints` table for a direct INTEGER/Sizeable
            // member with an inline X.680 §19/§25/§26/§51 constraint —
            // only INT_S64/INT_U64 storage gets one for INTEGER (see that
            // emitter's own doc). No dedicated field needed to detect
            // this: `tdref` (already set on every row, both backends) is
            // `"&" + tname` — the exact "asn_TYP_{parent}_{member}" text —
            // only when `build_member_type_descriptor_spec` actually built
            // a spec for this member; the plain/TypeRef-aliased/no-
            // constraint fallback (`cpp_type_descriptor_ref_for`) never
            // produces that prefix. `cname` itself is recomputed from
            // `tname`'s deterministic naming, not read back off stored
            // data — same table `constraints::validate_s64`/`validate_u64`/
            // `validate_size` (rust-runtime/ber/src/constraints.rs) read,
            // never a per-member generated function (#473 review).
            // `m.optional` also covers a DEFAULT-valued member (X.680
            // §25.1: `Generator::collect` passes `m->is_optional()`, true
            // for both markers) — its Rust field is `Option<T>` too (see
            // the `Option<{}>` wrapping just above), so the closure needs
            // to unwrap either way. A `None` field (genuinely absent
            // OPTIONAL member, or a DEFAULT member not yet filled at the
            // point this closure could in principle run) reports "valid"
            // (`0`) — same "nothing to check" contract
            // `encode_sequence_content`/`decode_sequence_content`
            // (`sequence.rs`) already give a `set_default`-less absent
            // member.
            std::string validate_expr = "None";
            if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Integer &&
                m.tdref.starts_with("&asn_TYP_") &&
                (m.storage_kind == IntStorageKind::S64 || m.storage_kind == IntStorageKind::U64)) {
                std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(std::format("asn_TYP_{}_{}", spec.type_name, m.mname)));
                const char* fn = m.storage_kind == IntStorageKind::S64 ? "validate_s64" : "validate_u64";
                validate_expr = m.optional
                    ? std::format("Some(|v| v.{}.map_or(0, |x| asn1cpp_ber::constraints::{}(x, &{})))", m.mname, fn, cname)
                    : std::format("Some(|v| asn1cpp_ber::constraints::{}(v.{}, &{}))", fn, m.mname, cname);
            } else if (m.mbuiltin && (*m.mbuiltin == ast::BuiltinType::OctetString || *m.mbuiltin == ast::BuiltinType::BitString) &&
                       m.tdref.starts_with("&asn_TYP_")) {
                std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(std::format("asn_TYP_{}_{}", spec.type_name, m.mname)));
                const char* method = *m.mbuiltin == ast::BuiltinType::BitString ? "bit_count" : "len";
                validate_expr = m.optional
                    ? std::format("Some(|v| v.{}.as_ref().map_or(0, |x| asn1cpp_ber::constraints::validate_size(x.{}(), &{})))",
                                   m.mname, method, cname)
                    : std::format("Some(|v| asn1cpp_ber::constraints::validate_size(v.{}.{}(), &{}))", m.mname, method, cname);
            } else if (m.mbuiltin && is_sizeable_string_kind(*m.mbuiltin) && m.tdref.starts_with("&asn_TYP_")) {
                // X.680 §51.4 FROM alphabet (gambas-asn1#466), combined with
                // SIZE via `constraints::validate_string` — the table
                // (`{cname}`, above) may or may not have a real
                // `encode_table`; `validate_string`/`validate_alphabet`
                // treat `None` as "no FROM constraint" uniformly, so this
                // wiring is identical whether the member actually has a
                // FROM clause or not, same "always wire, table decides"
                // shape the other constraint kinds use. `&str` coercion
                // chains through the newtype's own `Deref<Target=String>`
                // (`strings.rs`) automatically — no explicit `.as_str()`
                // needed, works for bare `String` (IA5String) too.
                std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(std::format("asn_TYP_{}_{}", spec.type_name, m.mname)));
                validate_expr = m.optional
                    ? std::format("Some(|v| v.{}.as_ref().map_or(0, |x| asn1cpp_ber::constraints::validate_string(x, &{})))", m.mname, cname)
                    : std::format("Some(|v| asn1cpp_ber::constraints::validate_string(&v.{}, &{}))", m.mname, cname);
            } else if (m.seq_of_kind != SeqOfKind::None) {
                // Inline SEQUENCE OF/SET OF member: the field's own Rust
                // type is the generic `SeqOf<T>`/`SetOf<T>` wrapper (shared
                // across every inline collection member, coherence-blocked
                // from a bare `Vec<T>` impl — `SeqOf<T>`'s own doc), not a
                // distinct type each member could carry its own
                // `Asn1Value::validate()` override on — same reason
                // INTEGER/OCTET STRING need `MemberDescriptor::validate`
                // instead of a trait override. `Generator::collect` always
                // promotes an inline SEQUENCE OF/SET OF member to its own
                // synthetic named type as a side effect (`synthetic_name`
                // below reproduces that exact name), and
                // `emit_seq_of_definition` (above) always emits that
                // synthetic type's own `..._CONSTRAINTS` table
                // unconditionally — real bounds or `flags: 0` — so this
                // reference is always valid, constrained or not.
                //
                // Fully qualified (`crate::{module}::{const}`), not a bare
                // reference: the synthetic type lives in its own generated
                // file/module (`Generator::emit_seq_of` runs it through its
                // own `TypeOutputSession`, separate from this SEQUENCE's
                // own), and this is the first thing in this file that ever
                // references it by name — `needs_seqof_wrapper_reference()`
                // is `false` for Rust (the field itself never names the
                // synthetic type, only the generic wrapper), so Generator's
                // own `use crate::X;` bookkeeping was never told to emit
                // one here. Fully qualifying sidesteps needing a `use` line
                // at all; the module name is the same `to_snake_case` of
                // the synthetic type name every other cross-module
                // reference in this codebase already derives it as.
                std::string synth = synthetic_name(spec.type_name, m.asn1_name);
                std::string cname = std::format("crate::{}::{}_CONSTRAINTS", to_snake_case(synth),
                                                 to_screaming_snake_case(synth));
                validate_expr = m.optional
                    ? std::format("Some(|v| v.{}.as_ref().map_or(0, |x| asn1cpp_ber::constraints::validate_size(x.len(), &{})))",
                                   m.mname, cname)
                    : std::format("Some(|v| asn1cpp_ber::constraints::validate_size(v.{}.len(), &{}))", m.mname, cname);
            }
            os << std::format("        validate: {},\n", validate_expr);
            os << "    },\n";
        }
        os << "];\n\n";

        // pub, not private static — a composite member
        // elsewhere (a different generated module) needs to name this SPEC
        // directly (encode_sequence_tagged/decode_sequence_tagged) when this
        // type is IMPLICITLY retagged as one of its members.
        os << std::format(
            "pub static {}: asn1cpp_ber::sequence::SequenceSpec<{}> = asn1cpp_ber::sequence::SequenceSpec {{\n",
            spec_ident, spec.type_name);
        // The real ASN.1/XER element name (spec.xer_name — may contain
        // hyphens the Rust identifier spec.type_name had to strip, e.g.
        // "PS-PDU"), not the Rust type name: this `name` field is the XER
        // wrapper tag text (encode_sequence_xer/decode_sequence_xer,
        // xer.rs), the same string Asn1Value::xer_element_name() already
        // reports for this type when nested as a composite member
        // elsewhere — using spec.type_name here diverged from that and
        // produced the wrong wrapper tag for any hyphenated ASN.1 name.
        os << std::format("    name: \"{}\",\n", spec.xer_name);
        // SET's own natural tag (universal 17), not
        // SEQUENCE's (16) — same distinction CppBackend's own
        // emit_sequence_definition already makes (spec.is_set), just never
        // threaded through here before now.
        // Honor a top-level [n] IMPLICIT/EXPLICIT tag on
        // this type assignment itself (X.690 §8.14) — same fix CppBackend
        // already has for this same case.
        os << std::format("    tag: {},\n",
                          spec.tag ? format_tag_literal(*spec.tag)
                                   : std::format("asn1cpp_ber::sequence::{}", spec.is_set ? "SET_TAG" : "SEQUENCE_TAG"));
        os << std::format("    members: &{},\n", members_ident);
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_ber::sequence::encode_sequence(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::sequence::decode_sequence(&{}, data)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn encode_xer(&self) -> String {\n";
        os << std::format("        asn1cpp_ber::xer::encode_sequence_xer(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::xer::decode_sequence_xer(&{}, xml)\n", spec_ident);
        os << "    }\n";
        os << "}\n\n";

        // Makes this type usable as a nested composite member elsewhere —
        // emitted unconditionally whenever this type has at least one
        // member, same as the table above. A member/alternative referencing
        // this type never needs to check anything about it in advance (see
        // sequence_member_covered's own doc) — it's always real,
        // BER and XER both; any individual member row that isn't itself
        // representable yet is an Unsupported stub (panics only if actually
        // reached), not a reason to withhold this whole impl.
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_ber::Tag {\n";
        os << std::format("        {}.tag\n", spec_ident);
        os << "    }\n\n";
        os << "    fn xer_element_name(&self) -> &'static str {\n";
        os << std::format("        \"{}\"\n", spec.xer_name);
        os << "    }\n\n";
        os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_ber::sequence::encode_sequence_content(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        let mut r = asn1cpp_ber::Reader::new(content);\n";
        os << std::format("        *self = asn1cpp_ber::sequence::decode_sequence_content(&{}, &mut r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << std::format("        asn1cpp_ber::xer::encode_sequence_xer_into(&{}, self, out, depth);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::xer::decode_sequence_xer_from(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n";
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
    os << "#[derive(Debug, Clone, PartialEq)]\n";
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
        os << std::format("    {}({}{}{}),\n", vname,
                          boxed ? "Box<" : "", rust_seqof_alt_mtype(a.mtype), boxed ? ">" : "");
    }
    // A `...`-marked CHOICE (X.680 §29.6) promises a future schema revision
    // may add alternatives this compiler run never saw. Every real
    // alternative declared after `...` in *this* schema version is already
    // a normal AlternativeSpec row above — this variant covers only
    // genuinely-unknown-to-us content, captured as a raw TLV (tag + value
    // bytes) so decode->re-encode still round-trips byte-identically. See
    // rust-runtime/ber/src/choice.rs's UnknownExtensionOps doc comment for
    // the runtime side.
    if (spec.ext_at >= 0) {
        auto [it, inserted] = seen_variants.emplace("UnknownExtension", "...");
        if (!inserted)
            throw std::runtime_error(std::format(
                "RustBackend: CHOICE '{}' — alternative '{}' collides with the reserved "
                "'UnknownExtension' variant name",
                spec.type_name, it->second));
        os << std::format("    UnknownExtension(asn1cpp_ber::Tag, Vec<u8>),\n");
    }
    os << "}\n\n";
}

/// @brief Emit per-alternative accessor functions for a CHOICE type.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
/// @note Free functions doing an exhaustive `match`, not methods — the
///       Rust analogue of the C++ side's offset-based accessor methods,
///       but compiler-checked
///       (exhaustive match) rather than an unchecked `reinterpret_cast`:
///       worst case on a mismatched variant is a controlled panic, not UB.
///       `tag_index_table`/`ber_tags` (BER wire-dispatch specific) are
///       unused here — no runtime wiring yet, same as every prior pairing.
void RustBackend::emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const {
    std::string prefix = escape(to_snake_case(spec.type_name));
    // gambas-asn1#313: a CHOICE with exactly one alternative makes every
    // "does x match this variant" pattern provably always true — rustc
    // correctly flags a `_ => panic!(...)` wildcard arm as unreachable in
    // that case (and, below, an `if let` as irrefutable). Special-cased
    // per this issue's own preferred fix (correct-by-construction output
    // over suppressing real compiler signal): a single-alternative CHOICE
    // uses a plain irrefutable `let` pattern instead of `match`/`if let`,
    // which needs no wildcard/`else` arm at all and warns on neither.
    // An extensible CHOICE (spec.ext_at >= 0) always gets a
    // second enum variant (UnknownExtension, see emit_choice_declaration) —
    // even when spec.alternatives itself has only one row, the enum as a
    // whole is never single-variant once extensible, so the single_alt
    // irrefutable-pattern special-case (#313) must not fire for it.
    bool single_alt = spec.alternatives.size() == 1 && spec.ext_at < 0;
    for (const auto& a : spec.alternatives) {
        std::string fname = escape(std::format("{}_get_{}", prefix, a.accessor_name));
        os << std::format("pub fn {}(x: &mut {}) -> &mut {} {{\n", fname, spec.type_name, rust_seqof_alt_mtype(a.mtype));
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

    // Table-driven, mirroring emit_sequence_definition's approach and the
    // generic runtime walker (encode_choice/decode_choice/encode_choice_xer/
    // decode_choice_xer, rust-runtime/ber/src/choice.rs) instead of a
    // per-type match/if chain. Every CHOICE with at least one *taggable*
    // alternative (choice_alternative_has_tag) always gets a real
    // descriptor table + encode()/decode() now, BER and XER both — an
    // alternative that isn't (yet) representable gets an `unimplemented!()`
    // stub row instead of withholding the whole type, mirroring
    // emit_sequence_definition's `Unsupported` row (a per-alternative
    // closure stub is simpler here: `AlternativeSpec` fields are already
    // plain closures, not an enum like `MemberAccess`, so no new runtime
    // type is needed). The one alternative shape that genuinely can't get
    // a row at all — real or stub — is one with no resolved tag whatsoever
    // (`choice_alternative_has_tag`'s own doc): `decode_choice`'s tag scan
    // needs a real `Tag` to know when to try a row, so that alternative is
    // simply omitted from the table entirely (its enum variant still
    // exists, just unreachable via the generated encode()/decode() —
    // `encode_choice`'s own "no alternative matched" panic already covers
    // that, same as any other codegen/table mismatch).
    // `spec.has_ber_table`/`spec.ber_tags` (Backend.hpp) cover the one case
    // `choice_alternative_has_tag` alone can't: an alternative with no tag
    // of its own whose type is itself a CHOICE (X.680 §28 — CHOICE has no
    // universal tag) — X.690 §8.13 dispatches straight through to *that*
    // CHOICE's own alternatives, so the outer alternative's real dispatch
    // tags are the union of the inner CHOICE's own resolved tags
    // (`Generator::collect_ber_tags_for`, already computed backend-
    // agnostically and pre-formatted in this backend's own tag-literal
    // syntax via `format_tag_literal`, same as every other resolved_tag
    // text elsewhere in this file). One `EmitRow` per flattened tag, all
    // pointing back at the same alternative — genuinely one row each for
    // the common case (a normal alternative always contributes exactly one
    // entry to `ber_tags` too), duplicated only for a CHOICE-of-CHOICE
    // alternative.
    struct EmitRow { const ChoiceAlternativeSpec* alt; std::string tag_lit; };
    std::vector<EmitRow> rows;
    if (spec.has_ber_table) {
        for (const auto& [tag_lit, idx] : spec.ber_tags)
            rows.push_back({&spec.alternatives[idx], tag_lit});
    } else {
        for (const auto& a : spec.alternatives)
            if (choice_alternative_has_tag(a))
                rows.push_back({&a, format_tag_literal(*a.resolved_tag)});
    }
    if (!rows.empty()) {
        std::string alts_ident = std::format("{}_ALTERNATIVES", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::choice::AlternativeSpec<{}>; {}] = [\n",
                          alts_ident, spec.type_name, rows.size());
        for (const auto& row : rows) {
            const auto& a = *row.alt;
            std::string vname = variant_name(*this, a.asn1_name);
            // Directly self-referential alternative (see
            // emit_choice_declaration's Box<> comment) — `v` binds as
            // `&Box<Self>`/`&mut Box<Self>` here, but every body_line below
            // was written assuming `v: &Self`/`&mut Self` (the unboxed
            // shape every other alternative has). Reborrowing through one
            // extra deref right after the match keeps every body_line
            // untouched instead of special-casing each one.
            bool boxed = (a.mtype == spec.type_name);
            const char* box_deref = boxed ? "let v = &**v; " : "";
            // `fn(T) -> C` constructor passed to choice::decode_alt*
            // (choice.rs) — a bare tuple-variant path is itself a valid
            // fn item; the boxed case needs a small non-capturing closure
            // instead (still coerces to the same fn-pointer type).
            std::string ctor_expr = boxed
                ? std::format("|v| {}::{}(Box::new(v))", spec.type_name, vname)
                : std::format("{}::{}", spec.type_name, vname);
            // choice::alt_match! (rust-runtime/ber/src/choice.rs) owns the
            // if-let/else-false plumbing generically, including the
            // gambas-asn1#313 single-alternative-CHOICE irrefutable-pattern
            // case — one line here regardless of alternative count.
            std::string variant_path = std::format("{}::{}", spec.type_name, vname);
            auto emit_encode_closure = [&](const char* field, const std::string& body_line) {
                os << std::format("        {}: |x, out| asn1cpp_ber::choice::alt_match!(x, {}, |v| {{ {}{} true }}),\n",
                                  field, variant_path, box_deref, body_line);
            };
            // `xer_encode` carries a third (`depth: usize`) parameter no
            // other closure field here does (`AlternativeSpec::xer_encode`'s
            // own doc, choice.rs) — a dedicated emitter, not another
            // `emit_encode_closure` parameter, since every call site wants
            // the exact same fixed shape (`x, out, depth`), never a mix.
            auto emit_xer_encode_closure = [&](const std::string& body_line) {
                os << std::format("        xer_encode: |x, out, depth| asn1cpp_ber::choice::alt_match!(x, {}, |v| {{ {}{} true }}),\n",
                                  variant_path, box_deref, body_line);
            };
            os << "    asn1cpp_ber::choice::AlternativeSpec {\n";
            os << std::format("        name: \"{}\",\n", a.asn1_name);
            if (!choice_alternative_covered(a)) {
                // Not yet representable (a builtin type/storage combination
                // with no Asn1Value impl, or a TypeRef to an
                // ARBITRARY-storage INTEGER alias) — stub every closure.
                // Graceful per-alternative, unlike a SEQUENCE Unsupported
                // row: encoding/decoding *other* alternatives of this same
                // CHOICE is completely unaffected, since encode only panics
                // when this specific variant is the active one and decode
                // dispatch only reaches this row when its own tag matched.
                os << std::format("        tag: {},\n", row.tag_lit);
                // Not `emit_encode_closure`/`emit_xer_encode_closure`: their
                // `out`/`depth` closure params are unused here
                // (`unimplemented!()` needs none of them), which would warn
                // under this crate's `-D warnings` bar — `_out`/`_depth`
                // params plus alt_match!'s bound value as `_v`. Rust's
                // leading-underscore convention suppresses the unused-
                // variable warning on a real identifier; a bare `_` can't be
                // used here instead, since it's its own reserved token in
                // the language grammar, not an identifier — `:ident`
                // fragments in macro_rules! only ever match identifiers.
                auto emit_stub_encode_closure = [&](const char* field, const char* params = "x, _out") {
                    os << std::format(
                        "        {}: |{}| asn1cpp_ber::choice::alt_match!(x, {}, |_v| unimplemented!(\"alternative not yet supported\")),\n",
                        field, params, variant_path);
                };
                emit_stub_encode_closure("ber_encode");
                os << std::format("        ber_decode_into: |_r| unimplemented!(\"alternative not yet supported\"),\n");
                emit_stub_encode_closure("xer_encode", "x, _out, _depth");
                os << std::format("        xer_decode_into: |_r| unimplemented!(\"alternative not yet supported\"),\n");
                os << "    },\n";
                continue;
            }
            if (a.resolved_tag && a.is_explicit && a.resolved_tag->tag_is_override) {
                // EXPLICIT — wrap the alternative's natural
                // Asn1Value encoding in an outer TLV via value::
                // encode_explicit/decode_explicit, generic over the
                // alternative's type (same reasoning as the SEQUENCE scalar
                // EXPLICIT branch above). Only a real `[n]` written on this
                // alternative itself (tag_is_override) reaches here — see
                // the `else` branch below for the bare-type-reference case,
                // where the referenced type's own Asn1Value impl already
                // wraps itself (own_tag, choice.rs) and a second wrap here
                // would double it (X.680 §30.1/30.3 — no TaggedType
                // construction on this alternative means no extra layer).
                os << std::format("        tag: {},\n", row.tag_lit);
                emit_encode_closure("ber_encode", std::format("asn1cpp_ber::value::encode_explicit(out, {}, v);", row.tag_lit));
                os << std::format("        ber_decode_into: |r| asn1cpp_ber::choice::decode_alt_explicit(r, {}, {}),\n", row.tag_lit, ctor_expr);
            } else if (a.resolved_tag && a.is_explicit) {
                // A bare type reference (no `[n]` of its own) to a type that
                // is itself EXPLICIT-tagged (e.g. an alternative referencing
                // `T4 ::= [53] CHOICE {...}`) — `row.tag_lit` is only needed
                // here for `decode_choice_from`'s dispatch match; the actual
                // wrap already happens inside the referenced type's own
                // Asn1Value impl, so delegate straight to it, same as the
                // untagged-CHOICE-alternative branch further below.
                os << std::format("        tag: {},\n", row.tag_lit);
                emit_encode_closure("ber_encode", "asn1cpp_ber::value::Asn1Value::ber_encode(v, out);");
                os << std::format("        ber_decode_into: |r| asn1cpp_ber::choice::decode_alt(r, {}),\n", ctor_expr);
            } else if (a.resolved_tag) {
                // Every other tagged alternative — whether IMPLICIT-retagged
                // or using its own natural tag — dispatches through one
                // generic pair, `Asn1Value::ber_encode_tagged`/
                // `ber_decode_into_tagged` (value.rs), using this row's own
                // tag whatever it is: the natural-tag case is
                // indistinguishable from an override at this level
                // (ber_encode_tagged's fast path makes them produce
                // identical bytes when the two coincide), so no per-kind or
                // override-vs-natural branching is needed here at all.
                os << std::format("        tag: {},\n", row.tag_lit);
                emit_encode_closure("ber_encode", std::format("asn1cpp_ber::value::Asn1Value::ber_encode_tagged(v, {}, out);", row.tag_lit));
                os << std::format("        ber_decode_into: |r| asn1cpp_ber::choice::decode_alt_tagged(r, {}, {}),\n", row.tag_lit, ctor_expr);
            } else {
                // No tag of its own at all (X.680 §28 — a CHOICE-of-CHOICE
                // alternative, only reachable when `spec.has_ber_table`):
                // this row's `tag` is one of the *referenced* CHOICE's own
                // flattened alternative tags (`row.tag_lit`), used purely to
                // get `decode_choice_from`'s linear scan to try this row —
                // once tried, the actual decode/encode delegates to the
                // referenced type's own natural (non-tag-substituting)
                // Asn1Value::ber_encode/ber_decode_into, since the value
                // already carries its own real tag (whichever of the
                // referenced CHOICE's alternatives it turns out to be).
                os << std::format("        tag: {},\n", row.tag_lit);
                emit_encode_closure("ber_encode", "asn1cpp_ber::value::Asn1Value::ber_encode(v, out);");
                os << std::format("        ber_decode_into: |r| asn1cpp_ber::choice::decode_alt(r, {}),\n", ctor_expr);
            }
            emit_xer_encode_closure("asn1cpp_ber::value::Asn1Value::xer_encode(v, out, depth);");
            os << std::format("        xer_decode_into: |r| asn1cpp_ber::choice::decode_alt_xer(r, {}),\n", ctor_expr);
            os << "    },\n";
        }
        os << "];\n\n";

        os << std::format(
            "static {}: asn1cpp_ber::choice::ChoiceSpec<{}> = asn1cpp_ber::choice::ChoiceSpec {{\n",
            spec_ident, spec.type_name);
        // X.693 §8.3.1 — document-root XMLTypedValue wrapper name, used only
        // by encode_choice_xer/decode_choice_xer (never by the _into/_from
        // nested variants, and never for BER).
        os << std::format("    name: \"{}\",\n", spec.xer_name);
        os << std::format("    alternatives: &{},\n", alts_ident);
        if (spec.ext_at >= 0) {
            // Wire the UnknownExtension variant (declared
            // in emit_choice_declaration) into the runtime's fallback path —
            // construct captures an unrecognized-tag TLV on decode, extract
            // hands it back to encode_choice for byte-identical re-encoding.
            os << "    unknown_extension: Some(asn1cpp_ber::choice::UnknownExtensionOps {\n";
            os << std::format("        construct: |tag, bytes| {}::UnknownExtension(tag, bytes),\n",
                               spec.type_name);
            os << "        extract: |x| match x {\n";
            os << std::format("            {}::UnknownExtension(tag, bytes) => Some((*tag, bytes.as_slice())),\n",
                               spec.type_name);
            os << "            _ => None,\n";
            os << "        },\n";
            os << "    }),\n";
        } else {
            os << "    unknown_extension: None,\n";
        }
        // X.680 §30.6 — a CHOICE type assignment's own declared [n] (when
        // present) is always EXPLICIT; see ChoiceSpec::own_tag's own doc.
        if (spec.tag) {
            os << std::format("    own_tag: Some({}),\n", format_tag_literal(*spec.tag));
        } else {
            os << "    own_tag: None,\n";
        }
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::choice::decode_choice(&{}, data)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn encode_xer(&self) -> String {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice_xer(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::choice::decode_choice_xer(&{}, xml)\n", spec_ident);
        os << "    }\n";
        os << "}\n\n";

        // Makes this type usable as a nested composite member elsewhere —
        // see emit_sequence_definition's identical Asn1Value impl for the
        // full rationale (always emitted now, BER and XER both, once this
        // CHOICE has at least one taggable alternative).
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_ber::Tag {\n";
        os << "        unreachable!(\"CHOICE has no natural tag (X.680 §28) — never invoked, a CHOICE-typed member/alternative is always EXPLICIT-wrapped when tagged (X.680 §30.6)\")\n";
        os << "    }\n\n";
        os << "    fn xer_element_name(&self) -> &'static str {\n";
        os << std::format("        \"{}\"\n", spec.xer_name);
        os << "    }\n\n";
        // CHOICE has no separate content representation to hand back
        // (its wire form already IS "whichever alternative's own tag +
        // content", self-delimiting per X.690 §8.13) — so, like
        // `Option<V>` in value.rs, it overrides the whole-TLV methods
        // directly instead of composing them from natural_tag + content.
        os << "    fn ber_encode_content(&self, _out: &mut Vec<u8>) {\n";
        os << "        unreachable!(\"CHOICE has no content-only representation — ber_encode is overridden directly\")\n";
        os << "    }\n\n";
        os << "    fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        unreachable!(\"CHOICE has no content-only representation — ber_decode_into is overridden directly\")\n";
        os << "    }\n\n";
        os << "    fn ber_encode(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice_into(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_into(&mut self, r: &mut asn1cpp_ber::Reader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::choice::decode_choice_from(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        // `encode_choice_xer_into` deliberately ends right after the
        // chosen alternative's own closing tag — no trailing `\n` +
        // `indent(depth)` (its own doc, rust-runtime/ber/src/choice.rs).
        // A CHOICE-typed member's own wrapper (`<mname>`, written by
        // `encode_sequence_xer_content`) does immediately follow, so
        // `xer_encode` itself (used for exactly that context) adds that
        // trailing bit here — mirrors `SequenceXerHandler`'s own
        // CHOICE-typed-member special case in C++, which writes its own
        // `s.indent(1) << "</" << mbr.name` closing line external to
        // `ChoiceXerHandler` for the very same reason.
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice_xer_into(&{}, self, out, depth);\n", spec_ident);
        os << "        out.push('\\n');\n";
        os << "        out.push_str(&asn1cpp_ber::xer::indent(depth));\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_ber::xer::XerReader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::choice::decode_choice_xer_from(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        // X.693: as a SEQUENCE OF/SET OF element, a CHOICE has no wrapper
        // of its own — the chosen alternative's own tag already serves as
        // the element tag, so this calls `encode_choice_xer_into` directly,
        // *not* `self.xer_encode` (whose trailing bit above is specific to
        // the member-wrapper case — no per-element wrapper follows a
        // SEQUENCE OF/SET OF element for it to position). The trailing
        // `\n` here instead matches `ChoiceXerHandler`'s own unconditional
        // "always end with `\n`" convention (`encode_choice_xer_into`'s own
        // doc, rust-runtime/ber/src/choice.rs) — `encode_seq_of_xer_named`
        // (sequence.rs) checks for it to avoid doubling up with its own
        // trailing separator.
        os << "    fn xer_encode_seqof_element(&self, out: &mut String, depth: usize, _name_override: std::option::Option<&str>) {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice_xer_into(&{}, self, out, depth + 1);\n", spec_ident);
        os << "        out.push('\\n');\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into_seqof_element(&mut self, r: &mut asn1cpp_ber::xer::XerReader, _name_override: std::option::Option<&str>) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        self.xer_decode_into(r)\n";
        os << "    }\n";
        if (spec.tag) {
            // Only reachable when this CHOICE has its own declared [n]
            // (X.680 §30.6, own_tag above): AUTOMATIC TAGS can then assign
            // an IMPLICIT tag to a member/alternative that's a plain
            // reference to this type (X.680 §22.5/§28.4 — an already-tagged
            // CHOICE is a TaggedType for retagging purposes, not a bare
            // untagged CHOICE, so it's no longer forced EXPLICIT), reaching
            // Asn1Value::ber_encode_tagged/ber_decode_into_tagged generically
            // (MemberAccess::TaggedScalar / the generic-tagged AlternativeSpec
            // branch). The trait's own defaults assume a natural-tag/content
            // split CHOICE can't support (X.680 §28, no universal tag) — see
            // encode_choice_tagged/decode_choice_tagged's own doc (choice.rs)
            // for the actual logic; this is a one-line delegate to it.
            os << "    fn ber_encode_tagged(&self, tag: asn1cpp_ber::Tag, out: &mut Vec<u8>) {\n";
            os << std::format("        asn1cpp_ber::choice::encode_choice_tagged(&{}, self, tag, out);\n", spec_ident);
            os << "    }\n\n";
            os << "    fn ber_decode_into_tagged(&mut self, r: &mut asn1cpp_ber::Reader, tag: asn1cpp_ber::Tag) -> Result<(), asn1cpp_ber::DecodeError> {\n";
            os << std::format("        *self = asn1cpp_ber::choice::decode_choice_tagged(&{}, r, tag)?;\n", spec_ident);
            os << "        Ok(())\n";
            os << "    }\n";
        }
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
    session.buffer(declaration_extension()) << "//! Module: " << module_comment << "\n\n";
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
///       would share `Vec<u8>`'s own single `Asn1Value` impl, whose
///       `xer_element_name()` can only ever return one fixed string,
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
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
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
///       the same element type), so it can't carry an `Asn1Value` impl
///       specific to *this* ASN.1 type. A newtype is a genuinely distinct
///       Rust type, so it can — see emit_seq_of_definition's own doc for
///       that impl. `Deref`/`DerefMut` to `Vec<ElemType>` keep `.len()`/
///       `.iter()`/indexing working without needing `.0` everywhere.
void RustBackend::emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const {
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
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
    session.buffer(declaration_extension()) << std::format("pub type {} = {};\n", type_name, target_type);
}

/// @brief Reference another generated type via its crate-relative module
///        path — assumes a generated crate root (main.cpp, --target=rust)
///        declares one module per generated file.
/// @note module *identifier* is snake_case
///       (to_snake_case(filename)), not the raw filename — see
///       finalize_output's own `#[path = ...]` module declaration. `filename`
///       here is still the on-disk file stem (PascalCase, matching
///       `type_name`), so it must be re-derived into the same snake_case
///       identifier finalize_output declared the module under, or this
///       `use` path wouldn't resolve.
void RustBackend::emit_type_reference(const std::string& type_name, const std::string& filename,
                                       TypeOutputSession& session) const {
    session.buffer(declaration_extension())
        << std::format("use crate::{}::{};\n", to_snake_case(filename), type_name);
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
///        WIP (#214): flat mod-per-file list, no module tree mirroring
///        ASN.1 modules.
/// @note module *identifier* is snake_case
///       (`pub mod contact_list;`), not the PascalCase file stem — Rust
///       convention wants snake_case module names even though the type
///       inside is (correctly) PascalCase; a bare `pub mod ContactList;`
///       fails rustc's non_snake_case lint. `#[path = "ContactList.rs"]`
///       keeps the on-disk filename PascalCase (matching `type_name`/
///       `filename_for`) while giving the module itself a snake_case Rust
///       identifier — emit_type_reference's `use` paths re-derive the same
///       to_snake_case(filename) so the two stay in sync without a second
///       source of truth.
void RustBackend::finalize_output(const std::string& out_dir) const {
    namespace fs = std::filesystem;
    fs::path lib_rs = fs::path(out_dir) / "lib.rs";
    std::ofstream lib(lib_rs);
    for (const auto& entry : fs::directory_iterator(out_dir)) {
        if (entry.path().extension() != ".rs" || entry.path() == lib_rs) continue;
        std::string stem = entry.path().stem().string();
        lib << std::format("#[path = \"{}.rs\"] pub mod {};\n", stem, to_snake_case(stem));
    }
}

} // namespace asn1::codegen
