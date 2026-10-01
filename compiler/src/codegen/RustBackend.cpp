#include "RustBackend.hpp"
#include "asn1cpp/codec/Constraints.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
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
    // newtype, not plain String) — each newtype's Asn1Value impl checks its
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
    // Not yet covered — no Asn1Value impl in rust-runtime/wire for these
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

/// @brief Whether `bt` is a known-multiplier character string kind PER
///        encoding (X.691 §26.5) covers — exactly `is_sizeable_string_kind`'s
///        own set (every character-string kind, wide-char included).
///        (bits, bytes-per-char, natural alphabet) is no longer decided
///        here: `asn1cpp_wire::per::strings::encode_string`/`decode_string` take
///        the type's own universal tag number and look the rest up
///        themselves (that crate's own `string_params` table, mirroring
///        `runtime/src/PerCodec.cpp`'s identical one) — codegen's only job
///        is picking the right tag constant (`builtin_ber_tag`, already
///        used for the BER leg) and, since the Rust field representation
///        genuinely does differ by kind, the byte-source/constructor shape
///        (Vec<u8> pass-through for wide-char, String::from_utf8 otherwise).
static bool per_string_covered(ast::BuiltinType bt) {
    return is_sizeable_string_kind(bt);
}

// Whole-program truth table for "does builtin kind `bt` have a real
// `Asn1Value::per_encode`/`per_decode_into`?" — an exhaustive switch,
// not an if-chain of early `return true` cases: `-Wswitch` (`-Wall`,
// enabled project-wide) then flags any `ast::BuiltinType` enumerator
// this function doesn't mention, so a future kind gaining a real PER
// impl (or a new enumerator altogether) can't silently stay
// unconsidered here the way BOOLEAN, inline ENUMERATED and REAL each
// did until this pass found them. `storage_kind` only matters for
// INTEGER, the one builtin kind whose coverage is still conditional;
// every other case ignores it.
//
// DELETE ONCE PER IS COMPLETE: no case below returns an unconditional
// `false` anymore — every builtin kind's PER encoding exists in the
// runtime (X.691 covers all of them, ANY/OID/RELATIVE-OID included as
// open-type fields, X.691 §10.2, and the twelve character-string kinds'
// FROM-alphabet remapping, X.691 §26.5.4/§26.5.7 — confirmed against
// asn1c's own reference handlers and this codebase's own C++ runtime,
// `runtime/src/PerCodec.cpp`). One conditional remains, tracking a real,
// independently-tracked implementation gap rather than anything
// structural: INTEGER's storage-kind check (I128/ARBITRARY storage has
// no PER encoding wired up yet). Once it closes, this whole function
// collapses to
// `return true;` unconditionally — delete it then, fold
// `per_member_covered`/`per_alt_covered`'s `m.mbuiltin`/`a.mbuiltin`
// branches into an unconditional `true`, and delete `per_stub_reason`'s
// builtin-kind text (only the SEQUENCE-OF reason would remain).
static bool per_builtin_covered(ast::BuiltinType bt, IntStorageKind storage_kind) {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Integer:
        return storage_kind == IntStorageKind::S64 || storage_kind == IntStorageKind::U64;
    // BOOLEAN (X.691 §12): one bit, no alignment.
    case BT::Boolean:
    // NULL (X.691 §14): zero bits either direction.
    case BT::Null:
    // OCTET STRING/BIT STRING (X.691 §16/§17): no alphabet concept at
    // all, unconditionally covered regardless of SIZE constraint (both
    // always-wire real bounds or a flags: 0 fallback).
    case BT::OctetString:
    case BT::BitString:
    // REAL (X.691 §16): not bit-packed — the value's own BER content
    // bytes, length-prefixed.
    case BT::Real:
    // An inline `ENUMERATED { ... }` member/alternative (X.680 §20) —
    // its own synthetic type (native_member_type_for) always gets a
    // real PerValue impl (emit_enumerated_definition's own doc), same
    // as a TypeRef to a named ENUMERATED; the inline case's own AST
    // node just never becomes a TypeRef, so it needs its own case here.
    case BT::Enumerated:
        return true;
    // Known-multiplier character strings (X.691 §26), FROM-constrained or
    // not: `asn1cpp_wire::per::strings::encode_string`/`decode_string`
    // remap to the declared alphabet's own ordinal width (X.691 §26.5.4/
    // §26.5.7) via the row's own `encode_table`/`alphabet` — the same
    // table `has_own_descriptor` already threads for any builtin kind.
    // The one thing still unimplemented, the extensible SIZE/FROM
    // out-of-root open-type escape, panics loudly at runtime rather than
    // corrupting output (`per::strings`'s own doc) — no schema exercises
    // it, so it's not excluded here either.
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
    // UTCTime/GeneralizedTime are generated by the same `char_string_type!`
    // macro (strings.rs) as the twelve kinds above and get the identical
    // `per_encode`/`per_decode_into` pair from it — not a separate,
    // narrower macro variant.
    case BT::UtcTime:
    case BT::GeneralizedTime:
        return true;
    // ANY (X.208 legacy, X.691 §10.2 open-type encoding) — length-
    // prefixed raw captured bytes, unconditionally covered by `Any`'s own
    // Asn1Value impl (any.rs).
    case BT::Any:
    // OBJECT IDENTIFIER/RELATIVE-OID (X.691 §23/§24, also a §10.2
    // open-type field — same length-prefixed BER-content shape as
    // REAL/ANY), unconditionally covered by `ObjectIdentifier`'s/
    // `RelativeOid`'s own Asn1Value impl.
    case BT::ObjectIdentifier:
    case BT::RelativeOid:
        return true;
    }
    return false;
}

/// @brief Does a SEQUENCE OF/SET OF element's own shape have a real
///        `Asn1Value::per_encode`/`per_decode_into`? Recurses through
///        nested collections to unbounded depth (`ElemShape::nested`),
///        matching `SeqOf<T>`/`SetOf<T>`'s own fully generic PER impl,
///        which never inspects `T` beyond calling its trait methods.
/// @param shape Resolved, backend-agnostic element shape (`ElemShape`).
/// @return Whether this element's leaf type is PER-representable.
static bool per_elem_shape_covered(const ElemShape& shape) {
    if (shape.kind != SeqOfKind::None)
        return shape.nested && per_elem_shape_covered(*shape.nested);
    if (shape.builtin)
        return per_builtin_covered(*shape.builtin, shape.storage_kind);
    // A composite (TypeRef/SEQUENCE/CHOICE) leaf always owns its own
    // constraint and ignores whatever `element` this row's `Constraints`
    // hands it — unconditionally safe, same reasoning
    // `SequenceMemberSpec::ref_kind == Other`'s own coverage gives a
    // plain composite member one level up.
    return true;
}

void RustBackend::emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    // Doc comment ties the generated name back to its ASN.1 source —
    // matters most at the edges variant_name's word-split conversion can
    // erase (e.g. "utf-8"/"utf8" both -> "Utf8", "a-b"/"ab" both -> "Ab").
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
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
        os << std::format("    /// ASN.1: `{}`\n", v.asn1_name);
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

        // One codec-agnostic table (X.680 §20): BER/PER read `value`, XER
        // reads `name`. Sorted ascending by value — the PER ordinal is the
        // sorted position (X.691 §22, matches asn1c and C++'s own sorted
        // EnumSpec::entries). Root layout (count, index width) is
        // precomputed here so no codec walker recounts it.
        std::vector<NamedValue> sorted_values = spec.values;
        std::sort(sorted_values.begin(), sorted_values.end(),
                   [](const NamedValue& a, const NamedValue& b) { return a.value < b.value; });
        size_t root_count = spec.root_count > 0 ? static_cast<size_t>(spec.root_count) : sorted_values.size();
        unsigned root_bits = 0;
        for (size_t r = root_count > 1 ? root_count - 1 : 0; r > 0; r >>= 1) ++root_bits;
        std::string map_ident = std::format("{}_ENUM_SPEC", to_screaming_snake_case(tname));
        os << std::format("static {}: asn1cpp_wire::spec::enumerated::EnumSpec = asn1cpp_wire::spec::enumerated::EnumSpec {{\n    entries: &[\n",
                           map_ident);
        for (const auto& v : sorted_values) {
            os << std::format("        asn1cpp_wire::spec::enumerated::EnumEntry {{ value: {}, name: \"{}\" }},\n",
                               v.value, v.asn1_name);
        }
        os << std::format("    ],\n    extensible: {}, root_count: {}, root_bits: {},\n}};\n\n",
                           spec.extensible ? "true" : "false", root_count, root_bits);

        // One merged Asn1Value impl (gambas-asn1#537 unified what used to be
        // two separate traits/impl blocks, asn1cpp_wire::value::Asn1Value
        // and asn1cpp_wire::value::Asn1Value) — BER leg (matches every other
        // Asn1Value impl this backend emits), XER leg (BASIC-XER
        // EmptyElementBoolean-style content, same as `bool`'s own impl
        // above in this file — mirrors EnumeratedXerHandler's
        // member-embedded form, runtime/src/XerCodec.cpp), and PER leg
        // together. `as i64`/`TryFrom<i64>` convert through the shared wire
        // representation (X.690 §8.4); the XER leg goes through
        // {map_ident} instead — BER's wire value and XER's value *name*
        // are different representations of the same table, not two
        // independent lookups.
        os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", tname);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n";
        os << "        asn1cpp_wire::ber::enumerated::ENUMERATED_TAG\n";
        os << "    }\n\n";
        os << "    fn xer_element_name(&self) -> &'static str {\n";
        os << std::format("        \"{}\"\n", spec.xer_name);
        os << "    }\n\n";
        os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
        os << "        asn1cpp_wire::ber::enumerated::encode_enumerated_content(out, *self as i64);\n";
        os << "    }\n\n";
        os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        *self = asn1cpp_wire::ber::enumerated::decode_enumerated_content(content)?;\n";
        os << "        Ok(())\n";
        os << "    }\n\n";
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << std::format("        asn1cpp_wire::ber::enumerated::xer_encode_enum(out, &{}, *self as i64);\n", map_ident);
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_wire::ber::enumerated::xer_decode_enum(r, &{})?;\n", map_ident);
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
        os << "        out.push_str(&asn1cpp_wire::xer::indent(depth + 1));\n";
        os << "        self.xer_encode(out, depth + 1);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into_seqof_element(&mut self, r: &mut asn1cpp_wire::xer::XerReader, _name_override: std::option::Option<&str>) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        self.xer_decode_into(r)\n";
        os << "    }\n\n";
        // X.680 §20/§51 — reuses {map_ident} (already
        // emitted above for BER/XER), same "table data, one generic
        // function, no per-type logic" shape the Constraints redesign
        // established. In practice unreachable through the normal decode
        // path (TryFrom<i64> already rejects an unrecognized wire value
        // before a Rust enum instance can exist — see
        // enumerated::validate_enum's own doc), but a real override, not
        // a stub, for parity with the other constraint kinds.
        os << "    fn validate(&self, _c: &asn1cpp_wire::constraints::Constraints) -> i64 {\n";
        os << std::format("        asn1cpp_wire::spec::enumerated::validate_enum(*self as i64, &{})\n", map_ident);
        os << "    }\n\n";

        os << "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {\n";
        os << std::format("        asn1cpp_wire::per::enumerated::encode_enum(w, &{}, *self as i64);\n", map_ident);
        os << "    }\n\n";
        os << "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {\n";
        os << std::format("        let v = asn1cpp_wire::per::enumerated::decode_enum(r, &{})?;\n", map_ident);
        os << std::format(
            "        *self = std::convert::TryFrom::try_from(v).map_err(|_| asn1cpp_wire::per::reader::DecodeError::new(\"PER: ENUM value not in {}\", r.bit_pos()))?;\n",
            tname);
        os << "        Ok(())\n";
        os << "    }\n";
        os << "}\n\n";
        // ENUMERATED's natural tag never varies by declaration.
        os << "\n";
        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", tname);
        os << "    const TAG: Option<asn1cpp_wire::Tag> = Some(asn1cpp_wire::ber::enumerated::ENUMERATED_TAG);\n";
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
        // its own type identity to carry a per-declaration `Asn1Value`/
        // `PerValue` impl (its own XER tag name, X.680 §19 range in a
        // single `validate()`/PER encode call, X.691 wire shape) — the same
        // reason every other builtin except INTEGER already gets one
        // (OctetString/BitString/the 11 string kinds). A TypeRef member to
        // this type dispatches through the trait (Scalar) exactly like a
        // TypeRef to ENUMERATED or another SEQUENCE/CHOICE, with no
        // per-member closure. `Deref`/`DerefMut` to the underlying
        // primitive keep arithmetic/comparison ergonomic.
        os << std::format("#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]\n");
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
        os << std::format("pub type {} = {};\n\n", tname, native_int_type(spec.storage_kind));
    }

    for (const auto& v : spec.named_values) {
        os << std::format("/// ASN.1: `{}`\n", v.asn1_name);
        if (spec.storage_kind == IntStorageKind::ARBITRARY)
            os << std::format("pub const {}: {} = {};\n", value_name(v.asn1_name), native_int_type(spec.storage_kind), v.value);
        else
            os << std::format("pub const {}: {} = {}({});\n", value_name(v.asn1_name), native_int_type(spec.storage_kind), native_int_type(spec.storage_kind), v.value);
    }
    if (!spec.named_values.empty()) os << "\n";
}

void RustBackend::emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;
    bool newtype = spec.storage_kind == IntStorageKind::S64 || spec.storage_kind == IntStorageKind::U64;
    if (!newtype) return;  // I128/ARBITRARY: plain alias, no impl of its own (declaration's own doc).

    bool semi = spec.semi_constrained || spec.hi_is_large;
    int flags = (spec.has_constraint ? (semi ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED) : 0)
              | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0);
    std::string cname = std::format("{}_CONSTRAINTS", to_screaming_snake_case(tname));
    // One combined BER+PER table (asn1cpp_wire::constraints::Constraints, same
    // shape emit_member_type_descriptor's Integer branch emits) — this
    // type's own Asn1Value::validate() and PerValue::per_encode/decode
    // both read it directly, so a member of this type needs nothing
    // beyond the ordinary accessor. range_bits is -1 for a
    // semi-constrained/unbounded range (no fixed bit width, never read in
    // that case) but can't format as a negative u32 literal; clamp to 0.
    if (spec.storage_kind == IntStorageKind::S64) {
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: {}, lower_bound: {}, upper_bound: {}, lower_u64: 0, upper_u64: 0, "
            "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,\n"
            "}};\n\n",
            cname, flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64);
    } else {
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: {}, lower_bound: 0, upper_bound: 0, lower_u64: {}u64, upper_u64: {}u64, "
            "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,\n"
            "}};\n\n",
            cname, flags, std::max(spec.range_bits, 0), spec.lower_u64, spec.upper_u64);
    }

    const char* fn_ns = spec.storage_kind == IntStorageKind::S64 ? "integer" : "uinteger";
    const char* fn_ty = spec.storage_kind == IntStorageKind::S64 ? "encode_int" : "encode_uint";
    const char* fn_dec = spec.storage_kind == IntStorageKind::S64 ? "decode_int" : "decode_uint";
    const char* validate_fn = spec.storage_kind == IntStorageKind::S64 ? "validate_s64" : "validate_u64";

    // `Asn1Value`: encode/decode content and the natural tag delegate to
    // the wrapped primitive's own impl (a shared native type's wire bytes
    // never vary by declared range, X.680 §19 — only validate() differs
    // per declaration); `xer_element_name`/`validate` are this type's own,
    // the two things a bare i64/u64 could never carry per-alias.
    os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", tname);
    os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n        self.0.ber_natural_tag()\n    }\n\n";
    os << std::format("    fn xer_element_name(&self) -> &'static str {{\n        \"{}\"\n    }}\n\n", spec.xer_name);
    os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n        self.0.ber_encode_content(out);\n    }\n\n";
    os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n        self.0.ber_decode_content(content)\n    }\n\n";
    os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n        self.0.xer_encode(out, depth);\n    }\n\n";
    os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n        self.0.xer_decode_into(r)\n    }\n\n";
    os << std::format("    fn constraints(&self) -> &'static asn1cpp_wire::constraints::Constraints {{\n        &{}\n    }}\n\n", cname);
    os << std::format("    fn validate(&self, _c: &asn1cpp_wire::constraints::Constraints) -> i64 {{\n        asn1cpp_wire::constraints::{}(*self.0, &{})\n    }}\n\n", validate_fn, cname);

    // PER leg (merged into the same impl block, gambas-asn1#537): X.691
    // wire shape is exactly `integer::encode_int`/`uinteger::encode_uint`
    // against this same table — no separate unconstrained function needed,
    // they already fall through to the unconstrained wire shape at runtime
    // when flags == 0.
    os << std::format("    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {{\n        asn1cpp_wire::per::{}::{}(w, &{}, *self.0);\n    }}\n", fn_ns, fn_ty, cname);
    os << std::format(
        "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {{\n"
        "        self.0 = {}(asn1cpp_wire::per::{}::{}(r, &{})?);\n        Ok(())\n    }}\n",
        native_int_type(spec.storage_kind), fn_ns, fn_dec, cname);
    os << "}\n\n";
    // Mirrors ber_natural_tag() (delegates to the wrapped primitive's
    // own TAG — INTEGER_TAG regardless of storage width).
    os << "\n";
    os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", tname);
    os << std::format("    const TAG: Option<asn1cpp_wire::Tag> = <{} as asn1cpp_wire::type_tag::TypeTag>::TAG;\n", native_int_type(spec.storage_kind));
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
///       `Asn1Value for String` impl (`rust-runtime/wire/src/value.rs`),
///       kept as-is for ergonomics/backward compatibility.
///       The other 11 restricted-character-string kinds
///       map to their own `rust-runtime/wire::strings`
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
    using BT = ast::BuiltinType;
    bool is_bits = spec.builtin_type == BT::BitString;
    bool is_octets = spec.builtin_type == BT::OctetString;
    // SIZE-able kinds (X.691 §16/§17/§26.5): OCTET STRING/BIT STRING plus
    // every character-string kind, wide-char included — validate() is
    // pure byte-length checking either way, no PER-specific alphabet
    // concern. Table-driven throughout (per review on #473: "all
    // constraints should be table based... never put it in code"),
    // always wired regardless of has_size_constraint (flags: 0 when
    // unconstrained) so validate() and, when covered, PerValue both read
    // the exact same static — no generated per-type bounds-check function.
    bool sizeable = is_bits || is_octets || is_sizeable_string_kind(spec.builtin_type);
    std::string cname = to_screaming_snake_case(tname) + "_CONSTRAINTS";
    if (sizeable) {
        int flags = spec.has_size_constraint
            ? (asn1::Constraints::SIZE_CONSTRAINED | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0))
            : 0;
        int64_t size_upper = spec.size_bounded ? spec.size_upper : std::numeric_limits<int64_t>::max();
        os << std::format(
            "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
            "    flags: {}, range_bits: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
            "size_range_bits: {}, size_lower: {}, size_upper: {}, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,\n"
            "}};\n\n",
            cname, flags, spec.size_range_bits, spec.size_lower, size_upper);
    }

    os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", tname);
    os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n";
    os << std::format("        {}\n", spec.tag ? format_tag_literal(*spec.tag) : "self.0.ber_natural_tag()");
    os << "    }\n\n";
    os << "    fn xer_element_name(&self) -> &'static str {\n";
    os << std::format("        \"{}\"\n", spec.xer_name);
    os << "    }\n\n";
    os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
    os << "        self.0.ber_encode_content(out);\n";
    os << "    }\n\n";
    os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n";
    os << "        self.0.ber_decode_content(content)\n";
    os << "    }\n\n";
    // BASE64/utf8 (X.693 §21, ENCODING-CONTROL XER ... BASE64 <TypeName> /
    // legacy `<TypeName> OCTET STRING ::= base64`/`::= utf8`) replaces this
    // alias's own xer_encode/xer_decode_into with the matching helper
    // directly — OctetString itself has no per-instance encoding flag to
    // branch on (see octet_string.rs's own base64_encode/utf8_encode doc).
    if (spec.xer_encoding == ast::XerEncoding::Base64) {
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << "        out.push_str(&asn1cpp_wire::octet_string::base64_encode(&self.0));\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        self.0.0 = asn1cpp_wire::octet_string::base64_decode(&r.read_text_content());\n";
        os << "        Ok(())\n";
        os << "    }\n";
    } else if (spec.xer_encoding == ast::XerEncoding::Utf8) {
        os << "    fn xer_encode(&self, out: &mut String, _depth: usize) {\n";
        os << "        asn1cpp_wire::octet_string::utf8_encode(&self.0, out);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        self.0.0 = asn1cpp_wire::octet_string::utf8_decode(r)?;\n";
        os << "        Ok(())\n";
        os << "    }\n";
    } else {
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << "        self.0.xer_encode(out, depth);\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        self.0.xer_decode_into(r)\n";
        os << "    }\n";
    }
    if (sizeable) {
        os << std::format("\n    fn constraints(&self) -> &'static asn1cpp_wire::constraints::Constraints {{\n        &{}\n    }}\n\n", cname);
        const char* method = is_bits ? "bit_count" : "len";
        os << std::format("\n    fn validate(&self, _c: &asn1cpp_wire::constraints::Constraints) -> i64 {{\n        asn1cpp_wire::constraints::validate_size(self.0.{}(), &{})\n    }}\n",
                           method, cname);
    }

    // PER leg (merged into the same impl block, gambas-asn1#537) — OCTET
    // STRING/BIT STRING unconditionally (no alphabet concept), a
    // known-multiplier character string kind (wide-char BmpString/
    // UniversalString included) when it has no FROM constraint (PER
    // encode/decode here doesn't implement alphabet remapping yet — same
    // exclusion per_member_covered's own Sizeable branch already applies
    // to a direct member of this kind). When not covered, `Asn1Value`'s
    // own panicking defaults for `per_encode`/`per_decode_into` apply —
    // same real-or-panic-stub policy an individual SEQUENCE/CHOICE member
    // row already gets (`MemberAccess::Unsupported`). A named alias's own
    // real `per_encode`/`per_decode_into` means any TypeRef to it
    // dispatches through the trait (Scalar) regardless of whether it's
    // actually covered — the panic, if ever reached, happens inside this
    // impl, not at the TypeRef site.
    bool str_covered = per_string_covered(spec.builtin_type);
    bool per_covered = is_bits || is_octets || (str_covered && spec.alphabet.empty());
    if (per_covered) {
        os << "\n";
        if (is_bits) {
            os << std::format(
                "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {{\n"
                "        asn1cpp_wire::per::bit_string::encode_bit_string(w, &{0}, &self.0.bytes, self.0.bit_count());\n    }}\n",
                cname);
            os << std::format(
                "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {{\n"
                "        let (bytes, unused) = asn1cpp_wire::per::bit_string::decode_bit_string(r, &{0})?;\n"
                "        self.0 = asn1cpp_wire::bit_string::BitString {{ bytes, unused_bits: unused }};\n        Ok(())\n    }}\n",
                cname);
        } else if (is_octets) {
            os << std::format(
                "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {{\n"
                "        asn1cpp_wire::per::octet_string::encode_octet_string(w, &{0}, &self.0.0);\n    }}\n",
                cname);
            os << std::format(
                "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {{\n"
                "        self.0 = asn1cpp_wire::octet_string::OctetString(asn1cpp_wire::per::octet_string::decode_octet_string(r, &{0})?);\n"
                "        Ok(())\n    }}\n",
                cname);
        } else {
            std::string tag_num = std::format("<{} as asn1cpp_wire::type_tag::TypeTag>::TAG.unwrap().number", native_builtin_type(spec.builtin_type));
            bool wide = spec.builtin_type == BT::BmpString || spec.builtin_type == BT::UniversalString;
            std::string bytes_expr = wide ? "&self.0.0" : "self.0.as_bytes()";
            std::string ctor = wide ? std::format("{}(x)", native_builtin_type(spec.builtin_type))
                              : std::format("{}(String::from_utf8(x).unwrap_or_default())", native_builtin_type(spec.builtin_type));
            os << std::format(
                "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {{\n"
                "        let _ = asn1cpp_wire::per::strings::encode_string(w, &{0}, {1}, {2});\n    }}\n",
                cname, tag_num, bytes_expr);
            os << std::format(
                "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {{\n"
                "        let x = asn1cpp_wire::per::strings::decode_string(r, &{0}, {1})?;\n"
                "        self.0 = {2};\n        Ok(())\n    }}\n",
                cname, tag_num, ctor);
        }
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
        // One combined table (BER + PER fields, gambas-asn1's shared
        // asn1cpp_wire::constraints::Constraints) serves both legs: BER's
        // `constraints::validate_s64`/`validate_u64` (rust-runtime/wire)
        // read flags/lower_bound/upper_bound/lower_u64/upper_u64 only;
        // PER's `integer::encode_int`/`uinteger::encode_uint`
        // (rust-runtime/wire/src/per) additionally read range_bits, and are the
        // only reason a member of this shape needs its row's `constraints`
        // reference at all (see
        // rust-runtime/wire/src/per/sequence.rs's own MemberAccess doc for
        // why a shared native type can't carry per-declaration PER shape
        // via a type-level trait impl). Emitted as `asn1cpp_wire::
        // constraints::Constraints` text — the same type both the BER/XER
        // and PER legs read, one shared module since gambas-asn1#537/#539.
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
                "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,\n"
                "}};\n\n",
                cname, flags, std::max(spec.range_bits, 0), spec.lower_s64, spec.upper_s64);
        } else if (spec.storage_kind == IntStorageKind::U64) {
            int flags = (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0) |
                        (spec.semi_constrained ? asn1::Constraints::SEMI_CONSTRAINED : asn1::Constraints::CONSTRAINED);
            os << std::format(
                "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
                "    flags: {}, range_bits: {}, lower_bound: 0, upper_bound: 0, lower_u64: {}u64, upper_u64: {}u64, "
                "size_range_bits: 0, size_lower: 0, size_upper: 0, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,\n"
                "}};\n\n",
                cname, flags, std::max(spec.range_bits, 0), spec.lower_u64, spec.upper_u64);
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
    // deliberate improvement over C++, not a parity gap.
    int flags = spec.has_size_constraint
        ? (asn1::Constraints::SIZE_CONSTRAINED | (spec.extensible ? asn1::Constraints::EXTENSIBLE : 0))
        : 0;
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
        // Decode-direction counterpart (X.691 §26.5.4/§26.5.7 decode:
        // ordinal -> character) — `per::strings::decode_string`'s own
        // table, `spec.alphabet` already sorted ascending by
        // `extract_from_alphabet` (its own doc).
        std::string alpha_ident = std::format("{}_ALPHA", to_screaming_snake_case(spec.tname));
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
        "alphabet_bits: {}, alphabet: {}, alphabet_size: {}, element: None,\n"
        "}};\n\n",
        cname, flags, spec.size_range_bits, spec.size_lower, size_upper, encode_table_expr,
        alphabet_bits, alphabet_expr, spec.alphabet.size());
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
    // Plain `static` data, not a generated per-type function
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
    // a deliberate improvement over C++'s own
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
        element_expr = std::format("Some(&{}_CONSTRAINTS)",
            to_screaming_snake_case(spec.elem_ref));
    }
    os << std::format(
        "pub static {}: asn1cpp_wire::constraints::Constraints = asn1cpp_wire::constraints::Constraints {{\n"
        "    flags: {}, range_bits: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
        "size_range_bits: {}, size_lower: {}, size_upper: {}, encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: {},\n"
        "}};\n\n",
        cname, flags, spec.range_bits, spec.size_lower, size_upper, element_expr);

    std::string natural_tag = std::format("asn1cpp_wire::spec::sequence::{}", spec.is_set_of ? "SET_TAG" : "SEQUENCE_TAG");
    // Honor a top-level [n] IMPLICIT/EXPLICIT tag on this type assignment
    // itself (X.690 §8.14) — same fix emit_sequence_definition already has.
    std::string tag_expr = spec.tag ? format_tag_literal(*spec.tag) : natural_tag;
    os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", spec.type_name);
    os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n";
    os << std::format("        {}\n", tag_expr);
    os << "    }\n\n";
    os << "    fn xer_element_name(&self) -> &'static str {\n";
    os << std::format("        \"{}\"\n", spec.xer_name);
    os << "    }\n\n";
    os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
    os << "        asn1cpp_wire::ber::sequence::encode_seq_of_content(out, &self.0);\n";
    os << "    }\n\n";
    os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n";
    os << "        self.0 = asn1cpp_wire::ber::sequence::decode_seq_of_content(content)?;\n";
    os << "        Ok(())\n";
    os << "    }\n";
    // Always real now — encode_seq_of_xer/decode_seq_of_xer (sequence.rs)
    // derive the per-element X.693 §12 tag from each element's own
    // Asn1Value::xer_element_name() generically, same as the member-level
    // SeqOf/TaggedSeqOf emission (see that lambda's own doc). When this
    // type declared its own X.693 §12 element identifier
    // (`SEQUENCE OF id INTEGER`), spec.elem_xer_name carries it through to
    // the _named variant (ignored by ENUMERATED/CHOICE/NULL elements —
    // see Asn1Value::xer_encode_seqof_element's own doc, rust-runtime/wire).
    os << "\n";
    os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
    if (spec.elem_xer_name) {
        os << std::format("        asn1cpp_wire::ber::sequence::encode_seq_of_xer_named(out, &self.0, depth, Some(\"{}\"));\n", *spec.elem_xer_name);
    } else {
        os << "        asn1cpp_wire::ber::sequence::encode_seq_of_xer(out, &self.0, depth);\n";
    }
    os << "    }\n\n";
    os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
    if (spec.elem_xer_name) {
        os << std::format("        self.0 = asn1cpp_wire::ber::sequence::decode_seq_of_xer_named(r, Some(\"{}\"))?;\n", *spec.elem_xer_name);
    } else {
        os << "        self.0 = asn1cpp_wire::ber::sequence::decode_seq_of_xer(r)?;\n";
    }
    os << "        Ok(())\n";
    os << "    }\n";
    // `Asn1Value::validate()`'s default (`value.rs`) is `0` — this override
    // is only needed when there's a real SIZE constraint to check, unlike
    // `{cname}` above (always emitted, unconditionally, so the member-row
    // loop's name-derivation never has to guess whether it exists). Plain
    // trait override, not a MemberDescriptor fn-pointer: every named or
    // synthetic SEQUENCE OF/SET OF type is genuinely its own distinct Rust
    // type (unlike INTEGER's shared `i64`), so it can carry its own
    // constraint directly.
    os << std::format("\n    fn constraints(&self) -> &'static asn1cpp_wire::constraints::Constraints {{\n        &{}\n    }}\n\n", cname);
    if (spec.has_size_constraint) {
        os << std::format("\n    fn validate(&self, _c: &asn1cpp_wire::constraints::Constraints) -> i64 {{\n        asn1cpp_wire::constraints::validate_size(self.0.len(), &{})\n    }}\n", cname);
    }
    // PER leg (X.691 §19/§20 — SIZE against this type's own {cname}
    // table, each element against {cname}'s own `element` field, exactly
    // the same runtime pair a member-embedded SeqOf<T>/SetOf<T> already
    // calls, `ber::sequence`'s own impl) — a named SEQUENCE OF/SET OF
    // owns its constraint, same convention SEQUENCE/CHOICE/ENUMERATED use,
    // so `_c` (the caller's row-level constraint, meaningless for a type
    // that carries its own) is ignored.
    os << std::format(
        "\n    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {{\n"
        "        asn1cpp_wire::per::seq_of::encode_seq_of_content(w, &{0}, &self.0);\n    }}\n",
        cname);
    os << std::format(
        "\n    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {{\n"
        "        self.0 = asn1cpp_wire::per::seq_of::decode_seq_of_content(r, &{0})?;\n        Ok(())\n    }}\n",
        cname);
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
///        `asn1cpp_wire::ber::sequence::SeqOf<T>` (rust-runtime/wire/src/sequence.rs),
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
    return std::format("asn1cpp_wire::ber::sequence::SeqOf<{}>", mtype.substr(4, mtype.size() - 5));
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
    return std::format("asn1cpp_wire::ber::sequence::{}<{}>",
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
///        (`rust-runtime/wire/src/sequence.rs`) instead of a raw
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
///       value under `--target=rust`. `ops`/`tdref`/`def_setter`/`offset_expr` are
///       C++-runtime-only (per SequenceMemberSpec's own doc) and unused
///       here; optional members become `Option<T>` rather than C++'s
///       `unique_ptr<T>`, Rust's natural equivalent.
/// @brief Does `m` get a real access closure (Scalar/TaggedScalar/
///        ExplicitScalar/SeqOf), or an `Unsupported` stub?
///        Every SEQUENCE/SET always gets a full table now regardless of the
///        answer (see `sequence::MemberAccess::Unsupported`'s doc,
///        rust-runtime/wire) — this only decides this one row's shape.
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
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
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
        os << std::format("    /// ASN.1: `{}`\n", m.asn1_name);
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
    // Human-readable reason baked into an Unsupported row's stub panic
    // message — best-effort diagnosability, not meant to be exhaustive.
    auto stub_reason = [](const SequenceMemberSpec& m) -> const char* {
        if (m.seq_of_kind != SeqOfKind::None) return "SEQUENCE OF/SET OF element type/tag/optionality combination not yet supported";
        if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) return "untagged ANY has no tag to detect presence";
        if (!m.mbuiltin) return "OPTIONAL member of an untagged type has no tag to detect presence";
        return "builtin type/storage combination not yet supported";
    };
    // PER coverage, per-row granularity — mirrors BER's own
    // `sequence_member_covered`: a not-yet-representable member gets its
    // own `asn1cpp_wire::per::sequence::MemberAccess::Unsupported` stub row
    // (panics only if actually reached) rather than withholding the whole
    // type's `PerValue` impl. Scope for now: a member whose ASN.1 type is
    // *directly* a builtin INTEGER (S64/U64 storage) or a character string
    // kind (`per_string_covered`'s own doc for exactly which), or a
    // TypeRef member whose resolved target is ENUMERATED, a
    // named INTEGER type, or another named SEQUENCE/CHOICE/SET
    // (`m.ref_kind`; all three are always representable regardless of
    // anything else, since the referenced type either always gets a
    // PerValue impl unconditionally (ENUMERATED, a named INTEGER's own
    // PER_CONSTRAINTS) or — for a composite `Other` target — is *itself*
    // guaranteed a PerValue impl by this same unconditional-emission
    // policy, recursively). `m.is_explicit`/`m.resolved_tag->
    // tag_is_override` are deliberately *not* checked: X.691 defines PER
    // encoding purely in terms of a type's abstract value structure — a
    // tag (natural, IMPLICIT-retagged including AUTOMATIC TAGS, or even
    // EXPLICIT) never changes a member's PER wire bytes at all. Confirmed
    // empirically against a live PerCodec run: `a [0] INTEGER(0..15)`,
    // `a [0] EXPLICIT INTEGER(0..15)`, and the same field under `AUTOMATIC
    // TAGS` with no `[n]` written at all, all three encode to identical
    // PER bytes. This matters in practice: 3GPP RRC's own PDU-definitions
    // module uses `AUTOMATIC TAGS` throughout, which would otherwise
    // exclude nearly every member in the schema.
    auto per_member_covered = [](const SequenceMemberSpec& m) -> bool {
        if (m.seq_of_kind != SeqOfKind::None) {
            // `SeqOf<T>`/`SetOf<T>`'s own PER impl (`ber::sequence`) is
            // fully generic over `T: Asn1Value` — it never inspects `T`'s
            // kind, just calls `T::per_encode`/`per_decode_into` per
            // element against the collection's own `element` Constraints
            // (`emit_seq_of_definition`'s own doc). So this only needs to
            // ask whether the element's *own* shape has a real PerValue
            // impl — recursing through any nesting depth — not whether
            // it's specifically INTEGER. A composite (TypeRef/SEQUENCE/
            // CHOICE) leaf is always safe: it owns its own constraint and
            // ignores whatever `element` is passed, same as any other
            // composite member. A builtin leaf is safe under the exact
            // same rule `per_builtin_covered` already applies one level
            // up — `has_own_descriptor`/`elem_ref` already threads a real
            // per-element constraint table generically for any builtin
            // kind (not just INTEGER), so nothing new is needed there.
            return per_elem_shape_covered(m.elem_shape);
        }
        if (m.mbuiltin)
            return per_builtin_covered(*m.mbuiltin, m.storage_kind);
        return m.ref_kind == SequenceMemberSpec::RefTargetKind::Enumerated ||
               m.ref_kind == SequenceMemberSpec::RefTargetKind::IntegerAlias ||
               m.ref_kind == SequenceMemberSpec::RefTargetKind::Other;
    };
    // Human-readable reason baked into an Unsupported PER row's stub
    // panic message — mirrors the BER-side `stub_reason` lambda above,
    // separate function since the PER and BER coverage boundaries differ
    // (e.g. SEQUENCE OF is BER-covered but PER-Unsupported).
    auto per_stub_reason = [](const SequenceMemberSpec& m) -> const char* {
        if (m.seq_of_kind != SeqOfKind::None) return "SEQUENCE OF/SET OF PER encoding not yet supported";
        if (m.mbuiltin) return "builtin type/storage combination not yet supported for PER";
        return "referenced type has no PerValue impl";
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

        os << std::format("static {}: [asn1cpp_wire::spec::sequence::MemberDescriptor<{}>; {}] = [\n",
                          members_ident, spec.type_name, spec.members.size());
        for (const auto& m : spec.members) {
            os << "    asn1cpp_wire::spec::sequence::MemberDescriptor {\n";
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
                os << "        tag: asn1cpp_wire::spec::sequence::SEQUENCE_TAG,\n";
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_wire::spec::sequence::MemberAccess::Unsupported {{ reason: \"{}\", get: |v| &v.{}, get_mut: |v| &mut v.{} }},\n",
                                  stub_reason(m), m.mname, m.mname);
            } else if (m.mbuiltin && *m.mbuiltin == ast::BuiltinType::Any) {
                // `[n] ANY` — always EXPLICIT (sequence_member_covered
                // only lets this branch's precondition through when so).
                // The field is `Any`/`Option<Any>` (native_builtin_type),
                // a real `Asn1Value` whose own `ber_encode`/`ber_decode_into`
                // replay/capture the raw TLV verbatim (any.rs's own doc),
                // so this goes through the same generic ExplicitScalar
                // path every other EXPLICIT-tagged member uses — no
                // per-member closure needed.
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << std::format("        access: asn1cpp_wire::spec::sequence::MemberAccess::ExplicitScalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
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
                os << std::format("        access: asn1cpp_wire::spec::sequence::MemberAccess::ExplicitScalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
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
                os << std::format("        access: asn1cpp_wire::spec::sequence::MemberAccess::TaggedScalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
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
                // Asks the member's own Rust type for its tag
                // instead of a per-builtin-kind switch —
                // works uniformly for every covered builtin, since every
                // one now implements `type_tag::TypeTag` (#547 gave each
                // one a real wrapper type).
                std::string tag_text = !m.mbuiltin
                    ? (m.resolved_tag ? format_tag_literal(*m.resolved_tag)
                                       : "asn1cpp_wire::spec::sequence::SEQUENCE_TAG /* untagged CHOICE member: no fixed tag, inert for required members */")
                    : std::format("<{} as asn1cpp_wire::type_tag::TypeTag>::TAG.unwrap()", m.mtype);
                os << std::format("        tag: {},\n", tag_text);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                // BASE64 XER instruction (X.693 §21) on a direct, untagged
                // OCTET STRING member: MemberAccess::Base64Scalar instead of
                // the plain Scalar path — see that variant's own doc.
                // Combined with a tag override (EXPLICIT/IMPLICIT) this
                // still falls through the ordinary Scalar path above/below
                // instead (no Base64*Tagged*Scalar variant yet) — narrower
                // in scope than CppBackend's own per-member TypeDescriptor,
                // which reads xer_encoding independently of tagging.
                bool base64_scalar = m.mbuiltin && *m.mbuiltin == ast::BuiltinType::OctetString
                                   && m.xer_encoding == ast::XerEncoding::Base64;
                os << std::format("        access: asn1cpp_wire::spec::sequence::MemberAccess::{} {{ get: |v| &v.{}, get_mut: |v| &mut v.{} }},\n",
                                  base64_scalar ? "Base64Scalar" : "Scalar", m.mname, m.mname);
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
            // constraint fallback (`type_descriptor_ref_for`) never
            // produces that prefix. `cname` itself is recomputed from
            // `tname`'s deterministic naming, not read back off stored
            // data — same table `constraints::validate_s64`/`validate_u64`/
            // `validate_size` (rust-runtime/wire/src/constraints.rs) read,
            // never a per-member generated function.
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
            // The declaration's own Constraints table, when this member has
            // one (`tdref` is "&" + tname only when
            // `build_member_type_descriptor_spec` built a spec for it): the
            // walker hands it to the member's `Asn1Value::validate` through
            // the row's own accessor, so no per-kind closure is needed —
            // INTEGER (S64/U64), OCTET STRING/BIT STRING and every
            // character string kind (SIZE, plus the FROM alphabet's
            // `encode_table` for the string kinds) all read the same table
            // shape. A member whose type owns its constraint (a named
            // generated type) gets `None`: its own `validate` is reached
            // through `ber_encode_tagged`'s `validate::check`.
            std::string constraints_expr = "None";
            bool own_table = !m.tdref.empty();
            if (m.mbuiltin && own_table &&
                ((*m.mbuiltin == ast::BuiltinType::Integer &&
                  (m.storage_kind == IntStorageKind::S64 || m.storage_kind == IntStorageKind::U64)) ||
                 *m.mbuiltin == ast::BuiltinType::OctetString || *m.mbuiltin == ast::BuiltinType::BitString ||
                 is_sizeable_string_kind(*m.mbuiltin))) {
                constraints_expr = std::format("Some(&{}_CONSTRAINTS)",
                    to_screaming_snake_case(std::format("asn_TYP_{}_{}", spec.type_name, m.mname)));
            } else if (m.seq_of_kind != SeqOfKind::None) {
                // Inline SEQUENCE OF/SET OF member: the field's own Rust
                // type is the generic `SeqOf<T>`/`SetOf<T>` wrapper shared
                // by every inline collection member, so it carries no
                // constraint of its own. `Generator::collect` always
                // promotes an inline collection member to its own synthetic
                // named type as a side effect (`synthetic_name` reproduces
                // that exact name), and `emit_seq_of_definition` always
                // emits that type's `..._CONSTRAINTS` table — real bounds
                // or `flags: 0` — so the reference is always valid.
                // Fully qualified (`crate::{module}::{const}`), not a bare
                // reference: the synthetic type lives in its own generated
                // module, and nothing else in this file names it.
                std::string synth = synthetic_name(spec.type_name, m.asn1_name);
                constraints_expr = std::format("Some(&crate::{}::{}_CONSTRAINTS)", to_snake_case(synth),
                                                to_screaming_snake_case(synth));
            }
            os << std::format("        constraints: {},\n", constraints_expr);
            // PER reads the same row; `per_unsupported` names the reason
            // this member has no PER encoding yet (`per_member_covered`).
            os << std::format("        per_unsupported: {},\n",
                              per_member_covered(m) ? std::string("None")
                                                    : std::format("Some(\"{}\")", per_stub_reason(m)));
            os << "    },\n";
        }
        os << "];\n\n";

        // pub, not private static — a composite member
        // elsewhere (a different generated module) needs to name this SPEC
        // directly (encode_sequence_tagged/decode_sequence_tagged) when this
        // type is IMPLICITLY retagged as one of its members.
        os << std::format(
            "pub static {}: asn1cpp_wire::spec::sequence::SequenceSpec<{}> = asn1cpp_wire::spec::sequence::SequenceSpec {{\n",
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
                                   : std::format("asn1cpp_wire::spec::sequence::{}", spec.is_set ? "SET_TAG" : "SEQUENCE_TAG"));
        os << std::format("    members: &{},\n", members_ident);
        os << std::format("    ext_at: {},\n", spec.ext_at);
        // Root OPTIONAL/DEFAULT member count (X.691 §18.1 preamble bitmap
        // width) — already computed backend-agnostically (Generator.cpp),
        // read here rather than recounted at runtime.
        os << std::format("    roms_count: {},\n", spec.roms_count);
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_wire::ber::sequence::encode_sequence(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::ber::sequence::decode_sequence(&{}, data)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn encode_xer(&self) -> String {\n";
        os << std::format("        asn1cpp_wire::xer::encode_sequence_xer(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::xer::decode_sequence_xer(&{}, xml)\n", spec_ident);
        os << "    }\n";
        os << "}\n\n";


        // Makes this type usable as a nested composite member elsewhere —
        // emitted unconditionally whenever this type has at least one
        // member, same as the table above. A member/alternative referencing
        // this type never needs to check anything about it in advance (see
        // sequence_member_covered's own doc) — it's always real,
        // BER/XER/PER all three; any individual member row that isn't
        // itself representable yet is an Unsupported stub (panics only if
        // actually reached), not a reason to withhold this whole impl.
        // One merged Asn1Value impl (gambas-asn1#537 unified what used to
        // be two separate traits/impl blocks, asn1cpp_wire::value::Asn1Value
        // and asn1cpp_wire::value::Asn1Value).
        os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n";
        os << std::format("        {}.tag\n", spec_ident);
        os << "    }\n\n";
        os << "    fn xer_element_name(&self) -> &'static str {\n";
        os << std::format("        \"{}\"\n", spec.xer_name);
        os << "    }\n\n";
        os << "    fn ber_encode_content(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_wire::ber::sequence::encode_sequence_content(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        let mut r = asn1cpp_wire::Reader::new(content);\n";
        os << std::format("        *self = asn1cpp_wire::ber::sequence::decode_sequence_content(&{}, &mut r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << std::format("        asn1cpp_wire::xer::encode_sequence_xer_into(&{}, self, out, depth);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_wire::xer::decode_sequence_xer_from(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";

        // PER leg (merged into the same impl block, gambas-asn1#537).
        os << "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {\n";
        os << std::format("        asn1cpp_wire::per::sequence::encode_sequence_content(&{}, w, self);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_wire::per::sequence::decode_sequence_content(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n";
        os << "}\n\n";
        // Mirrors this type's own ber_natural_tag() — a member/
        // alternative referencing this type by name can ask for its
        // tag without an Asn1Value in hand.
        os << "\n";
        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", spec.type_name);
        os << std::format("    const TAG: Option<asn1cpp_wire::Tag> = Some({}.tag);\n", spec_ident);
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
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
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
        os << std::format("    /// ASN.1: `{}`\n", a.asn1_name);
        os << std::format("    {}({}{}{}),\n", vname,
                          boxed ? "Box<" : "", rust_seqof_alt_mtype(a.mtype), boxed ? ">" : "");
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
    // decode_choice_xer, rust-runtime/wire/src/choice.rs) instead of a
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
    // BER dispatch: wire tag -> alternative index, precomputed here.
    // `spec.ber_tags` (Backend.hpp) already flattens an untagged
    // CHOICE-typed alternative into one entry per tag of the inner CHOICE
    // (X.690 §8.13); otherwise each tagged alternative contributes its own.
    // X.690 §8.1.2.2 class-bit encoding — mirrors Generator.cpp's own
    // `tag_class_rank` (used there to sort `spec.ber_tags`) and Rust's
    // `Tag::identifier_key` (`ber::tag.rs`) exactly. Deliberately not
    // `Backend::tag_class_index` (Backend.hpp) — that helper's
    // Private/Context order is swapped relative to the wire encoding
    // (fine for its own purpose, an arbitrary per-backend literal-string
    // array index), which would silently disagree with the other two.
    auto ber_choice_tag_class_rank = [](ast::TagClass cls) -> int {
        switch (cls) {
        case ast::TagClass::Universal:   return 0;
        case ast::TagClass::Application: return 1;
        case ast::TagClass::Context:     return 2;
        case ast::TagClass::Private:     return 3;
        default:                         return 4;
        }
    };
    // Carries each row's own (class, number) — not just the formatted
    // literal text — so the table can be sorted below regardless of which
    // branch built it: `has_ber_table` rows arrive pre-sorted
    // (`Generator::collect_ber_tags_for`'s own doc), the plain per-
    // alternative case doesn't. `Tag::identifier_key`
    // (`ber::tag.rs`)/`tag_class_rank` (`Generator.cpp`) agree on the same
    // class-rank order, so a table built here sorts identically to how
    // `ber::choice::decode_choice_dispatch` binary-searches it.
    struct DispatchRow { int cls_rank; int64_t number; std::string tag_lit; size_t idx; };
    std::vector<DispatchRow> dispatch;
    if (spec.has_ber_table) {
        for (const auto& e : spec.ber_tags)
            dispatch.push_back({ber_choice_tag_class_rank(e.cls), e.number, e.tag_literal, static_cast<size_t>(e.alt_index)});
    } else {
        for (size_t i = 0; i < spec.alternatives.size(); ++i)
            if (choice_alternative_has_tag(spec.alternatives[i])) {
                const auto& t = *spec.alternatives[i].resolved_tag;
                dispatch.push_back({ber_choice_tag_class_rank(t.cls), t.number, format_tag_literal(t), i});
            }
    }
    std::sort(dispatch.begin(), dispatch.end(), [](const DispatchRow& a, const DispatchRow& b) {
        return std::pair(a.cls_rank, a.number) < std::pair(b.cls_rank, b.number);
    });
    if (!dispatch.empty()) {
        std::string alts_ident = std::format("{}_ALTERNATIVES", to_screaming_snake_case(spec.type_name));
        std::string tags_ident = std::format("{}_BER_TAGS", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        auto per_alt_covered = [](const ChoiceAlternativeSpec& a) -> bool {
            if (a.mbuiltin)
                return per_builtin_covered(*a.mbuiltin, a.storage_kind);
            return a.ref_kind == ChoiceAlternativeSpec::RefTargetKind::Enumerated ||
                   a.ref_kind == ChoiceAlternativeSpec::RefTargetKind::IntegerAlias ||
                   a.ref_kind == ChoiceAlternativeSpec::RefTargetKind::Other;
        };

        os << std::format("static {}: [asn1cpp_wire::spec::choice::Alternative<{}>; {}] = [\n",
                          alts_ident, spec.type_name, spec.alternatives.size());
        for (const auto& a : spec.alternatives) {
            std::string vname = variant_name(*this, a.asn1_name);
            std::string variant_path = std::format("{}::{}", spec.type_name, vname);
            // How BER frames the payload; XER and PER read the same
            // payload through `active`/`emplace` and ignore it.
            std::string ber;
            if (!choice_alternative_covered(a)) {
                ber = "asn1cpp_wire::spec::choice::BerTagging::Unsupported(\"alternative not yet supported\")";
            } else if (a.resolved_tag && a.is_explicit && a.resolved_tag->tag_is_override) {
                // EXPLICIT (X.690 §8.14.3): an outer TLV around the payload.
                ber = std::format("asn1cpp_wire::spec::choice::BerTagging::Explicit({})", format_tag_literal(*a.resolved_tag));
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
            // The PER constraints table the alternative's payload encodes
            // against: the inline SIZE/range table emitted for it when
            // `tdref` names one, the shared unconstrained value otherwise.
            std::string alt_constraints = "&asn1cpp_wire::constraints::UNCONSTRAINED";
            if (a.mbuiltin && !a.tdref.empty()) {
                alt_constraints = "&" + to_screaming_snake_case(std::format("asn_TYP_{}_{}", spec.type_name, unescape_raw_ident(a.accessor_name))) + "_CONSTRAINTS";
            }
            // A single-variant enum (not extensible) needs an irrefutable
            // `let` instead of `match`, which would warn on its wildcard arm.
            std::string active = single_alt
                ? std::format("|x| {{ let {0}(v) = x; Some(v) }}", variant_path)
                : std::format("|x| match x {{ {0}(v) => Some(v), _ => None }}", variant_path);
            std::string emplace = single_alt
                ? std::format("|x| {{ *x = {0}(Default::default()); let {0}(v) = x; v }}", variant_path)
                : std::format("|x| {{ *x = {0}(Default::default()); match x {{ {0}(v) => v, _ => unreachable!() }} }}", variant_path);
            os << "    asn1cpp_wire::spec::choice::Alternative {\n";
            os << std::format("        name: \"{}\",\n", a.asn1_name);
            os << std::format("        ber: {},\n", ber);
            os << std::format("        active: {},\n", active);
            os << std::format("        emplace: {},\n", emplace);
            os << std::format("        constraints: {},\n", alt_constraints);
            os << std::format("        per_unsupported: {},\n",
                              per_alt_covered(a) ? std::string("None") : std::string("Some(\"alternative not yet supported for PER\")"));
            os << "    },\n";
        }
        os << "];\n\n";

        // Emitted in the sorted order computed above — matches
        // `Tag::identifier_key` (`ber::tag.rs`) so `ber::choice::
        // decode_choice_dispatch` can binary-search this table.
        os << std::format("static {}: [asn1cpp_wire::spec::choice::BerDispatch; {}] = [\n", tags_ident, dispatch.size());
        for (const auto& row : dispatch)
            os << std::format("    asn1cpp_wire::spec::choice::BerDispatch {{ tag: {}, alt: {} }},\n", row.tag_lit, row.idx);
        os << "];\n\n";

        os << std::format(
            "static {}: asn1cpp_wire::spec::choice::ChoiceSpec<{}> = asn1cpp_wire::spec::choice::ChoiceSpec {{\n",
            spec_ident, spec.type_name);
        // X.693 §8.3.1 — document-root XMLTypedValue wrapper name, used only
        // by encode_choice_xer/decode_choice_xer (never by the _into
        // nested variants, and never for BER).
        os << std::format("    name: \"{}\",\n", spec.xer_name);
        os << std::format("    alternatives: &{},\n", alts_ident);
        os << std::format("    ber_tags: &{},\n", tags_ident);
        if (spec.ext_at >= 0) {
            // Wire the UnknownExtension variant (declared
            // in emit_choice_declaration) into the runtime's fallback path —
            // construct captures an unrecognized-tag TLV on decode, extract
            // hands it back to encode_choice for byte-identical re-encoding.
            os << "    unknown_extension: Some(asn1cpp_wire::spec::choice::UnknownExtensionOps {\n";
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
        os << std::format("    ext_at: {},\n", spec.ext_at);
        // X.691 §22.6 — bit width of the root-alternative index, already
        // computed backend-agnostically (Generator.cpp); per::choice reads
        // it instead of recomputing it per call.
        os << std::format("    range_bits: {},\n", spec.range_bits);
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_wire::ber::choice::encode_choice(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::ber::choice::decode_choice(&{}, data)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn encode_xer(&self) -> String {\n";
        os << std::format("        asn1cpp_wire::ber::choice::encode_choice_xer(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::ber::choice::decode_choice_xer(&{}, xml)\n", spec_ident);
        os << "    }\n";
        os << "}\n\n";


        // Makes this type usable as a nested composite member elsewhere —
        // see emit_sequence_definition's identical Asn1Value impl for the
        // full rationale (always emitted now, BER/XER/PER all three, once
        // this CHOICE has at least one taggable alternative). One merged
        // Asn1Value impl (gambas-asn1#537 unified what used to be two
        // separate traits/impl blocks, asn1cpp_wire::value::Asn1Value and
        // asn1cpp_wire::value::Asn1Value).
        os << std::format("impl asn1cpp_wire::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_natural_tag(&self) -> asn1cpp_wire::Tag {\n";
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
        os << "    fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << "        unreachable!(\"CHOICE has no content-only representation — ber_decode_into is overridden directly\")\n";
        os << "    }\n\n";
        os << "    fn ber_encode(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_wire::ber::choice::encode_choice_into(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_into(&mut self, r: &mut asn1cpp_wire::Reader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::ber::choice::decode_choice_into(&{}, self, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n\n";
        // `encode_choice_xer_into` deliberately ends right after the
        // chosen alternative's own closing tag — no trailing `\n` +
        // `indent(depth)` (its own doc, rust-runtime/wire/src/choice.rs).
        // A CHOICE-typed member's own wrapper (`<mname>`, written by
        // `encode_sequence_xer_content`) does immediately follow, so
        // `xer_encode` itself (used for exactly that context) adds that
        // trailing bit here — mirrors `SequenceXerHandler`'s own
        // CHOICE-typed-member special case in C++, which writes its own
        // `s.indent(1) << "</" << mbr.name` closing line external to
        // `ChoiceXerHandler` for the very same reason.
        os << "    fn xer_encode(&self, out: &mut String, depth: usize) {\n";
        os << std::format("        asn1cpp_wire::ber::choice::encode_choice_xer_into(&{}, self, out, depth);\n", spec_ident);
        os << "        out.push('\\n');\n";
        os << "        out.push_str(&asn1cpp_wire::xer::indent(depth));\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into(&mut self, r: &mut asn1cpp_wire::xer::XerReader) -> Result<(), asn1cpp_wire::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::ber::choice::decode_choice_xer_into(&{}, self, r)?;\n", spec_ident);
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
        // doc, rust-runtime/wire/src/choice.rs) — `encode_seq_of_xer_named`
        // (sequence.rs) checks for it to avoid doubling up with its own
        // trailing separator.
        os << "    fn xer_encode_seqof_element(&self, out: &mut String, depth: usize, _name_override: std::option::Option<&str>) {\n";
        os << std::format("        asn1cpp_wire::ber::choice::encode_choice_xer_into(&{}, self, out, depth + 1);\n", spec_ident);
        os << "        out.push('\\n');\n";
        os << "    }\n\n";
        os << "    fn xer_decode_into_seqof_element(&mut self, r: &mut asn1cpp_wire::xer::XerReader, _name_override: std::option::Option<&str>) -> Result<(), asn1cpp_wire::DecodeError> {\n";
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
            os << "    fn ber_encode_tagged(&self, tag: asn1cpp_wire::Tag, out: &mut Vec<u8>) {\n";
            os << std::format("        asn1cpp_wire::ber::choice::encode_choice_tagged(&{}, self, tag, out);\n", spec_ident);
            os << "    }\n\n";
            os << "    fn ber_decode_into_tagged(&mut self, r: &mut asn1cpp_wire::Reader, tag: asn1cpp_wire::Tag) -> Result<(), asn1cpp_wire::DecodeError> {\n";
            os << std::format("        asn1cpp_wire::ber::choice::decode_choice_tagged_into(&{}, self, r, tag)?;\n", spec_ident);
            os << "        Ok(())\n";
            os << "    }\n";
        }

        // PER leg (merged into the same impl block, gambas-asn1#537).
        os << "    fn per_encode(&self, w: &mut asn1cpp_wire::per::writer::Writer, _c: &asn1cpp_wire::constraints::Constraints) {\n";
        os << std::format("        asn1cpp_wire::per::choice::encode_choice_content(&{}, w, self);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn per_decode_into(&mut self, r: &mut asn1cpp_wire::per::reader::Reader, _c: &asn1cpp_wire::constraints::Constraints) -> Result<(), asn1cpp_wire::per::reader::DecodeError> {\n";
        os << std::format("        asn1cpp_wire::per::choice::decode_choice_content_into(&{}, self, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n";
        os << "}\n\n";
        // CHOICE has no natural tag (X.680 §28).
        os << "\n";
        os << std::format("impl asn1cpp_wire::type_tag::TypeTag for {} {{\n", spec.type_name);
        os << "    const TAG: Option<asn1cpp_wire::Tag> = None;\n";
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
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
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
    if (!spec.asn1_name.empty()) os << std::format("/// ASN.1: `{}`\n", spec.asn1_name);
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
///       (escape(to_snake_case(filename))), not the raw filename — see
///       finalize_output's own `#[path = ...]` module declaration. `filename`
///       here is still the on-disk file stem (PascalCase, matching
///       `type_name`), so it must be re-derived into the same snake_case
///       identifier finalize_output declared the module under, or this
///       `use` path wouldn't resolve. The `escape()` wrap matters for a type
///       named e.g. "Type" — its snake_case module name "type" collides with
///       the Rust keyword and needs `r#type` raw-identifier escaping,
///       exactly the same mechanism member_name() already applies.
void RustBackend::emit_type_reference(const std::string& type_name, const std::string& filename,
                                       TypeOutputSession& session) const {
    session.buffer(declaration_extension())
        << std::format("use crate::{}::{};\n", escape(to_snake_case(filename)), type_name);
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
/// @note module *identifier* is snake_case
///       (`pub mod contact_list;`), not the PascalCase file stem — Rust
///       convention wants snake_case module names even though the type
///       inside is (correctly) PascalCase; a bare `pub mod ContactList;`
///       fails rustc's non_snake_case lint. `#[path = "ContactList.rs"]`
///       keeps the on-disk filename PascalCase (matching `type_name`/
///       `filename_for`) while giving the module itself a snake_case Rust
///       identifier — emit_type_reference's `use` paths re-derive the same
///       escape(to_snake_case(filename)) so the two stay in sync without a
///       second source of truth.
void RustBackend::finalize_output(const std::string& out_dir) const {
    namespace fs = std::filesystem;
    fs::path lib_rs = fs::path(out_dir) / "lib.rs";
    std::ofstream lib(lib_rs);
    for (const auto& entry : fs::directory_iterator(out_dir)) {
        if (entry.path().extension() != ".rs" || entry.path() == lib_rs) continue;
        std::string stem = entry.path().stem().string();
        lib << std::format("#[path = \"{}.rs\"] pub mod {};\n", stem, escape(to_snake_case(stem)));
    }
}

} // namespace asn1::codegen
