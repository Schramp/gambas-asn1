#include "RustBackend.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
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
///        drive this (e.g. OCTET STRING/BIT STRING/OBJECT IDENTIFIER/Any all
///        map to "Vec<u8>", but need different tags).
/// @note `mtype` (not `storage_kind`) for the Integer case
///       specifically because this function is also called for SEQUENCE OF
///       *element* coverage (elem_builtin/elem_mtype — no storage_kind
///       counterpart); the member/alt-level callers
///       (rust_tag_for_builtin_or_alias) intercept Integer via storage_kind
///       before ever reaching this switch.
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
    // Not yet covered — no Asn1Value impl in rust-runtime/ber for these
    // kinds yet, so a member of any of them falls back to struct-shape-only
    // codegen (no encode()/decode() at all if any member is uncovered).
    // Only ANY remains uncovered here (gambas-asn1#330 — separate, still
    // open). Enumerated never reaches this switch — routed through the
    // wholly separate emit_enumerated/EnumeratedSpec path.
    default:                                 return nullptr;
    }
}

/// @brief Is `bt` (a direct builtin member/alternative/SEQUENCE-OF-element
///        type) covered by `Asn1Value`'s XER leg? Kept as its own gate (not
///        just reusing builtin_ber_tag's BER coverage set) rather than
///        assuming the two always match — a member's own encode_xer()/
///        decode_xer() must never be emitted for a type whose Asn1Value XER
///        leg is still the trait's default, or the emitted method panics at
///        runtime. File-scope (not a per-function local lambda) so both
///        emit_sequence_definition's all_xer_ready and
///        emit_choice_definition's own equivalent gate share one
///        definition — same reasoning as builtin_ber_tag itself.
/// @note `bt == Integer` only ever checks `mtype == "i64"` here — the
///       direct-member callers (rust_member_xer_ready-equivalent lambdas)
///       intercept Integer via storage_kind before ever reaching this
///       function; only SEQUENCE OF *element* coverage (no storage_kind
///       counterpart) still needs the string check.
static bool builtin_xer_ready(ast::BuiltinType bt, const std::string& mtype) {
    switch (bt) {
    case ast::BuiltinType::Integer:     return mtype == "i64";  // element-level path only
    case ast::BuiltinType::Boolean:
    case ast::BuiltinType::Null:
    case ast::BuiltinType::Real:
    case ast::BuiltinType::BitString:
    case ast::BuiltinType::ObjectIdentifier:
    case ast::BuiltinType::RelativeOid:
    case ast::BuiltinType::OctetString:
    case ast::BuiltinType::Ia5String:
    case ast::BuiltinType::Utf8String:
    case ast::BuiltinType::NumericString:
    case ast::BuiltinType::PrintableString:
    case ast::BuiltinType::T61String:
    case ast::BuiltinType::VisibleString:
    case ast::BuiltinType::GeneralString:
    case ast::BuiltinType::GraphicString:
    case ast::BuiltinType::UniversalString:
    case ast::BuiltinType::BmpString:
    case ast::BuiltinType::VideotexString:
    case ast::BuiltinType::ObjectDescriptor:
    case ast::BuiltinType::UtcTime:
    case ast::BuiltinType::GeneralizedTime:
        return true;
    default:
        return false;
    }
}

/// @brief Same lookup as builtin_ber_tag, but for a member/alternative whose
///        own type may be a TypeRef alias rather than a direct builtin
///        (mbuiltin == nullopt) — the i64-native-INTEGER-alias case still
///        needs a tag despite carrying no mbuiltin.
/// @note The direct-builtin Integer case is intercepted
///       here via `storage_kind` (a real enum, not a string coincidence)
///       before ever reaching builtin_ber_tag's own `case Integer` —
///       builtin_ber_tag itself keeps taking `mtype` unchanged (still needed
///       string-based there for SEQUENCE OF *element* coverage, elem_builtin/
///       elem_mtype, which has no storage_kind counterpart — out of this
///       issue's scope). The `!mbuiltin` TypeRef-alias fallback below is
///       untouched too: SequenceMemberSpec/ChoiceAlternativeSpec have no
///       storage_kind for that case either (mbuiltin itself is unset), so
///       there's nothing to thread through — same pre-existing string check.
static const char* rust_tag_for_builtin_or_alias(std::optional<ast::BuiltinType> mbuiltin,
                                                  IntStorageKind storage_kind,
                                                  const std::string& mtype) {
    if (!mbuiltin) return mtype == "i64" ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
    if (*mbuiltin == ast::BuiltinType::Integer)
        // Same INTEGER_TAG regardless of storage width — the
        // Rust *type* varies (i64/u64/i128), the wire tag never does.
        // ARBITRARY (Vec<u8> storage) is excluded: collides with OCTET
        // STRING's own Asn1Value impl for that same Rust type — needs its
        // own newtype before it can get one (tracked separately).
        return (storage_kind == IntStorageKind::S64 || storage_kind == IntStorageKind::U64 ||
                storage_kind == IntStorageKind::I128)
            ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
    return builtin_ber_tag(*mbuiltin, mtype);
}

/// @brief Element type's own ASN.1 keyword, used as the per-element XER tag
///        inside a SEQUENCE OF member's own `<name>...</name>` wrapper
///        (X.693 §12 / SeqOfXerHandler, runtime/src/XerCodec.cpp — no
///        declared element identifier means the element's own type name is
///        the tag). "OCTET STRING"/"OBJECT IDENTIFIER" contain spaces
///        (invalid XML tag names) — hyphenated here; never actually
///        reachable today since OctetString/ObjectIdentifier aren't emitted
///        by builtin_ber_tag as seq-of *element* candidates requiring XER
///        (BER-only elements still get a table, just no encode_xer()/
///        decode_xer() on the enclosing type — same as any other
///        not-XER-ready member). Also doubles as the *_tagged primitives'
///        string-kind name parameter (read_char_string's error-message kind).
static const char* builtin_xer_name(ast::BuiltinType bt) {
    switch (bt) {
    case ast::BuiltinType::Integer:           return "INTEGER";
    case ast::BuiltinType::Boolean:            return "BOOLEAN";
    case ast::BuiltinType::Null:               return "NULL";
    case ast::BuiltinType::Real:               return "REAL";
    case ast::BuiltinType::BitString:          return "BIT-STRING";
    case ast::BuiltinType::ObjectIdentifier:   return "OBJECT-IDENTIFIER";
    case ast::BuiltinType::RelativeOid:        return "RELATIVE-OID";
    case ast::BuiltinType::OctetString:        return "OCTET-STRING";
    case ast::BuiltinType::Ia5String:          return "IA5String";
    case ast::BuiltinType::Utf8String:         return "UTF8String";
    case ast::BuiltinType::NumericString:      return "NumericString";
    case ast::BuiltinType::PrintableString:    return "PrintableString";
    case ast::BuiltinType::T61String:          return "T61String";
    case ast::BuiltinType::VisibleString:      return "VisibleString";
    case ast::BuiltinType::GeneralString:      return "GeneralString";
    case ast::BuiltinType::GraphicString:      return "GraphicString";
    case ast::BuiltinType::UniversalString:    return "UniversalString";
    case ast::BuiltinType::BmpString:          return "BMPString";
    case ast::BuiltinType::VideotexString:     return "VideotexString";
    case ast::BuiltinType::ObjectDescriptor:   return "ObjectDescriptor";
    case ast::BuiltinType::UtcTime:            return "UTCTime";
    case ast::BuiltinType::GeneralizedTime:    return "GeneralizedTime";
    // Same uncovered set as builtin_ber_tag's default (only Any,
    // gambas-asn1#330) — this fallback name is never actually reached in practice
    // since builtin_xer_name is only called for kinds builtin_ber_tag
    // already confirmed are covered (see call sites).
    default:                                    return "Value";
    }
}

/// @brief Which *_tagged runtime primitive family (if any) covers a given
///        builtin kind — the shared dispatch rust_tagged_ops/
///        rust_alt_tagged_ops both switch on. Deliberately stops short of
///        generating the closure bodies themselves: SEQUENCE members access
///        the value via `v.{mname}` (a struct field, possibly wrapped in
///        Option<T> for OPTIONAL) while CHOICE alternatives work with a
///        fresh local `v` (pattern-matched out of `x` on encode, built from
///        scratch on decode) — genuinely different code shapes, not worth
///        forcing through one closure-body generator.
enum class TaggedKind { None, Boolean, Integer, Real, Null, OctetString, BitString, ObjectIdentifier, RelativeOid, CharString };

// Takes storage_kind, not mtype — only ever called with
// member/alt-level data (never elem_builtin/elem_mtype), so unlike
// builtin_ber_tag/builtin_xer_ready there's no shared elem-level caller to
// keep a string-based signature for.
static TaggedKind tagged_kind_for(std::optional<ast::BuiltinType> mbuiltin, IntStorageKind storage_kind) {
    if (!mbuiltin) return TaggedKind::None;
    switch (*mbuiltin) {
    case ast::BuiltinType::Boolean:     return TaggedKind::Boolean;
    case ast::BuiltinType::Null:        return TaggedKind::Null;
    case ast::BuiltinType::Real:        return TaggedKind::Real;
    case ast::BuiltinType::Integer:
        return (storage_kind == IntStorageKind::S64 || storage_kind == IntStorageKind::U64 ||
                storage_kind == IntStorageKind::I128)
            ? TaggedKind::Integer : TaggedKind::None;
    case ast::BuiltinType::OctetString: return TaggedKind::OctetString;
    case ast::BuiltinType::BitString:   return TaggedKind::BitString;
    case ast::BuiltinType::ObjectIdentifier: return TaggedKind::ObjectIdentifier;
    case ast::BuiltinType::RelativeOid: return TaggedKind::RelativeOid;
    case ast::BuiltinType::Ia5String:
    case ast::BuiltinType::Utf8String:
    case ast::BuiltinType::NumericString:
    case ast::BuiltinType::PrintableString:
    case ast::BuiltinType::T61String:
    case ast::BuiltinType::VisibleString:
    case ast::BuiltinType::GeneralString:
    case ast::BuiltinType::GraphicString:
    case ast::BuiltinType::UniversalString:
    case ast::BuiltinType::BmpString:
    case ast::BuiltinType::VideotexString:
    case ast::BuiltinType::ObjectDescriptor:
    case ast::BuiltinType::UtcTime:
    case ast::BuiltinType::GeneralizedTime:
        return TaggedKind::CharString;
    // Same uncovered set as builtin_ber_tag's default (only Any,
    // gambas-asn1#330) — a tagged member/alternative of one of these kinds falls back
    // to the natural-tag path, which itself has no coverage either, so the
    // enclosing SEQUENCE/CHOICE gets no table at all (all_covered gates on
    // rust_member_ber_tag/rust_alt_ber_tag, not tagged_kind_for).
    default:
        return TaggedKind::None;
    }
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

        // BER leg only (matches every other Asn1Value impl this backend
        // emits — xer_encode/xer_decode_into keep the trait's default
        // panicking body). Makes this type usable as a SEQUENCE/CHOICE
        // member the same way i64/bool/etc already are (registered as
        // RustTypeKind::Enumerated in covered_type_names_ once emitted —
        // see sequence_member_ber_covered's doc) — `as i64`/TryFrom<i64>
        // convert through the shared wire
        // representation (enumerated::write_enumerated_tagged/
        // read_enumerated_tagged, X.690 §8.4).
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", tname);
        os << "    fn ber_encode(&self, out: &mut Vec<u8>) {\n";
        os << "        asn1cpp_ber::enumerated::write_enumerated_tagged(out, asn1cpp_ber::enumerated::ENUMERATED_TAG, *self as i64);\n";
        os << "    }\n\n";
        os << "    fn ber_decode_into(&mut self, r: &mut asn1cpp_ber::Reader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << "        let raw = asn1cpp_ber::enumerated::read_enumerated_tagged(r, asn1cpp_ber::enumerated::ENUMERATED_TAG)?;\n";
        os << std::format("        *self = <Self as std::convert::TryFrom<i64>>::try_from(raw)\n"
                           "            .map_err(|_| asn1cpp_ber::DecodeError::new(format!(\"invalid {} value: {{raw}}\"), 0))?;\n",
                           tname);
        os << "        Ok(())\n";
        os << "    }\n";
        os << "}\n\n";

        covered_type_names_[tname] = RustTypeKind::Enumerated;
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
    case BT::OctetString:      return "Vec<u8>";
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
    const char* tag_class_literal;
    switch (tag_spec.cls) {
    case ast::TagClass::Universal:   tag_class_literal = "asn1cpp_ber::tag::TagClass::Universal";   break;
    case ast::TagClass::Application: tag_class_literal = "asn1cpp_ber::tag::TagClass::Application"; break;
    case ast::TagClass::Private:     tag_class_literal = "asn1cpp_ber::tag::TagClass::Private";     break;
    default:                         tag_class_literal = "asn1cpp_ber::tag::TagClass::Context";     break;
    }
    return std::format("asn1cpp_ber::tag::Tag {{ class: {}, number: {}, constructed: {} }}",
                        tag_class_literal, tag_spec.number, tag_spec.constructed ? "true" : "false");
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
void RustBackend::emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << std::format("pub type {} = {};\n\n", tname, native_builtin_type(spec.builtin_type));

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
/// @param type_name   Storage type computed by Generator::cpp_type_for().
/// @param parent_name Enclosing SEQUENCE/SET type identifier.
/// @param member_name Member identifier (already backend-dispatched — snake_case).
/// @param os          Output stream to write to.
/// @note `type_name` is only genuinely backend-dispatched for Kind::Int
///       (via native_int_type) and Kind::EnumRef (via type_name()) — both
///       reused here directly. For Kind::Bool/Kind::String,
///       Generator::cpp_type_for() hardcodes a C++ runtime wrapper type
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
    std::string base = escape(to_snake_case(spec.tname));
    if (spec.kind == Kind::Integer) {
        os << std::format("pub fn {}_in_range(v: i64) -> bool {{\n", base);
        if (spec.semi_constrained || spec.hi_is_large) {
            os << std::format("    v >= {} // {}\n", spec.lower_s64,
                               spec.hi_is_large ? "upper bound exceeds i64 range, not checked"
                                                 : "semi-constrained, no upper cap");
        } else {
            os << std::format("    v >= {} && v <= {}\n", spec.lower_s64, spec.upper_s64);
        }
        os << "}\n\n";
        return;
    }
    if (!spec.has_size_constraint) return;
    std::string rust_type = native_builtin_type(spec.builtin_type);
    const char* len_expr = size_check_len_expr(spec.builtin_type);
    os << std::format("pub fn {}_size_ok(v: &{}) -> bool {{\n", base, rust_type);
    if (spec.size_bounded) {
        os << std::format("    ({0} as i64) >= {1} && ({0} as i64) <= {2}\n",
                           len_expr, spec.size_lower, spec.size_upper);
    } else {
        os << std::format("    ({} as i64) >= {} // semi-constrained, no upper cap\n",
                           len_expr, spec.size_lower);
    }
    os << "}\n\n";
}

/// @brief Emit a Rust size-check function for a SEQUENCE OF / SET OF type's
///        collection SIZE constraint (X.680 §25/26).
/// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
/// @param os   Output stream to write to.
/// @note `spec.elem_ref` is a C++ TypeDescriptor reference expression (not
///       usable by any other backend) and `spec.elem_xer_name` only matters
///       to a BER/XER runtime, so neither is used here — the emitted
///       function is generic over the element type (`Vec<T>`), matching
///       this issue's "likely Vec<T>" scoping note, and needs no element
///       type information to compile. Same "no runtime wiring yet" bar as
///       the other Rust pairings: always emitted (even when unconstrained,
///       where it degenerates to a trivial `>= 0` check) rather than
///       introducing a has-constraint field SeqOfSpec doesn't otherwise need.
void RustBackend::emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const {
    std::string fname = escape(to_snake_case(spec.type_name) + "_size_ok");
    os << std::format("pub fn {}<T>(v: &Vec<T>) -> bool {{\n", fname);
    if (spec.size_upper) {
        os << std::format("    (v.len() as i64) >= {} && (v.len() as i64) <= {}\n",
                           spec.size_lower, *spec.size_upper);
    } else {
        os << std::format("    (v.len() as i64) >= {} // semi-constrained or unconstrained, no upper cap\n",
                           spec.size_lower);
    }
    os << "}\n\n";
}

/// @brief Emit the Rust struct declaration for a SEQUENCE/SET type.
/// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
/// @param os   Output stream to write to.
/// @note `spec.members[i].mtype` is treated as an opaque, already-Rust-
///       shaped type name string, always a real `Generator::cpp_type_for()`
///       value under `--target=rust`. `ops`/`tdref`/`def_setter`/`offset_expr` are
///       C++-runtime-only (per SequenceMemberSpec's own doc) and unused
///       here; optional members become `Option<T>` rather than C++'s
///       `unique_ptr<T>`, Rust's natural equivalent.
/// @brief Is `m` covered by this backend's wire (BER) encoding — the single
///        source of truth `emit_sequence_definition`'s own member-table gate.
/// @note `mbuiltin` unset means the member's type is a TypeRef to
///       something else entirely — SEQUENCE/SET/CHOICE, ENUMERATED, or a
///       plain INTEGER subtype alias (gambas-asn1#361, separate, unrelated
///       gap). `covered_type_names_` is the only source of truth for which
///       of those actually have a real `Asn1Value` impl: `Asn1Value` is
///       object-safe, so a member row referencing `T: Asn1Value` compiles
///       fine regardless of what `T` contains, *once T's own impl actually
///       exists* — but it can't be assumed unconditionally (confirmed
///       empirically: optimistically assuming every such reference is
///       covered produced over a thousand cascading "trait bound not
///       satisfied" errors on the real schema, rooted in ENUMERATED having
///       no Asn1Value impl before that gap was closed). A member
///       referencing a type Generator hasn't emitted yet in this run
///       (declared later in the same module) conservatively gets no
///       coverage — not a regression, just not maximally complete.
bool RustBackend::sequence_member_ber_covered(const SequenceMemberSpec& m) const {
    if (m.is_seq_of)
        return !m.optional && m.elem_builtin && builtin_ber_tag(*m.elem_builtin, m.elem_mtype) != nullptr;
    if (!m.mbuiltin) {
        if (!covered_type_names_.count(m.mtype)) return false;
        // A required member's MemberDescriptor.tag is never consulted at
        // decode time (decode_sequence's Scalar/TaggedScalar branches only
        // peek it for OPTIONAL presence detection) — so a required member
        // whose type is an untagged CHOICE (no AUTOMATIC TAGS, no fixed
        // tag at all, X.680 §28) is still coverable. An OPTIONAL one isn't:
        // presence detection needs a single Tag to peek for, which a
        // tagless CHOICE member doesn't have.
        return !m.optional || m.resolved_tag.has_value();
    }
    return rust_tag_for_builtin_or_alias(m.mbuiltin, m.storage_kind, m.mtype) != nullptr;
}

/// @brief CHOICE alternative analogue of sequence_member_ber_covered.
/// @note Unlike a SEQUENCE member, `decode_choice` compares *every*
///       alternative's tag against the wire tag (no positional/blind
///       decode) — so an alternative referencing another generated type
///       needs a real resolved tag unconditionally, required or not
///       (CHOICE alternatives have no OPTIONAL concept in the first place,
///       X.680 §28).
bool RustBackend::choice_alternative_ber_covered(const ChoiceAlternativeSpec& a) const {
    if (!a.mbuiltin)
        return covered_type_names_.count(a.mtype) > 0 && a.resolved_tag.has_value();
    return rust_tag_for_builtin_or_alias(a.mbuiltin, a.storage_kind, a.mtype) != nullptr;
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
        std::string ftype = m.member_type_in_cycle ? std::format("Box<{}>", m.mtype) : m.mtype;
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
    // generic SequenceBerHandler dispatch (runtime/src/BerCodec.cpp) instead
    // of a straight-line per-type encode()/decode() body. Scoped
    // narrowly on purpose — only SEQUENCEs whose
    // every member is a plain required member of a type with a real
    // Asn1Value BER impl (see rust_member_ber_tag below for the currently-
    // covered set) get a real descriptor
    // table + encode()/decode(); anything else still gets only the
    // struct shape. Broadening further member-type/tag coverage is real
    // follow-on work.
    // mbuiltin is unset for TypeRef members (named INTEGER subtype aliases,
    // e.g. `MyByte ::= INTEGER (0..255)` used as a member type) — Generator
    // only populates it from the member's own AST node when that node
    // directly holds a builtin type (`std::get_if<ast::BuiltinType>`), not
    // for a reference that *resolves* to one. The `mtype == "i64"` fallback
    // a few lines below (rust_member_xer_ready) is meant to cover this case
    // too, but doesn't in practice: cpp_type_for's TypeRef branch returns the
    // alias's own type name (e.g. "MyByte"), never the resolved native type
    // — so `mtype` is never literally "i64" for an aliased member, and the
    // fallback is currently dead. Pre-existing gap, not introduced or fixed
    // here — filed separately (gambas-asn1#361).
    // `mbuiltin == Integer` only says the member *is* an
    // INTEGER, not which Rust storage type classify_integer_storage/
    // native_int_type actually picked for it (i64 default; u64/i128/
    // Vec<u8> for wider constrained ranges — same IntStorageKind the C++
    // side also branches on). Asn1Value is only implemented for i64
    // (rust-runtime/ber/src/value.rs), so the INTEGER case must be gated on
    // that storage kind — found on the real ETSI LI PS-PDU schema,
    // where a semi-constrained-wide INTEGER member picked u64 storage and
    // the old unconditional `case Integer:` still emitted a table row for
    // it, producing `the trait bound u64: Asn1Value is not satisfied`.
    // That gate is now `storage_kind == IntStorageKind::S64`
    // (a real enum, checked by rust_member_xer_ready/rust_member_ber_tag's
    // callers before ever reaching this function) rather than `mtype ==
    // "i64"` — this function's own `case Integer` below still takes `mtype`
    // because it's also called for SEQUENCE OF *element* coverage
    // (elem_builtin/elem_mtype has no storage_kind counterpart,
    // out of scope here), so it keeps the original string check for that path.
    auto rust_member_ber_tag = [](const SequenceMemberSpec& m) -> const char* {
        return rust_tag_for_builtin_or_alias(m.mbuiltin, m.storage_kind, m.mtype);
    };
    // IMPLICIT tag override closures — see
    // MemberAccess::TaggedScalar's doc comment (rust-runtime/ber/src/
    // sequence.rs) for why `Scalar`'s get/get_mut can't express this.
    // Returns (ber_encode closure body, ber_decode_into closure body) for a
    // member whose real resolved tag differs from its natural one, or
    // nullopt if this builtin kind has no `*_tagged` runtime primitive yet
    // (only direct builtins — TypeRef-aliased members fall back to Scalar,
    // same natural-tag-only limitation they already had).
    auto rust_tagged_ops = [&](const SequenceMemberSpec& m, const std::string& tag_lit)
            -> std::optional<std::pair<std::string, std::string>> {
        switch (tagged_kind_for(m.mbuiltin, m.storage_kind)) {
        case TaggedKind::None:
            return std::nullopt;
        case TaggedKind::Boolean:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = v.{0} {{ asn1cpp_ber::boolean::write_boolean_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::boolean::read_boolean_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::boolean::write_boolean_tagged(out, {1}, v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::boolean::read_boolean_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        case TaggedKind::Integer: {
            // Same tag (INTEGER is INTEGER regardless of storage width),
            // different *_tagged primitive per Rust storage type
            // (integer.rs has one pair per width — no generic-over-width
            // helper, since BER's minimal-two's-complement trimming differs
            // between signed and unsigned encodings).
            const char* fn = m.storage_kind == IntStorageKind::U64  ? "write_integer_u64_tagged"
                            : m.storage_kind == IntStorageKind::I128 ? "write_integer_i128_tagged"
                                                                      : "write_integer_tagged";
            const char* rfn = m.storage_kind == IntStorageKind::U64  ? "read_integer_u64_tagged"
                             : m.storage_kind == IntStorageKind::I128 ? "read_integer_i128_tagged"
                                                                       : "read_integer_tagged";
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = v.{0} {{ asn1cpp_ber::integer::{2}(out, {1}, x); }} }}", m.mname, tag_lit, fn),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::integer::{2}(r, {1})?); Ok(()) }}", m.mname, tag_lit, rfn));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::integer::{2}(out, {1}, v.{0})", m.mname, tag_lit, fn),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::integer::{2}(r, {1})?; Ok(()) }}", m.mname, tag_lit, rfn));
        }
        // same shape as Integer — f64 is Copy.
        case TaggedKind::Real:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = v.{0} {{ asn1cpp_ber::real::write_real_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::real::read_real_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::real::write_real_tagged(out, {1}, v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::real::read_real_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        // NULL carries no data — encode only checks presence
        // (Option case) or writes unconditionally (required case); `v` is
        // unused on encode (`_v`) since there's nothing to read from the field.
        case TaggedKind::Null:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if v.{0}.is_some() {{ asn1cpp_ber::null::write_null_tagged(out, {1}); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ asn1cpp_ber::null::read_null_tagged(r, {1})?; v.{0} = Some(()); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|_v, out| asn1cpp_ber::null::write_null_tagged(out, {0})", tag_lit),
                std::format("|v, r| {{ asn1cpp_ber::null::read_null_tagged(r, {0})?; v.{1} = (); Ok(()) }}", tag_lit, m.mname));
        case TaggedKind::OctetString:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::octet_string::write_octet_string_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::octet_string::read_octet_string_tagged(r, {1})?.to_vec()); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::octet_string::write_octet_string_tagged(out, {1}, &v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::octet_string::read_octet_string_tagged(r, {1})?.to_vec(); Ok(()) }}", m.mname, tag_lit));
        // read_bit_string_tagged already returns an owned
        // BitString (unlike octet_string's &[u8] needing .to_vec()).
        case TaggedKind::BitString:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::bit_string::write_bit_string_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::bit_string::read_bit_string_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::bit_string::write_bit_string_tagged(out, {1}, &v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::bit_string::read_bit_string_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        // same shape as BitString — read_object_identifier_tagged
        // already returns an owned ObjectIdentifier.
        case TaggedKind::ObjectIdentifier:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::oid::write_object_identifier_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::oid::read_object_identifier_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::oid::write_object_identifier_tagged(out, {1}, &v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::oid::read_object_identifier_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        // same shape as ObjectIdentifier.
        case TaggedKind::RelativeOid:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::relative_oid::write_relative_oid_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::relative_oid::read_relative_oid_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::relative_oid::write_relative_oid_tagged(out, {1}, &v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::relative_oid::read_relative_oid_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        case TaggedKind::CharString: {
            // IA5String's field is plain String (no wrapper); the other 11
            // kinds are a `char_string_type!` newtype (m.mtype is that
            // newtype's own name, e.g. "asn1cpp_ber::strings::NumericString")
            // whose inner String lives at `.0` (strings.rs).
            bool is_plain_string = (*m.mbuiltin == ast::BuiltinType::Ia5String);
            const char* kind_name = builtin_xer_name(*m.mbuiltin);
            std::string ctor_open  = is_plain_string ? "" : m.mtype + "(";
            std::string ctor_close = is_plain_string ? "" : ")";
            std::string enc_ref = is_plain_string ? "x" : "&x.0";
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::strings::write_char_string(out, {1}, {2}); }} }}",
                                 m.mname, tag_lit, enc_ref),
                    std::format("|v, r| {{ v.{0} = Some({2}asn1cpp_ber::strings::read_char_string(r, {1}, \"{3}\")?{4}); Ok(()) }}",
                                 m.mname, tag_lit, ctor_open, kind_name, ctor_close));
            std::string enc_ref_req = is_plain_string ? std::format("&v.{}", m.mname) : std::format("&v.{}.0", m.mname);
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::strings::write_char_string(out, {1}, {2})", m.mname, tag_lit, enc_ref_req),
                std::format("|v, r| {{ v.{0} = {2}asn1cpp_ber::strings::read_char_string(r, {1}, \"{3}\")?{4}; Ok(()) }}",
                             m.mname, tag_lit, ctor_open, kind_name, ctor_close));
        }
        }
        return std::nullopt;  // unreachable: switch is exhaustive over TaggedKind
    };
    auto rust_member_xer_ready = [&](const SequenceMemberSpec& m) -> bool {
        if (!m.mbuiltin) return m.mtype == "i64";
        // storage_kind, not mtype=="i64" — same interception
        // as rust_tag_for_builtin_or_alias, before builtin_xer_ready's own
        // (still string-based, still shared with SEQUENCE OF elements) check.
        if (*m.mbuiltin == ast::BuiltinType::Integer) return m.storage_kind == IntStorageKind::S64;
        return builtin_xer_ready(*m.mbuiltin, m.mtype);
    };
    // A SEQUENCE OF member is covered only when it's
    // required (this PR's scope stops short of OPTIONAL SEQUENCE OF —
    // absent-vs-empty-list presence detection needs its own design pass,
    // not folded silently into this one) and its element type is itself
    // covered by builtin_ber_tag/builtin_xer_ready.
    auto rust_seqof_ber_tag = [&](const SequenceMemberSpec& m) -> const char* {
        if (!m.is_seq_of || m.optional || !m.elem_builtin) return nullptr;
        return builtin_ber_tag(*m.elem_builtin, m.elem_mtype);
    };
    auto rust_seqof_xer_ready = [&](const SequenceMemberSpec& m) -> bool {
        return rust_seqof_ber_tag(m) != nullptr && builtin_xer_ready(*m.elem_builtin, m.elem_mtype);
    };
    // OPTIONAL members are table-covered too — an
    // OPTIONAL member's own field type (rust-runtime/ber's blanket
    // `Asn1Value for Option<V>` impl, value.rs) handles wire-absence
    // entirely on its own; the `get`/`get_mut` closures below are identical
    // whether the field is `T` or `Option<T>` (Rust doesn't care, and the
    // `&dyn Asn1Value` coercion works for both). Coverage is purely about
    // whether the member's *type* has a real Asn1Value BER impl
    // (rust_member_ber_tag) — no more blanket `!m.optional` exclusion.
    auto rust_member_covered = [&](const SequenceMemberSpec& m) -> bool {
        return sequence_member_ber_covered(m);
    };
    // Composite (SEQUENCE/SET/CHOICE-typed) members never
    // contribute an XER leg in this PR's scope — see sequence_member_ber_covered's
    // doc for the BER-only rationale. Excluding them here (rather than
    // teaching encode_sequence_xer/decode_sequence_xer to recurse) keeps
    // the containing type's own XER coverage decision safe: a composite
    // member whose target type has no real Asn1Value::xer_encode would
    // otherwise panic at runtime the first time the containing type's
    // encode_xer() actually reached it.
    auto rust_member_covered_xer_ready = [&](const SequenceMemberSpec& m) -> bool {
        if (!m.mbuiltin && !m.is_seq_of) return false;
        return m.is_seq_of ? rust_seqof_xer_ready(m) : rust_member_xer_ready(m);
    };
    bool all_covered = !spec.members.empty() &&
        std::all_of(spec.members.begin(), spec.members.end(), rust_member_covered);
    bool all_xer_ready = all_covered &&
        std::all_of(spec.members.begin(), spec.members.end(), rust_member_covered_xer_ready);
    if (all_covered) covered_type_names_[spec.type_name] = RustTypeKind::SequenceOrSet;
    if (all_covered) {
        std::string members_ident = std::format("{}_MEMBERS", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::sequence::MemberDescriptor<{}>; {}] = [\n",
                          members_ident, spec.type_name, spec.members.size());
        for (const auto& m : spec.members) {
            os << "    asn1cpp_ber::sequence::MemberDescriptor {\n";
            os << std::format("        name: \"{}\",\n", m.asn1_name);
            if (m.is_seq_of) {
                const char* elem_xer_name = builtin_xer_name(*m.elem_builtin);
                // Prefer the member's real resolved tag
                // (IMPLICIT override) over SEQUENCE-OF's natural SEQUENCE_TAG,
                // same TaggedScalar-vs-Scalar branch used below for scalar
                // members.
                if (m.resolved_tag && m.is_explicit) {
                    // EXPLICIT — wrap the natural SeqOf
                    // encoding (encode_seq_of/decode_seq_of, not the
                    // tag-substituting _tagged variant) in an outer TLV.
                    std::string tag_lit = format_tag_literal(*m.resolved_tag);
                    os << std::format("        tag: {},\n", tag_lit);
                    // optional: false here (not m.optional) inherits the
                    // same scope limit as the IMPLICIT TaggedSeqOf/
                    // SeqOf branches below — OPTIONAL SEQUENCE OF isn't
                    // handled by any SeqOf path yet (no presence-peek in
                    // decode_sequence's SeqOf-family arms).
                    os << "        optional: false,\n";
                    os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedSeqOf {\n";
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::writer::write_explicit(out, {1}, |inner| asn1cpp_ber::sequence::encode_seq_of(inner, &v.{0})),\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = asn1cpp_ber::reader::read_explicit(r, {1}, |inner| asn1cpp_ber::sequence::decode_seq_of(inner))?; Ok(()) }},\n", m.mname, tag_lit);
                    os << std::format("            xer_encode: |v, out| asn1cpp_ber::sequence::encode_seq_of_xer(out, &v.{}, \"{}\"),\n", m.mname, elem_xer_name);
                    os << std::format("            xer_decode_into: |v, r| {{ v.{} = asn1cpp_ber::sequence::decode_seq_of_xer(r, \"{}\")?; Ok(()) }},\n", m.mname, elem_xer_name);
                    os << "        },\n";
                } else if (m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit) {
                    std::string tag_lit = format_tag_literal(*m.resolved_tag);
                    os << std::format("        tag: {},\n", tag_lit);
                    // optional: false here (not m.optional) inherits the
                    // scope limit below — OPTIONAL SEQUENCE OF isn't handled
                    // by either SeqOf path yet (no presence-peek in
                    // decode_sequence's SeqOf/TaggedSeqOf arms), not something
                    // this fix introduces or narrows.
                    os << "        optional: false,\n";
                    os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedSeqOf {\n";
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::sequence::encode_seq_of_tagged(out, {}, &v.{}),\n", tag_lit, m.mname);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{} = asn1cpp_ber::sequence::decode_seq_of_tagged(r, {})?; Ok(()) }},\n", m.mname, tag_lit);
                    os << std::format("            xer_encode: |v, out| asn1cpp_ber::sequence::encode_seq_of_xer(out, &v.{}, \"{}\"),\n", m.mname, elem_xer_name);
                    os << std::format("            xer_decode_into: |v, r| {{ v.{} = asn1cpp_ber::sequence::decode_seq_of_xer(r, \"{}\")?; Ok(()) }},\n", m.mname, elem_xer_name);
                    os << "        },\n";
                } else {
                    // The descriptor's own `tag` is the OUTER
                    // SEQUENCE-OF container tag — decode_sequence's SeqOf branch
                    // never actually consults it (no OPTIONAL presence-peek for
                    // this PR's required-only scope), kept only so the struct
                    // literal has a real value, same role SEQUENCE_TAG plays on
                    // SequenceSpec itself for a member that happens to be a
                    // nested collection.
                    os << "        tag: asn1cpp_ber::sequence::SEQUENCE_TAG,\n";
                    os << "        optional: false,\n";
                    os << "        access: asn1cpp_ber::sequence::MemberAccess::SeqOf {\n";
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::sequence::encode_seq_of(out, &v.{}),\n", m.mname);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{} = asn1cpp_ber::sequence::decode_seq_of(r)?; Ok(()) }},\n", m.mname);
                    os << std::format("            xer_encode: |v, out| asn1cpp_ber::sequence::encode_seq_of_xer(out, &v.{}, \"{}\"),\n", m.mname, elem_xer_name);
                    os << std::format("            xer_decode_into: |v, r| {{ v.{} = asn1cpp_ber::sequence::decode_seq_of_xer(r, \"{}\")?; Ok(()) }},\n", m.mname, elem_xer_name);
                    os << "        },\n";
                }
            } else if (m.resolved_tag && m.is_explicit) {
                // EXPLICIT tagging (X.690 §8.14.3) — wrap
                // the member's natural (untagged) Asn1Value encoding in a
                // constructed outer TLV via value::encode_explicit/
                // decode_explicit, rather than substituting the tag like
                // the IMPLICIT (TaggedScalar via rust_tagged_ops) branch
                // below. Generic over Asn1Value (unlike the *_tagged
                // primitives IMPLICIT needs), so it covers every member the
                // natural Scalar path already covers with one runtime pair.
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedScalar {\n";
                if (m.optional) {
                    os << std::format("            ber_encode: |v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::value::encode_explicit(out, {1}, x); }} }},\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = Some(asn1cpp_ber::value::decode_explicit(r, {1})?); Ok(()) }},\n", m.mname, tag_lit);
                } else {
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::value::encode_explicit(out, {1}, &v.{0}),\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = asn1cpp_ber::value::decode_explicit(r, {1})?; Ok(()) }},\n", m.mname, tag_lit);
                }
                os << std::format("            get: |v| &v.{0}, get_mut: |v| &mut v.{0},\n", m.mname);
                os << "        },\n";
            } else if (!m.mbuiltin && m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit &&
                       covered_type_names_.count(m.mtype) &&
                       covered_type_names_.at(m.mtype) == RustTypeKind::SequenceOrSet) {
                // IMPLICIT retag (X.690 §8.14.2) of a
                // composite (SEQUENCE/SET-typed — CHOICE members are always
                // EXPLICIT, see member_is_explicit) member: same content,
                // different outer tag, via the target type's own SPEC and
                // the generic encode_sequence_tagged/decode_sequence_tagged
                // pair (no per-builtin-kind *_tagged primitive needed, this
                // works for any SequenceSpec<T>).
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                // Fully-qualified, not a bare identifier — this member's
                // enclosing type and the composite target's SPEC constant
                // live in different generated modules/files (same
                // convention as the `use crate::<snake_case>::<Type>;`
                // import already emitted for the field's own type).
                std::string target_spec = std::format("crate::{}::{}_SPEC",
                    to_snake_case(m.mtype), to_screaming_snake_case(m.mtype));
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedScalar {\n";
                if (m.optional) {
                    os << std::format("            ber_encode: |v, out| {{ if let Some(x) = &v.{0} {{ out.extend_from_slice(&asn1cpp_ber::sequence::encode_sequence_tagged(&{1}, x, {2})); }} }},\n", m.mname, target_spec, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = Some(asn1cpp_ber::sequence::decode_sequence_tagged(&{1}, r, {2})?); Ok(()) }},\n", m.mname, target_spec, tag_lit);
                } else {
                    os << std::format("            ber_encode: |v, out| out.extend_from_slice(&asn1cpp_ber::sequence::encode_sequence_tagged(&{1}, &v.{0}, {2})),\n", m.mname, target_spec, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ v.{0} = asn1cpp_ber::sequence::decode_sequence_tagged(&{1}, r, {2})?; Ok(()) }},\n", m.mname, target_spec, tag_lit);
                }
                os << std::format("            get: |v| &v.{0}, get_mut: |v| &mut v.{0},\n", m.mname);
                os << "        },\n";
            } else if (!m.mbuiltin && m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit &&
                       covered_type_names_.count(m.mtype) &&
                       covered_type_names_.at(m.mtype) == RustTypeKind::Enumerated) {
                // IMPLICIT retag of an ENUMERATED-typed member — X.680 §22.3
                // permits it (unlike CHOICE/ANY). No shared table to
                // reference (ENUMERATED has no SequenceSpec-style table,
                // just a per-type Asn1Value impl going through `as i64`/
                // TryFrom<i64>), so the override tag substitutes directly
                // in the same write_enumerated_tagged/read_enumerated_tagged
                // pair the type's own Asn1Value impl uses internally
                // (emit_enumerated_definition) with ENUMERATED_TAG fixed —
                // here the *_tagged pair takes the override tag instead.
                std::string tag_lit = format_tag_literal(*m.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedScalar {\n";
                if (m.optional) {
                    os << std::format("            ber_encode: |v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::enumerated::write_enumerated_tagged(out, {1}, x as i64); }} }},\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ let raw = asn1cpp_ber::enumerated::read_enumerated_tagged(r, {1})?; v.{0} = Some(<{2} as std::convert::TryFrom<i64>>::try_from(raw).map_err(|_| asn1cpp_ber::DecodeError::new(format!(\"invalid {2} value: {{raw}}\"), 0))?); Ok(()) }},\n", m.mname, tag_lit, m.mtype);
                } else {
                    os << std::format("            ber_encode: |v, out| asn1cpp_ber::enumerated::write_enumerated_tagged(out, {1}, v.{0} as i64),\n", m.mname, tag_lit);
                    os << std::format("            ber_decode_into: |v, r| {{ let raw = asn1cpp_ber::enumerated::read_enumerated_tagged(r, {1})?; v.{0} = <{2} as std::convert::TryFrom<i64>>::try_from(raw).map_err(|_| asn1cpp_ber::DecodeError::new(format!(\"invalid {2} value: {{raw}}\"), 0))?; Ok(()) }},\n", m.mname, tag_lit, m.mtype);
                }
                os << std::format("            get: |v| &v.{0}, get_mut: |v| &mut v.{0},\n", m.mname);
                os << "        },\n";
            } else {
                // Prefer the member's real resolved tag
                // (IMPLICIT override) over its natural one whenever one
                // applies and this builtin kind has a *_tagged primitive.
                std::optional<std::pair<std::string, std::string>> tagged_ops;
                if (m.mbuiltin && m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit)
                    tagged_ops = rust_tagged_ops(m, format_tag_literal(*m.resolved_tag));
                if (tagged_ops) {
                    os << std::format("        tag: {},\n", format_tag_literal(*m.resolved_tag));
                    os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                    os << "        access: asn1cpp_ber::sequence::MemberAccess::TaggedScalar {\n";
                    os << std::format("            ber_encode: {},\n", tagged_ops->first);
                    os << std::format("            ber_decode_into: {},\n", tagged_ops->second);
                    os << std::format("            get: |v| &v.{0}, get_mut: |v| &mut v.{0},\n", m.mname);
                    os << "        },\n";
                } else {
                    // A member whose type is a TypeRef (mbuiltin unset)
                    // reaches here either with its natural tag
                    // (SEQUENCE_TAG/SET_TAG/ENUMERATED_TAG, or an
                    // EXPLICIT-forced CHOICE tag already handled above) or —
                    // required-only, per sequence_member_ber_covered —
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
            }
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
        os << std::format("    name: \"{}\",\n", spec.type_name);
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
        os << "    }\n";
        if (all_xer_ready) {
            os << "\n";
            os << "    pub fn encode_xer(&self) -> String {\n";
            os << std::format("        asn1cpp_ber::xer::encode_sequence_xer(&{}, self)\n", spec_ident);
            os << "    }\n\n";
            os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
            os << std::format("        asn1cpp_ber::xer::decode_sequence_xer(&{}, xml)\n", spec_ident);
            os << "    }\n";
        }
        os << "}\n\n";

        // Makes this type usable as a nested composite member
        // elsewhere — emitted unconditionally whenever this type itself got
        // a real member table (all_covered above), so any other type's
        // sequence_member_ber_covered/choice_alternative_ber_covered can
        // reference it via Asn1Value without needing to predict this in
        // advance (see those methods' own doc for why no prediction is
        // needed). BER leg only; xer_encode/xer_decode_into keep the
        // trait's own default (panicking) body, same "BER first"
        // incremental pairing this crate uses throughout (see value.rs's
        // Asn1Value doc).
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_encode(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_ber::sequence::encode_sequence_into(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_into(&mut self, r: &mut asn1cpp_ber::Reader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::sequence::decode_sequence_from(&{}, r)?;\n", spec_ident);
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
        os << std::format("    {}({}),\n", vname, a.mtype);
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
        os << std::format("pub fn {}(x: &mut {}) -> &mut {} {{\n", fname, spec.type_name, a.mtype);
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

    // Table-driven, mirroring emit_sequence_definition's
    // approach and the generic runtime walker
    // (encode_choice/decode_choice/encode_choice_xer/decode_choice_xer,
    // rust-runtime/ber/src/choice.rs) instead of a per-type match/if chain.
    // Same scope restriction as SEQUENCE: only CHOICEs whose every
    // alternative has a real Asn1Value BER impl (INTEGER, BOOLEAN, OCTET
    // STRING, IA5String) get a real descriptor table + encode()/decode();
    // anything else still gets only the enum + accessor functions above.
    //
    // Unlike SEQUENCE, BER and XER coverage aren't gated separately here:
    // AlternativeSpec<T>'s xer_encode/xer_decode_into are struct fields, not
    // a separate trait-dispatched leg, so the table can't be constructed at
    // all without them — there's no way to emit a "BER-only" CHOICE table
    // the way emit_sequence_definition can emit BER-only encode()/decode()
    // and skip encode_xer()/decode_xer(). Not a live gap today: every
    // builtin type covered here already has both legs (Asn1Value's XER leg
    // landed for all four builtin kinds). Would need
    // revisiting if a future BER-only type is added to builtin_ber_tag's
    // switch before its XER leg lands.
    // Same u64/i128-vs-i64 storage gate as
    // emit_sequence_definition's rust_member_ber_tag — see that lambda's
    // comment for the full rationale.
    auto rust_alt_covered = [&](const ChoiceAlternativeSpec& a) -> bool {
        return choice_alternative_ber_covered(a);
    };
    auto rust_alt_ber_tag = [](const ChoiceAlternativeSpec& a) -> const char* {
        return rust_tag_for_builtin_or_alias(a.mbuiltin, a.storage_kind, a.mtype);
    };
    // IMPLICIT tag override for a CHOICE alternative — same
    // reasoning as emit_sequence_definition's rust_tagged_ops, adapted
    // to a fresh local `v` (pattern-matched out of `x`/decoded from scratch)
    // instead of a struct member access. Returns the encode/decode body
    // fragments (statements ending in the variant construction/`out` write),
    // or nullopt if this builtin kind has no `*_tagged` runtime primitive yet
    // — same coverage limit rust_tagged_ops documents.
    auto rust_alt_tagged_ops = [&](const ChoiceAlternativeSpec& a, const std::string& tag_lit)
            -> std::optional<std::pair<std::string, std::string>> {
        std::string vname = variant_name(*this, a.asn1_name);
        auto variant_ctor = [&](const std::string& expr) {
            return std::format("Ok({}::{}({}))", spec.type_name, vname, expr);
        };
        switch (tagged_kind_for(a.mbuiltin, a.storage_kind)) {
        case TaggedKind::None:
            return std::nullopt;
        case TaggedKind::Boolean:
            return std::make_pair(
                std::format("asn1cpp_ber::boolean::write_boolean_tagged(out, {}, *v);", tag_lit),
                std::format("let v = asn1cpp_ber::boolean::read_boolean_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        case TaggedKind::Integer: {
            const char* fn = a.storage_kind == IntStorageKind::U64  ? "write_integer_u64_tagged"
                            : a.storage_kind == IntStorageKind::I128 ? "write_integer_i128_tagged"
                                                                      : "write_integer_tagged";
            const char* rfn = a.storage_kind == IntStorageKind::U64  ? "read_integer_u64_tagged"
                             : a.storage_kind == IntStorageKind::I128 ? "read_integer_i128_tagged"
                                                                       : "read_integer_tagged";
            return std::make_pair(
                std::format("asn1cpp_ber::integer::{}(out, {}, *v);", fn, tag_lit),
                std::format("let v = asn1cpp_ber::integer::{}(r, {})?; {}",
                             rfn, tag_lit, variant_ctor("v")));
        }
        // same shape as Integer — f64 is Copy.
        case TaggedKind::Real:
            return std::make_pair(
                std::format("asn1cpp_ber::real::write_real_tagged(out, {}, *v);", tag_lit),
                std::format("let v = asn1cpp_ber::real::read_real_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        // NULL's payload (`()`) carries no data — `let _ =
        // v;` explicitly discards the `if let`-bound match (still needed to
        // destructure the enum) so rustc's unused_variables lint stays quiet.
        case TaggedKind::Null:
            return std::make_pair(
                std::format("let _ = v; asn1cpp_ber::null::write_null_tagged(out, {});", tag_lit),
                std::format("asn1cpp_ber::null::read_null_tagged(r, {})?; {}", tag_lit, variant_ctor("()")));
        case TaggedKind::OctetString:
            return std::make_pair(
                std::format("asn1cpp_ber::octet_string::write_octet_string_tagged(out, {}, v);", tag_lit),
                std::format("let v = asn1cpp_ber::octet_string::read_octet_string_tagged(r, {})?.to_vec(); {}",
                             tag_lit, variant_ctor("v")));
        // read_bit_string_tagged already returns an owned
        // BitString (unlike octet_string's &[u8] needing .to_vec()).
        case TaggedKind::BitString:
            return std::make_pair(
                std::format("asn1cpp_ber::bit_string::write_bit_string_tagged(out, {}, v);", tag_lit),
                std::format("let v = asn1cpp_ber::bit_string::read_bit_string_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        // same shape as BitString.
        case TaggedKind::ObjectIdentifier:
            return std::make_pair(
                std::format("asn1cpp_ber::oid::write_object_identifier_tagged(out, {}, v);", tag_lit),
                std::format("let v = asn1cpp_ber::oid::read_object_identifier_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        // same shape as ObjectIdentifier.
        case TaggedKind::RelativeOid:
            return std::make_pair(
                std::format("asn1cpp_ber::relative_oid::write_relative_oid_tagged(out, {}, v);", tag_lit),
                std::format("let v = asn1cpp_ber::relative_oid::read_relative_oid_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        case TaggedKind::CharString: {
            // Same IA5String-is-plain-String-vs-newtype split as
            // rust_tagged_ops — see that lambda's comment.
            bool is_plain_string = (*a.mbuiltin == ast::BuiltinType::Ia5String);
            const char* kind_name = builtin_xer_name(*a.mbuiltin);
            std::string enc_ref = is_plain_string ? "v" : "&v.0";
            std::string ctor_open  = is_plain_string ? "" : a.mtype + "(";
            std::string ctor_close = is_plain_string ? "" : ")";
            return std::make_pair(
                std::format("asn1cpp_ber::strings::write_char_string(out, {}, {});", tag_lit, enc_ref),
                std::format("let s = asn1cpp_ber::strings::read_char_string(r, {}, \"{}\")?; let v = {}s{}; {}",
                             tag_lit, kind_name, ctor_open, ctor_close, variant_ctor("v")));
        }
        }
        return std::nullopt;  // unreachable: switch is exhaustive over TaggedKind
    };
    bool all_covered = !spec.alternatives.empty() &&
        std::all_of(spec.alternatives.begin(), spec.alternatives.end(), rust_alt_covered);
    if (all_covered) covered_type_names_[spec.type_name] = RustTypeKind::Choice;
    // XER coverage is no longer implied by BER coverage now that composite
    // alternatives (BER-only — no real XER support yet) and wide-storage
    // INTEGER (U64/I128, also BER-only) are both included in all_covered —
    // gated separately, same all_covered-vs-all_xer_ready split
    // emit_sequence_definition already uses. The generated AlternativeSpec
    // rows' own xer_encode/xer_decode_into closures still exist
    // unconditionally either way (required struct fields, not optional) —
    // they just aren't reachable through anything this backend generates
    // when all_xer_ready is false, since encode_xer()/decode_xer() are
    // the only callers and this gate withholds them.
    auto rust_alt_xer_ready = [](const ChoiceAlternativeSpec& a) -> bool {
        if (!a.mbuiltin) return false;
        if (*a.mbuiltin == ast::BuiltinType::Integer) return a.storage_kind == IntStorageKind::S64;
        return builtin_xer_ready(*a.mbuiltin, a.mtype);
    };
    bool all_xer_ready = all_covered &&
        std::all_of(spec.alternatives.begin(), spec.alternatives.end(), rust_alt_xer_ready);
    if (all_covered) {
        std::string alts_ident = std::format("{}_ALTERNATIVES", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::choice::AlternativeSpec<{}>; {}] = [\n",
                          alts_ident, spec.type_name, spec.alternatives.size());
        for (const auto& a : spec.alternatives) {
            std::string vname = variant_name(*this, a.asn1_name);
            // gambas-asn1#313: same single-alternative special-case as
            // emit_choice_definition's accessor functions above — an
            // `if let ... = x { ... } else { false }` is irrefutable when
            // `Type` has exactly one variant (rustc flags it), so emit a
            // plain `let` (no `else` arm needed, matches unconditionally)
            // instead in that case.
            auto emit_encode_closure = [&](const char* field, const std::string& body_line) {
                os << std::format("        {}: |x, out| ", field);
                if (single_alt) {
                    os << std::format("{{\n            let {}::{}(v) = x;\n", spec.type_name, vname);
                    os << std::format("            {}\n", body_line);
                    os << "            true\n";
                    os << "        },\n";
                } else {
                    os << std::format("if let {}::{}(v) = x {{\n", spec.type_name, vname);
                    os << std::format("            {}\n", body_line);
                    os << "            true\n";
                    os << "        } else { false },\n";
                }
            };
            std::optional<std::pair<std::string, std::string>> tagged_ops;
            std::string tag_lit;
            if (a.resolved_tag && a.resolved_tag->tag_is_override && !a.is_explicit) {
                tag_lit = format_tag_literal(*a.resolved_tag);
                tagged_ops = rust_alt_tagged_ops(a, tag_lit);
            }
            os << "    asn1cpp_ber::choice::AlternativeSpec {\n";
            os << std::format("        name: \"{}\",\n", a.asn1_name);
            if (a.resolved_tag && a.is_explicit) {
                // EXPLICIT — wrap the alternative's natural
                // Asn1Value encoding in an outer TLV via value::
                // encode_explicit/decode_explicit, generic over the
                // alternative's type (same reasoning as the SEQUENCE scalar
                // EXPLICIT branch above).
                std::string etag = format_tag_literal(*a.resolved_tag);
                os << std::format("        tag: {},\n", etag);
                emit_encode_closure("ber_encode", std::format("asn1cpp_ber::value::encode_explicit(out, {}, v);", etag));
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let v: {} = asn1cpp_ber::value::decode_explicit(r, {})?;\n", a.mtype, etag);
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            } else if (!a.mbuiltin && a.resolved_tag && a.resolved_tag->tag_is_override && !a.is_explicit &&
                       covered_type_names_.count(a.mtype) &&
                       covered_type_names_.at(a.mtype) == RustTypeKind::SequenceOrSet) {
                // IMPLICIT retag (X.690 §8.14.2) of a composite
                // (SEQUENCE/SET-typed — CHOICE targets are always EXPLICIT,
                // X.680 §30.6) alternative: same shape as
                // emit_sequence_definition's composite TaggedScalar branch,
                // via the target's own SPEC and the generic
                // encode_sequence_tagged/decode_sequence_tagged pair.
                std::string tag_lit2 = format_tag_literal(*a.resolved_tag);
                std::string target_spec = std::format("crate::{}::{}_SPEC",
                    to_snake_case(a.mtype), to_screaming_snake_case(a.mtype));
                os << std::format("        tag: {},\n", tag_lit2);
                emit_encode_closure("ber_encode",
                    std::format("out.extend_from_slice(&asn1cpp_ber::sequence::encode_sequence_tagged(&{}, v, {}));",
                                 target_spec, tag_lit2));
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let v: {} = asn1cpp_ber::sequence::decode_sequence_tagged(&{}, r, {})?;\n",
                                   a.mtype, target_spec, tag_lit2);
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            } else if (!a.mbuiltin && a.resolved_tag && a.resolved_tag->tag_is_override && !a.is_explicit &&
                       covered_type_names_.count(a.mtype) &&
                       covered_type_names_.at(a.mtype) == RustTypeKind::Enumerated) {
                // IMPLICIT retag of an ENUMERATED-typed alternative — same
                // reasoning as emit_sequence_definition's Enumerated retag
                // branch (X.680 §22.3 permits it).
                std::string tag_lit2 = format_tag_literal(*a.resolved_tag);
                os << std::format("        tag: {},\n", tag_lit2);
                emit_encode_closure("ber_encode",
                    std::format("asn1cpp_ber::enumerated::write_enumerated_tagged(out, {}, *v as i64);", tag_lit2));
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let raw = asn1cpp_ber::enumerated::read_enumerated_tagged(r, {})?;\n", tag_lit2);
                os << std::format("            let v = <{0} as std::convert::TryFrom<i64>>::try_from(raw).map_err(|_| asn1cpp_ber::DecodeError::new(format!(\"invalid {0} value: {{raw}}\"), 0))?;\n", a.mtype);
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            } else if (tagged_ops) {
                os << std::format("        tag: {},\n", tag_lit);
                emit_encode_closure("ber_encode", tagged_ops->first);
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            {}\n", tagged_ops->second);
                os << "        },\n";
            } else {
                // An alternative whose type is a TypeRef (mbuiltin unset)
                // reaching here has its target's own natural tag
                // (SEQUENCE_TAG/SET_TAG/ENUMERATED_TAG) — EXPLICIT-forced
                // CHOICE targets and IMPLICIT overrides are both already
                // handled above; choice_alternative_ber_covered guarantees
                // resolved_tag is present whenever mbuiltin is unset.
                std::string tag_text = !a.mbuiltin
                    ? format_tag_literal(*a.resolved_tag)
                    : rust_alt_ber_tag(a);
                os << std::format("        tag: {},\n", tag_text);
                emit_encode_closure("ber_encode", "asn1cpp_ber::value::Asn1Value::ber_encode(v, out);");
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let mut v: {} = Default::default();\n", a.mtype);
                os << "            asn1cpp_ber::value::Asn1Value::ber_decode_into(&mut v, r)?;\n";
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            }
            emit_encode_closure("xer_encode", "asn1cpp_ber::value::Asn1Value::xer_encode(v, out);");
            os << "        xer_decode_into: |r| {\n";
            os << std::format("            let mut v: {} = Default::default();\n", a.mtype);
            os << "            asn1cpp_ber::value::Asn1Value::xer_decode_into(&mut v, r)?;\n";
            os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
            os << "        },\n";
            os << "    },\n";
        }
        os << "];\n\n";

        os << std::format(
            "static {}: asn1cpp_ber::choice::ChoiceSpec<{}> = asn1cpp_ber::choice::ChoiceSpec {{\n",
            spec_ident, spec.type_name);
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
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::choice::decode_choice(&{}, data)\n", spec_ident);
        os << "    }\n";
        if (all_xer_ready) {
            os << "\n";
            os << "    pub fn encode_xer(&self) -> String {\n";
            os << std::format("        asn1cpp_ber::choice::encode_choice_xer(&{}, self)\n", spec_ident);
            os << "    }\n\n";
            os << "    pub fn decode_xer(xml: &str) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
            os << std::format("        asn1cpp_ber::choice::decode_choice_xer(&{}, xml)\n", spec_ident);
            os << "    }\n";
        }
        os << "}\n\n";

        // Makes this type usable as a nested composite
        // member elsewhere — see emit_sequence_definition's identical
        // Asn1Value impl for the full rationale (BER leg only; xer_encode/
        // xer_decode_into keep the trait's default panicking body —
        // encode_choice_xer's nested-content framing hasn't been verified
        // safe to reuse as Asn1Value::xer_encode's contract, same
        // BER-first incremental scope as the SEQUENCE side).
        os << std::format("impl asn1cpp_ber::value::Asn1Value for {} {{\n", spec.type_name);
        os << "    fn ber_encode(&self, out: &mut Vec<u8>) {\n";
        os << std::format("        asn1cpp_ber::choice::encode_choice_into(&{}, self, out);\n", spec_ident);
        os << "    }\n\n";
        os << "    fn ber_decode_into(&mut self, r: &mut asn1cpp_ber::Reader) -> Result<(), asn1cpp_ber::DecodeError> {\n";
        os << std::format("        *self = asn1cpp_ber::choice::decode_choice_from(&{}, r)?;\n", spec_ident);
        os << "        Ok(())\n";
        os << "    }\n";
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

/// @brief Emit the declaration half of a builtin-alias type.
/// @note Deliberately empty: RustBackend's emit_builtin_alias_definition
///       already emits the complete `pub type X = ...;` alias plus any
///       size-check function in one call — there is no separate
///       declaration/definition split on the Rust side for this
///       construct (documented on emit_builtin_alias_definition itself). Emitting
///       anything here would duplicate that output.
void RustBackend::emit_builtin_alias_declaration(const BuiltinAliasSpec& spec, std::ostream& os) const {
    (void)spec;
    (void)os;
}

void RustBackend::emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const {
    emit_builtin_alias_declaration(spec, session.buffer(declaration_extension()));
    emit_builtin_alias_definition(spec, session.buffer(definition_extension()));
}

/// @brief Emit the declaration half of a SEQUENCE OF / SET OF type: a real
///        `pub type X = Vec<ElemType>;` alias.
/// @note `spec.elem_type` is treated as an opaque, already-Rust-shaped type
///       string — same "supplied by the caller" contract as every other
///       pairing (see e.g. emit_sequence_declaration's note).
void RustBackend::emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const {
    os << std::format("pub type {} = Vec<{}>;\n\n", spec.type_name, spec.elem_type);
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
