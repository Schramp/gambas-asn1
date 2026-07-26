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
// gambas-asn1#305: to_upper_camel_case (real word-split conversion), not
// capitalize_first(type_name(...)) — the latter routes through
// to_cpp_name's hyphen->underscore substitution first, so a hyphenated
// multi-word value name (e.g. "eight-bit-binary") came out "Eight_bit_binary"
// instead of "EightBitBinary". Operates on the raw ASN.1 name directly,
// bypassing type_name(), so the hyphen is available to split on.
static std::string variant_name(const RustBackend& backend, const std::string& asn1_name) {
    return backend.escape(to_upper_camel_case(asn1_name));
}

// gambas-asn1#344: per-builtin-kind lookup tables shared by
// emit_sequence_definition (SEQUENCE members, SEQUENCE OF elements) and
// emit_choice_definition (CHOICE alternatives) — previously three separate
// near-identical switches over ast::BuiltinType per function (six total).
// Hoisted to file scope so there's exactly one switch per question asked,
// not one per caller.

/// @brief Per-builtin-kind BER tag constant. See TaggedMemberSpec::mbuiltin's
///        doc comment (Backend.hpp) for why native storage type alone can't
///        drive this (e.g. OCTET STRING/BIT STRING/OBJECT IDENTIFIER/Any all
///        map to "Vec<u8>", but need different tags).
static const char* builtin_ber_tag(ast::BuiltinType bt, const std::string& mtype) {
    switch (bt) {
    case ast::BuiltinType::Integer:     return mtype == "i64" ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
    case ast::BuiltinType::Boolean:     return "asn1cpp_ber::boolean::BOOLEAN_TAG";
    case ast::BuiltinType::OctetString: return "asn1cpp_ber::octet_string::OCTET_STRING_TAG";
    case ast::BuiltinType::Ia5String:   return "asn1cpp_ber::strings::IA5_STRING_TAG";
    // gambas-asn1#326: the other 11 restricted-character-string kinds
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
    // Not yet covered — no Asn1Value impl in rust-runtime/ber for these
    // kinds yet, so a member of any of them falls back to struct-shape-only
    // codegen (no encode()/decode() at all if any member is uncovered).
    // BitString/Null/ObjectIdentifier/RelativeOid/Real/UtcTime/
    // GeneralizedTime: gambas-asn1#349. Any: gambas-asn1#330 (separate,
    // pre-existing issue). Enumerated never reaches this switch — routed
    // through the wholly separate emit_enumerated/EnumeratedSpec path.
    default:                                 return nullptr;
    }
}

/// @brief Same lookup as builtin_ber_tag, but for a member/alternative whose
///        own type may be a TypeRef alias rather than a direct builtin
///        (mbuiltin == nullopt) — the i64-native-INTEGER-alias case still
///        needs a tag despite carrying no mbuiltin.
static const char* rust_tag_for_builtin_or_alias(std::optional<ast::BuiltinType> mbuiltin,
                                                  const std::string& mtype) {
    if (!mbuiltin) return mtype == "i64" ? "asn1cpp_ber::integer::INTEGER_TAG" : nullptr;
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
    // Same uncovered set as builtin_ber_tag's default (gambas-asn1#349/
    // #330) — this fallback name is never actually reached in practice
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
///        forcing through one closure-body generator (gambas-asn1#344).
enum class TaggedKind { None, Boolean, Integer, OctetString, CharString };

static TaggedKind tagged_kind_for(std::optional<ast::BuiltinType> mbuiltin, const std::string& mtype) {
    if (!mbuiltin) return TaggedKind::None;
    switch (*mbuiltin) {
    case ast::BuiltinType::Boolean:     return TaggedKind::Boolean;
    case ast::BuiltinType::Integer:     return mtype == "i64" ? TaggedKind::Integer : TaggedKind::None;
    case ast::BuiltinType::OctetString: return TaggedKind::OctetString;
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
        return TaggedKind::CharString;
    // Same uncovered set as builtin_ber_tag's default (gambas-asn1#349/
    // #330) — a tagged member/alternative of one of these kinds falls back
    // to the natural-tag path, which itself has no coverage either, so the
    // enclosing SEQUENCE/CHOICE gets no table at all (all_covered gates on
    // rust_member_ber_tag/rust_alt_ber_tag, not tagged_kind_for).
    default:
        return TaggedKind::None;
    }
}

void RustBackend::emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& tname = spec.type_name;

    os << "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n";
    os << "#[repr(i64)]\n";
    os << std::format("pub enum {} {{\n", tname);
    // gambas-asn1#305: variant_name's word-split conversion discards
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
    // gambas-asn1#304: `()` written out directly, not `Self::Error` — an
    // ASN.1 ENUMERATED value literally named `Error` (real case on the
    // ETSI LI PS-PDU schema, #299) makes `Self::Error` ambiguous: it could
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

    // gambas-asn1#311: a manual Default impl (not #[derive(Default)] — no
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
///       `Asn1Value for String` impl (`rust-runtime/ber/src/value.rs`,
///       gambas-asn1#282), kept as-is for ergonomics/backward compatibility.
///       The other 11 restricted-character-string kinds
///       (gambas-asn1#326) map to their own `rust-runtime/ber::strings`
///       newtype (`NumericString`, `PrintableString`, ...) — a plain
///       `String` can only carry one `Asn1Value` impl, so a second string
///       kind can't reuse `Ia5String`'s without fighting over which tag to
///       check/write (see `strings.rs`'s module doc). `Vec<u8>` for OCTET
///       STRING/BIT STRING/OID/Any, `String` for UtcTime/GeneralizedTime
///       rather than a real timestamp type — matches this pairing's scope
///       (compiles as real Rust, no runtime wiring yet for those). A real
///       BER/PER runtime would likely want tighter types (e.g. `[u32]` arcs
///       for OID); revisit then.
std::string RustBackend::native_builtin_type(ast::BuiltinType bt) const {
    using BT = ast::BuiltinType;
    switch (bt) {
    case BT::Boolean:          return "bool";
    case BT::Real:             return "f64";
    case BT::Null:             return "()";
    case BT::BitString:        return "Vec<u8>";
    case BT::OctetString:      return "Vec<u8>";
    case BT::ObjectIdentifier: return "Vec<u64>";
    case BT::RelativeOid:      return "Vec<u64>";
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
    case BT::UtcTime:          return "String";
    case BT::GeneralizedTime:  return "String";
    case BT::Any:              return "Vec<u8>";
    default:                   return "Vec<u8>";  // Integer/Enumerated: unreachable here
    }
}

/// @brief Format a resolved `TagSpec` as an `asn1cpp_ber::tag::Tag` struct
///        literal. gambas-asn1#290: mirrors `CppBackend::format_tag_literal`
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
    os << std::format("pub fn {}_size_ok(v: &{}) -> bool {{\n", base, rust_type);
    if (spec.size_bounded) {
        os << std::format("    (v.len() as i64) >= {} && (v.len() as i64) <= {}\n",
                           spec.size_lower, spec.size_upper);
    } else {
        os << std::format("    (v.len() as i64) >= {} // semi-constrained, no upper cap\n",
                           spec.size_lower);
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
///       shaped type name string — the same "supplied by the caller"
///       contract as CppBackend's own consumer today: real Generator ->
///       RustBackend wiring (a from-Generator::cpp_type_for() value) doesn't
///       exist yet (no `--target=rust` CLI flag, #245), so nothing in this
///       pairing can verify a *real* schema's field types compile as Rust —
///       only that the emitted struct shape is correct for whatever type
///       strings arrive. `ops`/`tdref`/`def_setter`/`offset_expr` are
///       C++-runtime-only (per SequenceMemberSpec's own doc) and unused
///       here; optional members become `Option<T>` rather than C++'s
///       `unique_ptr<T>`, Rust's natural equivalent.
void RustBackend::emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const {
    os << "#[derive(Debug, Clone, Default, PartialEq)]\n";
    os << std::format("pub struct {} {{\n", spec.type_name);
    for (const auto& m : spec.members) {
        // gambas-asn1#303: a member whose class type cycles back to this
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

    // gambas-asn1#278: table-driven, mirroring asn_MBR_/asn_SPC_ + the
    // generic SequenceBerHandler dispatch (runtime/src/BerCodec.cpp) instead
    // of #219's straight-line per-type encode()/decode() bodies. Scoped
    // narrowly on purpose, same as #219 before it — only SEQUENCEs whose
    // every member is a plain required member of a type with a real
    // Asn1Value BER impl (gambas-asn1#282: INTEGER, BOOLEAN, OCTET STRING,
    // IA5String — see rust_member_ber_tag below) get a real descriptor
    // table + encode()/decode(); anything else (OPTIONAL members, CHOICE/
    // SEQUENCE OF/other string or time members, ...) still gets only the
    // struct shape. Broadening further member-type/tag coverage is real
    // follow-on work, not this issue's scope.
    // mbuiltin is unset for TypeRef members (named INTEGER subtype aliases,
    // e.g. `MyByte ::= INTEGER (0..255)` used as a member type) — Generator
    // only populates it from the member's own AST node when that node
    // directly holds a builtin type (`std::get_if<ast::BuiltinType>`), not
    // for a reference that *resolves* to one. Such aliases still map to
    // Rust "i64" via native_int_type's default storage kind, so the mtype
    // fallback below (not just a defensive no-op) is what makes an aliased
    // INTEGER member participate in the descriptor table at all.
    // gambas-asn1#315: `mbuiltin == Integer` only says the member *is* an
    // INTEGER, not which Rust storage type classify_integer_storage/
    // native_int_type actually picked for it (i64 default; u64/i128/
    // Vec<u8> for wider constrained ranges — same IntStorageKind the C++
    // side also branches on). Asn1Value is only implemented for i64
    // (rust-runtime/ber/src/value.rs), so the INTEGER case must check
    // `mtype == "i64"` same as the `!mbuiltin` fallback does one line
    // below — found on the real ETSI LI PS-PDU schema (#299), where a
    // semi-constrained-wide INTEGER member picked u64 storage and the old
    // unconditional `case Integer:` still emitted a table row for it,
    // producing `the trait bound u64: Asn1Value is not satisfied`.
    // Asn1Value's XER leg now covers the same kinds the BER leg does
    // (gambas-asn1#283/#326). Kept as its own gate (not just reusing
    // builtin_ber_tag's coverage set) rather than assuming the two always
    // match — encode_xer()/decode_xer() must never be emitted for a member
    // type whose Asn1Value XER leg is still the default, or the emitted
    // method panics at runtime (found in #282's review).
    auto builtin_xer_ready = [](ast::BuiltinType bt, const std::string& mtype) -> bool {
        switch (bt) {
        case ast::BuiltinType::Integer:     return mtype == "i64";  // #315: same gate as BER
        case ast::BuiltinType::Boolean:
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
            return true;
        default:
            return false;
        }
    };
    auto rust_member_ber_tag = [](const SequenceMemberSpec& m) -> const char* {
        return rust_tag_for_builtin_or_alias(m.mbuiltin, m.mtype);
    };
    // gambas-asn1#332: IMPLICIT tag override closures — see
    // MemberAccess::TaggedScalar's doc comment (rust-runtime/ber/src/
    // sequence.rs) for why `Scalar`'s get/get_mut can't express this.
    // Returns (ber_encode closure body, ber_decode_into closure body) for a
    // member whose real resolved tag differs from its natural one, or
    // nullopt if this builtin kind has no `*_tagged` runtime primitive yet
    // (only direct builtins — TypeRef-aliased members fall back to Scalar,
    // same natural-tag-only limitation they already had).
    auto rust_tagged_ops = [&](const SequenceMemberSpec& m, const std::string& tag_lit)
            -> std::optional<std::pair<std::string, std::string>> {
        switch (tagged_kind_for(m.mbuiltin, m.mtype)) {
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
        case TaggedKind::Integer:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = v.{0} {{ asn1cpp_ber::integer::write_integer_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::integer::read_integer_tagged(r, {1})?); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::integer::write_integer_tagged(out, {1}, v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::integer::read_integer_tagged(r, {1})?; Ok(()) }}", m.mname, tag_lit));
        case TaggedKind::OctetString:
            if (m.optional)
                return std::make_pair(
                    std::format("|v, out| {{ if let Some(x) = &v.{0} {{ asn1cpp_ber::octet_string::write_octet_string_tagged(out, {1}, x); }} }}", m.mname, tag_lit),
                    std::format("|v, r| {{ v.{0} = Some(asn1cpp_ber::octet_string::read_octet_string_tagged(r, {1})?.to_vec()); Ok(()) }}", m.mname, tag_lit));
            return std::make_pair(
                std::format("|v, out| asn1cpp_ber::octet_string::write_octet_string_tagged(out, {1}, &v.{0})", m.mname, tag_lit),
                std::format("|v, r| {{ v.{0} = asn1cpp_ber::octet_string::read_octet_string_tagged(r, {1})?.to_vec(); Ok(()) }}", m.mname, tag_lit));
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
        return builtin_xer_ready(*m.mbuiltin, m.mtype);
    };
    // gambas-asn1#331: a SEQUENCE OF member is covered only when it's
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
    // gambas-asn1#326: OPTIONAL members are now table-covered too — an
    // OPTIONAL member's own field type (rust-runtime/ber's blanket
    // `Asn1Value for Option<V>` impl, value.rs) handles wire-absence
    // entirely on its own; the `get`/`get_mut` closures below are identical
    // whether the field is `T` or `Option<T>` (Rust doesn't care, and the
    // `&dyn Asn1Value` coercion works for both). Coverage is purely about
    // whether the member's *type* has a real Asn1Value BER impl
    // (rust_member_ber_tag) — no more blanket `!m.optional` exclusion.
    auto rust_member_covered = [&](const SequenceMemberSpec& m) -> bool {
        return m.is_seq_of ? rust_seqof_ber_tag(m) != nullptr : rust_member_ber_tag(m) != nullptr;
    };
    auto rust_member_covered_xer_ready = [&](const SequenceMemberSpec& m) -> bool {
        return m.is_seq_of ? rust_seqof_xer_ready(m) : rust_member_xer_ready(m);
    };
    bool all_covered = !spec.members.empty() &&
        std::all_of(spec.members.begin(), spec.members.end(), rust_member_covered);
    bool all_xer_ready = all_covered &&
        std::all_of(spec.members.begin(), spec.members.end(), rust_member_covered_xer_ready);
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
                // gambas-asn1#337: prefer the member's real resolved tag
                // (IMPLICIT override) over SEQUENCE-OF's natural SEQUENCE_TAG,
                // same TaggedScalar-vs-Scalar branch used below for scalar
                // members.
                if (m.resolved_tag && m.is_explicit) {
                    // gambas-asn1#346: EXPLICIT — wrap the natural SeqOf
                    // encoding (encode_seq_of/decode_seq_of, not the
                    // tag-substituting _tagged variant) in an outer TLV.
                    std::string tag_lit = format_tag_literal(*m.resolved_tag);
                    os << std::format("        tag: {},\n", tag_lit);
                    // optional: false here (not m.optional) inherits the
                    // same #331 scope limit as the IMPLICIT TaggedSeqOf/
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
                    // optional: false here (not m.optional) inherits #331's
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
                    // gambas-asn1#331: the descriptor's own `tag` is the OUTER
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
                // gambas-asn1#346: EXPLICIT tagging (X.690 §8.14.3) — wrap
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
            } else {
                // gambas-asn1#332: prefer the member's real resolved tag
                // (IMPLICIT override) over its natural one whenever one
                // applies and this builtin kind has a *_tagged primitive.
                std::optional<std::pair<std::string, std::string>> tagged_ops;
                if (m.resolved_tag && m.resolved_tag->tag_is_override && !m.is_explicit)
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
                    os << std::format("        tag: {},\n", rust_member_ber_tag(m));
                    os << std::format("        optional: {},\n", m.optional ? "true" : "false");
                    os << std::format("        access: asn1cpp_ber::sequence::MemberAccess::Scalar {{ get: |v| &v.{0}, get_mut: |v| &mut v.{0} }},\n", m.mname);
                }
            }
            os << "    },\n";
        }
        os << "];\n\n";

        os << std::format(
            "static {}: asn1cpp_ber::sequence::SequenceSpec<{}> = asn1cpp_ber::sequence::SequenceSpec {{\n",
            spec_ident, spec.type_name);
        os << std::format("    name: \"{}\",\n", spec.type_name);
        // gambas-asn1#326: SET's own natural tag (universal 17), not
        // SEQUENCE's (16) — same distinction CppBackend's own
        // emit_sequence_definition already makes (spec.is_set), just never
        // threaded through here before now.
        // gambas-asn1#342: honor a top-level [n] IMPLICIT/EXPLICIT tag on
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
///       `std::launder`/`ChoiceOps<T>` storage design (see design note on
///       gambas-asn1#240) — that design exists only to dodge
///       `std::variant`'s O(N²) template-instantiation blowup on large
///       CHOICEs, a C++-template-specific failure mode. Rust's `enum` is a
///       native tagged union, not template-recursive, so the natural
///       mapping has no equivalent problem. No `#[derive(Default)]`: unlike
///       a struct, a CHOICE has no natural default variant.
void RustBackend::emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const {
    // gambas-asn1#284: variant names use variant_name(), not the raw
    // a.pr_name — found while building #284's fixture. a.pr_name is
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
    // gambas-asn1#305: same collision guard as emit_enumerated_declaration —
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
    os << "}\n\n";
}

/// @brief Emit per-alternative accessor functions for a CHOICE type.
/// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
/// @param os   Output stream to write to.
/// @note Free functions doing an exhaustive `match`, not methods — the
///       Rust analogue of the C++ side's offset-based accessor methods
///       (see design note on gambas-asn1#240), but compiler-checked
///       (exhaustive match) rather than an unchecked `reinterpret_cast`:
///       worst case on a mismatched variant is a controlled panic, not UB.
///       `tag_index_table`/`ber_tags` (BER wire-dispatch specific) are
///       unused here — no runtime wiring yet, same as every prior pairing.
void RustBackend::emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const {
    std::string prefix = escape(to_snake_case(spec.type_name));
    for (const auto& a : spec.alternatives) {
        std::string fname = escape(std::format("{}_get_{}", prefix, a.accessor_name));
        os << std::format("pub fn {}(x: &mut {}) -> &mut {} {{\n", fname, spec.type_name, a.mtype);
        os << std::format("    match x {{ {}::{}(v) => v, _ => panic!(\"wrong variant\") }}\n",
                           spec.type_name, variant_name(*this, a.asn1_name));
        os << "}\n\n";
    }

    // gambas-asn1#311: manual Default impl, first-declared alternative with
    // its own type's Default value — same rationale as ENUMERATED's Default
    // impl just above this call in the file (emit_enumerated_definition):
    // X.680 CHOICE (§28) has no "default alternative" concept at all (even
    // less than ENUMERATED's arbitrary-but-defensible "first value"), but
    // without *some* Default a SEQUENCE with a required (non-OPTIONAL)
    // CHOICE-typed member can't derive Default itself — the actual bug
    // found on the real ETSI LI PS-PDU schema (193 compile errors, #299).
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

    // gambas-asn1#284/#285: table-driven, mirroring emit_sequence_definition's
    // approach (#278/#282) and the generic runtime walker
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
    // landed for all four in #283, before this issue). Would need
    // revisiting if a future BER-only type is added to builtin_ber_tag's
    // switch before its XER leg lands.
    // gambas-asn1#315: same u64/i128-vs-i64 storage gate as
    // emit_sequence_definition's rust_member_ber_tag — see that lambda's
    // comment for the full rationale.
    auto rust_alt_ber_tag = [](const ChoiceAlternativeSpec& a) -> const char* {
        return rust_tag_for_builtin_or_alias(a.mbuiltin, a.mtype);
    };
    // gambas-asn1#336: IMPLICIT tag override for a CHOICE alternative — same
    // reasoning as emit_sequence_definition's rust_tagged_ops (#332), adapted
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
        switch (tagged_kind_for(a.mbuiltin, a.mtype)) {
        case TaggedKind::None:
            return std::nullopt;
        case TaggedKind::Boolean:
            return std::make_pair(
                std::format("asn1cpp_ber::boolean::write_boolean_tagged(out, {}, *v);", tag_lit),
                std::format("let v = asn1cpp_ber::boolean::read_boolean_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        case TaggedKind::Integer:
            return std::make_pair(
                std::format("asn1cpp_ber::integer::write_integer_tagged(out, {}, *v);", tag_lit),
                std::format("let v = asn1cpp_ber::integer::read_integer_tagged(r, {})?; {}",
                             tag_lit, variant_ctor("v")));
        case TaggedKind::OctetString:
            return std::make_pair(
                std::format("asn1cpp_ber::octet_string::write_octet_string_tagged(out, {}, v);", tag_lit),
                std::format("let v = asn1cpp_ber::octet_string::read_octet_string_tagged(r, {})?.to_vec(); {}",
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
        std::all_of(spec.alternatives.begin(), spec.alternatives.end(),
                     [&](const ChoiceAlternativeSpec& a) { return rust_alt_ber_tag(a) != nullptr; });
    if (all_covered) {
        std::string alts_ident = std::format("{}_ALTERNATIVES", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::choice::AlternativeSpec<{}>; {}] = [\n",
                          alts_ident, spec.type_name, spec.alternatives.size());
        for (const auto& a : spec.alternatives) {
            std::string vname = variant_name(*this, a.asn1_name);
            std::optional<std::pair<std::string, std::string>> tagged_ops;
            std::string tag_lit;
            if (a.resolved_tag && a.resolved_tag->tag_is_override && !a.is_explicit) {
                tag_lit = format_tag_literal(*a.resolved_tag);
                tagged_ops = rust_alt_tagged_ops(a, tag_lit);
            }
            os << "    asn1cpp_ber::choice::AlternativeSpec {\n";
            os << std::format("        name: \"{}\",\n", a.asn1_name);
            if (a.resolved_tag && a.is_explicit) {
                // gambas-asn1#346: EXPLICIT — wrap the alternative's natural
                // Asn1Value encoding in an outer TLV via value::
                // encode_explicit/decode_explicit, generic over the
                // alternative's type (same reasoning as the SEQUENCE scalar
                // EXPLICIT branch above).
                std::string etag = format_tag_literal(*a.resolved_tag);
                os << std::format("        tag: {},\n", etag);
                os << std::format("        ber_encode: |x, out| if let {}::{}(v) = x {{\n",
                                  spec.type_name, vname);
                os << std::format("            asn1cpp_ber::value::encode_explicit(out, {}, v);\n", etag);
                os << "            true\n";
                os << "        } else { false },\n";
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let v: {} = asn1cpp_ber::value::decode_explicit(r, {})?;\n", a.mtype, etag);
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            } else if (tagged_ops) {
                os << std::format("        tag: {},\n", tag_lit);
                os << std::format("        ber_encode: |x, out| if let {}::{}(v) = x {{\n",
                                  spec.type_name, vname);
                os << std::format("            {}\n", tagged_ops->first);
                os << "            true\n";
                os << "        } else { false },\n";
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            {}\n", tagged_ops->second);
                os << "        },\n";
            } else {
                os << std::format("        tag: {},\n", rust_alt_ber_tag(a));
                os << std::format("        ber_encode: |x, out| if let {}::{}(v) = x {{\n",
                                  spec.type_name, vname);
                os << "            asn1cpp_ber::value::Asn1Value::ber_encode(v, out);\n";
                os << "            true\n";
                os << "        } else { false },\n";
                os << "        ber_decode_into: |r| {\n";
                os << std::format("            let mut v: {} = Default::default();\n", a.mtype);
                os << "            asn1cpp_ber::value::Asn1Value::ber_decode_into(&mut v, r)?;\n";
                os << std::format("            Ok({}::{}(v))\n", spec.type_name, vname);
                os << "        },\n";
            }
            os << std::format("        xer_encode: |x, out| if let {}::{}(v) = x {{\n",
                              spec.type_name, vname);
            os << "            asn1cpp_ber::value::Asn1Value::xer_encode(v, out);\n";
            os << "            true\n";
            os << "        } else { false },\n";
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
///       nothing else. See the design note on gambas-asn1#241: the
///       two-call (hpp preamble / cpp preamble) split this method is part
///       of bakes in C++'s header+impl file model, which doesn't fit Rust
///       (no split at all). Not resolved here — this pairing's scope is
///       proving each Backend method produces real, compiling output under
///       the existing two-call contract, not redesigning that contract
///       (needs actual file/stream-ownership requirements from a real
///       --target=rust CLI wiring, gambas-asn1#245, which doesn't exist yet).
void RustBackend::emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const {
    session.buffer(declaration_extension()) << "//! Module: " << module_comment << "\n\n";
}

/// @brief Emit the file-level preamble for a generated module's
///        implementation output.
/// @note Deliberately empty: Rust has nothing analogous to C++'s
///       `#include "X.hpp"` + GCC pragma pair here. See emit_declaration_preamble's
///       note — this is the concrete symptom of the two-file-model
///       mismatch flagged in #241's design note, left unresolved by design
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
/// @note Deliberately empty: RustBackend's emit_builtin_alias_definition (#236)
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
///       pairing (see e.g. emit_sequence_declaration's note): real Generator ->
///       RustBackend wiring doesn't exist yet (#245).
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
///        declares `pub mod <filename>;` for every generated file, one
///        module per file, module name == filename (gambas-asn1#266).
void RustBackend::emit_type_reference(const std::string& type_name, const std::string& filename,
                                       TypeOutputSession& session) const {
    session.buffer(declaration_extension()) << std::format("use crate::{}::{};\n", filename, type_name);
}

/// @brief Rust has no forward-declaration concept — a type is visible
///        regardless of declaration order once its module is `use`d.
void RustBackend::emit_forward_declaration(const std::string&, TypeOutputSession&) const {
}

/// @brief Rust's `Option<T>` needs no special member functions — no
///        equivalent of C++'s unique_ptr-deep-copy dance (gambas-asn1#268).
void RustBackend::emit_special_members(const std::string&, TypeOutputSession&) const {
}

/// @brief Rust's `Option<T>` needs no storage-ops helper type — same
///        rationale as emit_special_members.
void RustBackend::emit_optional_member_ops(const std::string&, const std::string&,
                                            const std::string&, TypeOutputSession&) const {
}

/// @brief Write the crate root: one `pub mod <filename>;` per generated
///        `.rs` file, so the `use crate::<filename>::<Type>;` paths
///        emit_type_reference emits actually resolve (gambas-asn1#266).
///        WIP (#214): flat mod-per-file list, no module tree mirroring
///        ASN.1 modules.
void RustBackend::finalize_output(const std::string& out_dir) const {
    namespace fs = std::filesystem;
    fs::path lib_rs = fs::path(out_dir) / "lib.rs";
    std::ofstream lib(lib_rs);
    for (const auto& entry : fs::directory_iterator(out_dir)) {
        if (entry.path().extension() != ".rs" || entry.path() == lib_rs) continue;
        lib << "pub mod " << entry.path().stem().string() << ";\n";
    }
}

} // namespace asn1::codegen
