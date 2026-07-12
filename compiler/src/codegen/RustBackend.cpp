#include "RustBackend.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>

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
static std::string variant_name(const RustBackend& backend, const std::string& asn1_name) {
    return backend.escape(capitalize_first(backend.type_name(asn1_name)));
}

void RustBackend::emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const {
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

void RustBackend::emit_enumerated_definition(const EnumeratedSpec& spec, std::ostream& os) const {
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
/// @note Deliberately simple mappings (`String` for every text type
///       regardless of alphabet, `Vec<u8>` for OCTET STRING/BIT STRING/OID/
///       Any, `String` for UtcTime/GeneralizedTime rather than a real
///       timestamp type) — matches this pairing's scope (compiles as real
///       Rust, no runtime wiring yet). A real BER/PER runtime would likely
///       want tighter types (e.g. `[u32]` arcs for OID); revisit then.
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
        os << std::format("    pub {}: {},\n", m.mname,
                           m.optional ? std::format("Option<{}>", m.mtype) : m.mtype);
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
    // every member is a plain required INTEGER (native_int_type's S64
    // default, "i64") get a real descriptor table + encode()/decode();
    // anything else (OPTIONAL members, CHOICE/SEQUENCE OF/string members,
    // ...) still gets only the struct shape. Broadening member-type/tag
    // coverage is real follow-on work, not this issue's scope — the point
    // here is the *shape* (table + accessor functions + generic runtime
    // walker), not covering every construct.
    bool integer_only = !spec.members.empty() &&
        std::all_of(spec.members.begin(), spec.members.end(),
                     [](const SequenceMemberSpec& m) { return !m.optional && m.mtype == "i64"; });
    if (integer_only) {
        std::string members_ident = std::format("{}_MEMBERS", to_screaming_snake_case(spec.type_name));
        std::string spec_ident = std::format("{}_SPEC", to_screaming_snake_case(spec.type_name));

        os << std::format("static {}: [asn1cpp_ber::sequence::MemberDescriptor<{}>; {}] = [\n",
                          members_ident, spec.type_name, spec.members.size());
        for (const auto& m : spec.members) {
            os << "    asn1cpp_ber::sequence::MemberDescriptor {\n";
            os << std::format("        name: \"{}\",\n", m.asn1_name);
            os << "        tag: asn1cpp_ber::integer::INTEGER_TAG,\n";
            os << "        optional: false,\n";
            os << std::format("        get: |v| &v.{},\n", m.mname);
            os << std::format("        get_mut: |v| &mut v.{},\n", m.mname);
            os << "    },\n";
        }
        os << "];\n\n";

        os << std::format(
            "static {}: asn1cpp_ber::sequence::SequenceSpec<{}> = asn1cpp_ber::sequence::SequenceSpec {{\n",
            spec_ident, spec.type_name);
        os << "    tag: asn1cpp_ber::sequence::SEQUENCE_TAG,\n";
        os << std::format("    members: &{},\n", members_ident);
        os << "};\n\n";

        os << std::format("impl {} {{\n", spec.type_name);
        os << "    pub fn encode(&self) -> Vec<u8> {\n";
        os << std::format("        asn1cpp_ber::sequence::encode_sequence(&{}, self)\n", spec_ident);
        os << "    }\n\n";
        os << "    pub fn decode(data: &[u8]) -> Result<Self, asn1cpp_ber::DecodeError> {\n";
        os << std::format("        asn1cpp_ber::sequence::decode_sequence(&{}, data)\n", spec_ident);
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
///       `std::launder`/`ChoiceOps<T>` storage design (see design note on
///       gambas-asn1#240) — that design exists only to dodge
///       `std::variant`'s O(N²) template-instantiation blowup on large
///       CHOICEs, a C++-template-specific failure mode. Rust's `enum` is a
///       native tagged union, not template-recursive, so the natural
///       mapping has no equivalent problem. No `#[derive(Default)]`: unlike
///       a struct, a CHOICE has no natural default variant.
void RustBackend::emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const {
    os << "#[derive(Debug, Clone, PartialEq)]\n";
    os << std::format("pub enum {} {{\n", spec.type_name);
    for (const auto& a : spec.alternatives)
        os << std::format("    {}({}),\n", a.pr_name, a.mtype);
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
                           spec.type_name, a.pr_name);
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
