#pragma once
#include "Backend.hpp"
#include "Casing.hpp"
#include "Generator.hpp"  // to_cpp_name / make_synthetic_name — reused where PascalCase overlaps with Rust (see class comment)
#include <cctype>
#include <unordered_map>
#include <unordered_set>

namespace asn1::codegen {

// Escape an identifier that collides with a Rust 2021 keyword or any name in
// `extra`, using a raw identifier (`r#...`) — matches the convention rustc
// itself uses for keyword-colliding names from external sources.
inline std::string rust_escape(std::string n,
                                std::initializer_list<std::string_view> extra = {}) {
    static const std::unordered_set<std::string> kw = {
        "as","break","const","continue","crate","dyn","else","enum","extern",
        "false","fn","for","if","impl","in","let","loop","match","mod","move",
        "mut","pub","ref","return","self","Self","static","struct","super",
        "trait","true","type","unsafe","use","where","while","async","await",
        "try","union","abstract","become","box","do","final","macro","override",
        "priv","typeof","unsized","virtual","yield",
    };
    auto is_reserved = [&](const std::string& s) {
        if (kw.count(s)) return true;
        for (auto e : extra) if (s == e) return true;
        return false;
    };
    if (!is_reserved(n)) return n;
    return "r#" + n;
}

/// @brief Rust backend: the second `Backend` implementation, proving the
///        naming interface is genuinely language-agnostic and not secretly
///        C++-shaped.
///
/// Deliberately diverges from CppBackend only where Rust *syntax* (not
/// style) requires it — `escape` uses Rust's own keyword list +
/// raw-identifier escaping (`r#...`), not C++'s trailing-underscore
/// convention. `type_name`/`member_name`/`synthetic_name`/`value_name`
/// otherwise reuse the same minimal, no-recase transliteration as
/// CppBackend (hyphen -> underscore only): ASN.1 name fidelity in generated
/// code is preferred over Rust style-guide conformance (naming lints are
/// blanket-suppressed per generated file instead — see
/// emit_declaration_preamble). An earlier version of this backend did a
/// real word-split recase (to_upper_camel_case/to_snake_case/
/// to_screaming_snake_case) purely to dodge those lints, but two distinct
/// ASN.1 identifiers can fold to the same recased name (e.g. "field-one"
/// and "fieldOne" both became "FieldOne") — a silent type/name collision,
/// not just a style choice. Generator::dedupe_styled_names/
/// promoted_member_name_ remain as a safety net for a genuine ASN.1-level
/// clash (literal "foo-bar" vs "foo_bar" siblings), but are no longer the
/// primary defense.
class RustBackend : public Backend {
public:
    std::string type_name(std::string_view asn1_name) const override {
        return to_cpp_name(asn1_name);
    }

    // Minimal transliteration (hyphen -> underscore, lowercase first letter)
    // — not Generator.hpp's to_member_name, which also runs C++'s own
    // keyword list via safe_name; Rust keyword safety comes from the
    // rust_escape() wrap below instead.
    std::string member_name(std::string_view asn1_name,
                             std::initializer_list<std::string_view> extra = {}) const override {
        auto n = to_cpp_name(asn1_name);
        if (!n.empty()) n[0] = (char)std::tolower((unsigned char)n[0]);
        return rust_escape(std::move(n), extra);
    }

    // Minimal transliteration (hyphen -> underscore only, case preserved,
    // matching asn1c's own INTEGER-named-value convention) instead of
    // to_screaming_snake_case. Unlike SCREAMING_SNAKE_CASE (all-uppercase,
    // so never literally equal to a lowercase Rust keyword), a
    // case-preserving name could collide with one — explicit rust_escape()
    // needed here where it wasn't before.
    std::string value_name(std::string_view asn1_name) const override {
        return rust_escape(to_value_name(asn1_name));
    }

    std::string escape(std::string name,
                        std::initializer_list<std::string_view> extra = {}) const override {
        return rust_escape(std::move(name), extra);
    }

    // Reuses make_synthetic_name verbatim (CppBackend's own synthetic_name
    // body) — now that type_name() is the same minimal transliteration
    // CppBackend uses, this is byte-for-byte the same formula as
    // Generator::native_member_type_for's own inline-ENUMERATED-member
    // calculation (`member_synth_name`'s fallback,
    // `current_type_ + capitalize_first(backend_.type_name(name))`), so the
    // two can't drift apart the way two independent recase formulas could.
    std::string synthetic_name(const std::string& parent,
                                const std::string& member_name) const override {
        return make_synthetic_name(parent, member_name);
    }

    // No "asn_TYP_" prefix (that's CppBackend's own static-variable
    // convention) — an explicit "_" separator, not just a
    // case transition, so to_screaming_snake_case's word-splitter finds the
    // parent/member boundary correctly even when mname is lowercase-first
    // (the common case, X.680 §11.2's own convention for member names) —
    // concatenating with no separator at all would merge the two into one
    // run with no detectable boundary.
    std::string member_descriptor_base_name(const std::string& parent_cname,
                                              const std::string& mname) const override {
        return parent_cname + "_" + mname;
    }

    std::string native_int_type(IntStorageKind kind) const override {
        switch (kind) {
            case IntStorageKind::U64:       return "asn1cpp_wire::integer::UInteger";
            case IntStorageKind::I128:      return "asn1cpp_wire::integer::BigInteger";  // Rust has a real 128-bit type — no C++-style stub
            case IntStorageKind::ARBITRARY: return "asn1cpp_wire::integer::ArbitraryInteger";
            default:                        return "asn1cpp_wire::integer::Integer";
        }
    }

    // Defined in RustBackend.cpp — reuses the same mapping as the file-local
    // native_builtin_type() free function every other Rust construct pairing
    // calls internally, also reachable from
    // Generator::native_member_type_for, not just RustBackend's own emit_* methods.
    std::string native_builtin_type(ast::BuiltinType bt) const override;

    // Generator::tag_literal()/natural_tag_for() call this
    // unconditionally (populates SequenceMemberSpec::resolved_tag/
    // ChoiceAlternativeSpec::resolved_tag for every SEQUENCE/CHOICE member,
    // regardless of active backend) — must be real, not a stub, or Rust
    // codegen throws on every SEQUENCE/CHOICE. Defined in RustBackend.cpp.
    std::string format_tag_literal(const TypeTagSpec& tag_spec) const override;

    // Same reasoning as format_tag_literal's own comment —
    // resolved_tag is populated unconditionally for every member, so this
    // must return real Rust syntax, not throw. Dead in practice today (no
    // RustBackend.cpp call site ever reads SequenceMemberSpec::resolved_tag/
    // ChoiceAlternativeSpec::resolved_tag — RustBackend computes its own
    // tags via mbuiltin instead), but must stay valid Rust in case that
    // changes (e.g. CHOICE-member coverage).
    std::string format_no_tag_literal() const override {
        return "asn1cpp_wire::ber::tag::Tag { class: asn1cpp_wire::ber::tag::TagClass::Context, number: 0, constructed: false }";
    }

    // tdref is populated unconditionally for every
    // Every kind but MemberOwnTable has no codec dispatch table wired up yet
    // for Rust to read (see Backend::format_type_descriptor_ref's own doc) —
    // same status as needs_seqof_wrapper_reference() below. Empty string is
    // a valid, harmlessly-unused default there; revisit together with
    // needs_seqof_wrapper_reference() once Rust grows its own per-member
    // descriptor table for those kinds. MemberOwnTable is real: it's how a
    // member's own inline-constraint Constraints table (already emitted by
    // emit_member_type_descriptor) gets found by name — returned bare, with
    // no decoration, since every consumer (SeqOf element constraint lookup,
    // the own-table checks for SEQUENCE members/CHOICE alternatives) only
    // ever needs the plain base name to build its own
    // `{SCREAMING_SNAKE_CASE}_CONSTRAINTS` reference from.
    std::string format_type_descriptor_ref(const TypeDescriptorRefSpec& spec) const override {
        if (spec.kind == TypeDescriptorRefKind::MemberOwnTable) return spec.name;
        return {};
    }

    std::string wrap_collection_type(const std::string& elem_type) const override {
        return std::format("Vec<{}>", elem_type);
    }

    // Defined in RustBackend.cpp — real emission logic, not a one-liner
    // like the naming methods above.
    void emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const override;
    void emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const override;
    void emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const override;
    void emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                              const std::string& parent_name, const std::string& member_name,
                              TypeOutputSession& session) const override;
    void emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const override;
    void emit_seq_of(const SeqOfSpec& spec, TypeOutputSession& session) const override;
    void emit_sequence(const SequenceSpec& spec, TypeOutputSession& session) const override;
    void emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const override;
    void emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const override;
    void emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const override;
    void emit_namespace_open(const std::string& name, TypeOutputSession& session) const override;
    void emit_namespace_close(const std::string& name, TypeOutputSession& session) const override;
    void emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                 TypeOutputSession& session) const override;
    void emit_type_reference(const std::string& type_name, const std::string& filename,
                              TypeOutputSession& session) const override;
    // dedupe_type_references() default (Backend.hpp) is
    // true and covers RustBackend's need — no override necessary here.
    // needs_seqof_wrapper_reference() default (Backend.hpp)
    // is true, tied to CppBackend's tdref/asn_DEF_<wrapper> descriptor
    // usage — RustBackend has no such table wiring yet, so the wrapper
    // reference is dead weight (unused_imports) today. Provisional, not a
    // structural "Rust never needs this" fact — see Backend::needs_seqof_
    // wrapper_reference's own doc comment. Revisit this override once Rust
    // grows real BER/XER dispatch tables for SEQUENCE OF/SET OF members.
    bool needs_seqof_wrapper_reference() const override { return false; }

    // See Backend::needs_forward_declare_for_cyclic_alias's own doc: Rust's
    // whole-crate name resolution needs the ordinary `use` import
    // regardless of cycles, and RustBackend::emit_forward_declaration below
    // is a true no-op — following the C++ default here would silently drop
    // that import for a cyclic bare-alias reference.
    bool needs_forward_declare_for_cyclic_alias() const override { return false; }

    void emit_forward_declaration(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_special_members(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_optional_member_ops(const std::string& type_name, const std::string& member_name,
                                   const std::string& member_type, TypeOutputSession& session) const override;
    void finalize_output(const std::string& out_dir) const override;

    // Single-file mode: Rust has no header/impl split.
    // Returning the same extension from both methods makes
    // TypeOutputSession::buffer() hand back the same stream for
    // emit_declaration's and emit_definition's content, merging them into one "<Type>.rs"
    // file instead of a ".hpp"/".cpp" pair — no separate merge flag needed.
    std::string declaration_extension() const override { return "rs"; }
    std::string definition_extension() const override { return "rs"; }

private:
    // Split declaration/definition halves — kept as private helpers so the
    // per-construct emission bodies don't need reshaping; the public emit_*
    // overrides above just call both in sequence.
    void emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const;
    void emit_enumerated_definition(const EnumeratedSpec& spec, std::ostream& os) const;
    void emit_integer_declaration(const IntegerSpec& spec, std::ostream& os) const;
    void emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const;
    void emit_builtin_alias_declaration(const BuiltinAliasSpec& spec, std::ostream& os) const;
    void emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const;
    void emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const;
    void emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const;
    void emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const;
    void emit_sequence_definition(const SequenceSpec& spec, std::ostream& os) const;
    void emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const;
    void emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const;

    // Per-row real-vs-stub predicates for emit_sequence_definition/
    // emit_choice_definition — every generated SEQUENCE/SET/CHOICE always
    // gets a real table and `Asn1Value` impl (see
    // `sequence::MemberAccess::Unsupported`'s doc, rust-runtime/wire). These
    // predicates do not gate whether a *type* gets emitted at all; they only
    // decide whether a given member/alternative's own row is a real access
    // closure or an `Unsupported` stub. A referenced composite type (a
    // TypeRef to SEQUENCE/SET/CHOICE/ENUMERATED, or a TypeRef-aliased
    // INTEGER) is always real regardless of processing order — it will
    // have *some* `Asn1Value` impl (real or stub) by the time the crate
    // finishes compiling either way, so referencing it is always safe; no
    // per-run coverage bookkeeping is needed to know that in advance. The
    // Rust-only concern (this backend's own trait-object dispatch model),
    // so it lives here rather than on the shared Backend interface/Generator.
    // No per-run bookkeeping needed: every referenced composite type (a
    // TypeRef to SEQUENCE/SET/CHOICE/ENUMERATED, a TypeRef-aliased INTEGER
    // of any storage kind, an ARBITRARY-storage alias included since
    // `integer::ArbitraryInteger` is its own real newtype now) is always
    // real regardless of processing order — it will have *some* `Asn1Value`
    // impl (real or stub) by the time the crate finishes compiling either
    // way, so referencing it is always safe.
    bool sequence_member_covered(const SequenceMemberSpec& m) const;
    bool choice_alternative_covered(const ChoiceAlternativeSpec& a) const;
    // Whether a CHOICE alternative has any resolved tag at all — see
    // choice_alternative_has_tag's own doc (RustBackend.cpp) for why this
    // is a separate, prior question from choice_alternative_covered.
    bool choice_alternative_has_tag(const ChoiceAlternativeSpec& a) const;
};

} // namespace asn1::codegen
