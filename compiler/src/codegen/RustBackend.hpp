#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / make_synthetic_name — reused where PascalCase overlaps with Rust (see class comment)
#include <cctype>
#include <unordered_map>
#include <unordered_set>

namespace asn1::codegen {

// gambas-asn1#306: acronym-aware word splitter — the naive "insert '_'
// before every uppercase letter" rule (to_snake_case's old body) splits a
// run of consecutive uppercase letters one at a time ("TYP" -> "t_y_p"
// instead of "typ"), because it treats every individual uppercase letter as
// its own word start rather than recognizing a whole acronym run as one
// word. Standard rule instead: '-' or '_' is always a hard word break
// (X.680's own identifier separator, plus the literal underscores already
// present in CppBackend-convention synthetic names like "asn_TYP_Parent_
// member" that also get routed through to_snake_case); a lowercase/digit ->
// uppercase transition starts a new word; a run of 2+ uppercase letters
// followed by a lowercase letter keeps the run together except its *last*
// letter, which starts the next word ("HTTPServer" -> ["HTTP", "Server"],
// not one letter per word). Not purely cosmetic scope creep: this is the
// same word-splitting problem #305's to_upper_camel_case solves in the
// opposite case direction — see gambas-asn1#356 (tracked follow-up to
// unify both under one shared tokenizer instead of near-duplicate logic).
inline std::vector<std::string> split_words(std::string_view s) {
    std::vector<std::string> words;
    std::string cur;
    auto flush = [&]() { if (!cur.empty()) { words.push_back(cur); cur.clear(); } };
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '-' || c == '_') { flush(); continue; }
        if (std::isupper(static_cast<unsigned char>(c)) && !cur.empty()) {
            bool prev_upper = std::isupper(static_cast<unsigned char>(cur.back()));
            bool next_lower = (i + 1 < s.size()) && std::islower(static_cast<unsigned char>(s[i + 1]));
            if (!prev_upper || next_lower) flush();
        }
        cur += c;
    }
    flush();
    return words;
}

// snake_case conversion shared by member_name/value_name — word-split via
// split_words(), each word lower-cased and joined with '_'.
// "myMember" -> "my_member"; "MyType" -> "my_type"; "HTTPServer" ->
// "http_server" (not "h_t_t_p_server"); "already_snake" unchanged.
inline std::string to_snake_case(std::string_view s) {
    std::string out;
    for (const auto& w : split_words(s)) {
        if (!out.empty()) out += '_';
        for (char c : w) out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// SCREAMING_SNAKE_CASE conversion for Rust `const` names.
inline std::string to_screaming_snake_case(std::string_view s) {
    std::string out = to_snake_case(s);
    for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

// gambas-asn1#305: real word-split UpperCamelCase conversion, unlike
// capitalize_first (which only uppercases the first character of the whole
// string). X.680 §11.2 identifiers are hyphen-separated lowercase words
// (e.g. "eight-bit-binary") — capitalize_first(to_cpp_name(...)) turns the
// hyphen into a literal underscore first, so multi-word ASN.1 value names
// came out "Eight_bit_binary" (fails rustc's non_camel_case_types lint), not
// "EightBitBinary". Splits on '-' (the only word separator X.680 allows in
// an identifier) and capitalizes the first letter of every segment, joining
// with no separator; single-word names behave identically to the old
// capitalize_first(to_cpp_name(...)) path.
inline std::string to_upper_camel_case(std::string_view s) {
    std::string out;
    bool new_word = true;
    for (char c : s) {
        if (c == '-') { new_word = true; continue; }
        if (new_word) {
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            new_word = false;
        } else {
            out += c;
        }
    }
    return out;
}

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
/// Deliberately diverges from CppBackend where Rust convention differs —
/// `member_name`/`value_name` are real snake_case/SCREAMING_SNAKE_CASE
/// conversions, not a reuse of C++'s lowerCamelCase, and `escape` uses
/// Rust's own keyword list + raw-identifier escaping (`r#...`), not C++'s
/// trailing-underscore convention. `type_name`/`synthetic_name` reuse the
/// same PascalCase transform as CppBackend because ASN.1 type names and
/// Rust struct/enum names both want PascalCase — that overlap is
/// coincidental, not an assumption baked into the interface.
class RustBackend : public Backend {
public:
    // gambas-asn1#306: to_upper_camel_case (real word-split PascalCase,
    // shared with #305's variant_name), not to_cpp_name (hyphen->underscore
    // only, no case normalization) — an ASN.1 type name written
    // ALL-CAPS-WITH-HYPHENS (e.g. "TARGETACTIVITYMONITOR-1") or
    // mixed-case-with-hyphens (e.g. "EpsHI2OperationsGA-PointWithUnCertainty")
    // used to keep its hyphen as a literal underscore in the generated Rust
    // identifier ("TARGETACTIVITYMONITOR_1"), which fails rustc's
    // non_camel_case_types lint — the lint only checks for a literal
    // underscore in the identifier, not internal acronym casing, so simply
    // not reintroducing the hyphen as an underscore is enough (confirmed
    // empirically: an all-caps identifier with no underscore, e.g.
    // "TARGETACTIVITYMONITOR1", does not warn).
    std::string type_name(std::string_view asn1_name) const override {
        return to_upper_camel_case(asn1_name);
    }

    std::string member_name(std::string_view asn1_name,
                             std::initializer_list<std::string_view> extra = {}) const override {
        return rust_escape(to_snake_case(asn1_name), extra);
    }

    std::string value_name(std::string_view asn1_name) const override {
        return to_screaming_snake_case(asn1_name);
    }

    std::string escape(std::string name,
                        std::initializer_list<std::string_view> extra = {}) const override {
        return rust_escape(std::move(name), extra);
    }

    // gambas-asn1#306: parent + to_upper_camel_case(member_name), not
    // make_synthetic_name's capitalize_first(to_cpp_name(...)) — must match
    // Generator::cpp_type_for's own inline-ENUMERATED-member calculation
    // (`current_type_ + capitalize_first(backend_.type_name(name))`,
    // Generator.cpp), the *other* independent place that computes this same
    // synthetic type's name when referencing it from a field/generic
    // position. Both sides agreed by coincidence while type_name() was
    // to_cpp_name too; diverged the moment type_name() became a real
    // word-split PascalCase conversion, producing an
    // undefined-type-reference compile error on any real-world schema with
    // hyphenated inline SEQUENCE/CHOICE/ENUMERATED member names (confirmed
    // on the ETSI LI PS-PDU schema, #299/#355).
    std::string synthetic_name(const std::string& parent,
                                const std::string& member_name) const override {
        return parent + to_upper_camel_case(member_name);
    }

    std::string native_int_type(IntStorageKind kind) const override {
        switch (kind) {
            case IntStorageKind::U64:       return "u64";
            case IntStorageKind::I128:      return "i128";  // Rust has a real 128-bit type — no C++-style stub
            case IntStorageKind::ARBITRARY: return "Vec<u8>";
            default:                        return "i64";
        }
    }

    // Defined in RustBackend.cpp — reuses the same mapping as the file-local
    // native_builtin_type() free function every other Rust construct pairing
    // already calls internally (gambas-asn1#270: now also reachable from
    // Generator::cpp_type_for, not just RustBackend's own emit_* methods).
    std::string native_builtin_type(ast::BuiltinType bt) const override;

    // gambas-asn1#290: Generator::tag_literal()/natural_tag_for() call this
    // unconditionally (populates SequenceMemberSpec::eff_tag/
    // ChoiceAlternativeSpec::eff_tag for every SEQUENCE/CHOICE member,
    // regardless of active backend) — must be real, not a stub, or Rust
    // codegen throws on every SEQUENCE/CHOICE. Defined in RustBackend.cpp.
    std::string format_tag_literal(const TypeTagSpec& tag_spec) const override;

    // gambas-asn1#347: same reasoning as format_tag_literal's own comment —
    // eff_tag is populated unconditionally for every member, so this must
    // return real Rust syntax, not throw. Dead in practice today (no
    // RustBackend.cpp call site ever reads SequenceMemberSpec::eff_tag/
    // ChoiceAlternativeSpec::eff_tag — confirmed by grep — RustBackend
    // computes its own tags via mbuiltin/resolved_tag instead), but must
    // stay valid Rust in case that changes (e.g. CHOICE-member coverage).
    std::string format_no_tag_literal() const override {
        return "asn1cpp_ber::tag::Tag { class: asn1cpp_ber::tag::TagClass::Context, number: 0, constructed: false }";
    }

    std::string wrap_collection_type(const std::string& elem_type) const override {
        return std::format("Vec<{}>", elem_type);
    }

    // See Backend::use_synthetic_seqof_member_type's own doc — Vec<T> has
    // no Asn1Value impl to reach for a named member/alternative, so use the
    // synthetic wrapper Generator::generate_inline_types already generates.
    bool use_synthetic_seqof_member_type() const override { return true; }

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
    // gambas-asn1#300: dedupe_type_references() default (Backend.hpp) is
    // true and covers RustBackend's need — no override necessary here.
    // gambas-asn1#312: needs_seqof_wrapper_reference() default (Backend.hpp)
    // is true, tied to CppBackend's tdref/asn_DEF_<wrapper> descriptor
    // usage — RustBackend has no such table wiring yet, so the wrapper
    // reference is dead weight (unused_imports) today. Provisional, not a
    // structural "Rust never needs this" fact — see Backend::needs_seqof_
    // wrapper_reference's own doc comment. Revisit this override once Rust
    // grows real BER/XER dispatch tables for SEQUENCE OF/SET OF members.
    bool needs_seqof_wrapper_reference() const override { return false; }

    void emit_forward_declaration(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_special_members(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_optional_member_ops(const std::string& type_name, const std::string& member_name,
                                   const std::string& member_type, TypeOutputSession& session) const override;
    void finalize_output(const std::string& out_dir) const override;

    // Single-file mode (gambas-asn1#262): Rust has no header/impl split.
    // Returning the same extension from both methods makes
    // TypeOutputSession::buffer() hand back the same stream for
    // emit_declaration's and emit_definition's content, merging them into one "<Type>.rs"
    // file instead of a ".hpp"/".cpp" pair — no separate merge flag needed.
    std::string declaration_extension() const override { return "rs"; }
    std::string definition_extension() const override { return "rs"; }

private:
    // Split declaration/definition halves — kept as private helpers so the
    // per-construct emission bodies don't need reshaping; the public emit_*
    // overrides above just call both in sequence (gambas-asn1#265).
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
    // gets a real table and `Asn1Value` impl now (see
    // `sequence::MemberAccess::Unsupported`'s doc, rust-runtime/ber), so
    // these no longer gate whether a *type* gets emitted at all; they only
    // decide whether a given member/alternative's own row is a real access
    // closure or an `Unsupported` stub. A referenced composite type (a
    // TypeRef to SEQUENCE/SET/CHOICE/ENUMERATED, or a TypeRef-aliased
    // INTEGER) is always real regardless of processing order — it will
    // have *some* `Asn1Value` impl (real or stub) by the time the crate
    // finishes compiling either way, so referencing it is always safe; no
    // per-run coverage bookkeeping is needed to know that in advance. The
    // one exception is unusable_alias_names_ below — see
    // sequence_member_covered's own doc (RustBackend.cpp) for why.
    // Rust-only concerns (this backend's own trait-object dispatch model),
    // so they live here rather than on the shared Backend interface/Generator.
    bool sequence_member_covered(const SequenceMemberSpec& m) const;
    bool choice_alternative_covered(const ChoiceAlternativeSpec& a) const;
    // Whether a CHOICE alternative has any resolved tag at all — see
    // choice_alternative_has_tag's own doc (RustBackend.cpp) for why this
    // is a separate, prior question from choice_alternative_covered.
    bool choice_alternative_has_tag(const ChoiceAlternativeSpec& a) const;

    // Names of type aliases known to resolve to a Rust type with no usable
    // Asn1Value impl for member-reference purposes — an ARBITRARY-storage
    // INTEGER alias (Vec<u8>, wrong-shaped: collides with OCTET STRING's
    // own impl) or a named top-level SEQUENCE OF/SET OF alias (Vec<T>,
    // T != u8: no impl at all). Populated by emit_integer_declaration/
    // emit_seq_of_declaration, consulted by sequence_member_covered/
    // choice_alternative_covered to explicitly stub a reference to one
    // instead of assuming it's safe like every other composite reference
    // (see those methods' own doc for the full rationale). `mutable`:
    // populated by emit_integer/emit_seq_of, which are const per the
    // Backend interface.
    mutable std::unordered_set<std::string> unusable_alias_names_;
};

} // namespace asn1::codegen
