#pragma once
#include <string>
#include <string_view>
#include <initializer_list>
#include <ostream>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>
#include <sstream>
#include <utility>
#include <asn1cpp/compat/format.hpp>
#include "../ast/TypeDef.hpp"
#include "../ast/Tag.hpp"

namespace asn1::codegen {

/// @brief Backend-agnostic BER tag decision (X.690 §8.1) — class, number,
///        and encoding form. No C++/Rust/etc. syntax; a backend formats
///        this into its own literal syntax (see CppBackend::format_tag_literal).
/// @note Lives here, not Generator.hpp, for the same reason as
///       IntStorageKind: BuiltinAliasSpec (below) needs it, and Backend.hpp
///       can't include Generator.hpp without a cycle.
struct TagSpec {
    ast::TagClass cls;          ///< Tag class (Universal/Application/Context/Private).
    int64_t       number;       ///< Tag number within the class.
    bool          constructed;  ///< True for constructed encoding form.
};

// Storage class for INTEGER types — chosen at codegen time from constraint
// analysis (Generator::classify_integer_storage). Backend-agnostic: a
// backend maps each kind to its own native storage type (see
// Backend::native_int_type). Lives here, not Generator.hpp, because
// IntegerSpec (below) needs it and Backend.hpp can't include Generator.hpp
// without a cycle (Generator.hpp already includes Backend.hpp).
enum class IntStorageKind {
    S64,       // int64_t  — asn1::Integer (default; constrained or signed ranges)
    U64,       // uint64_t — asn1::UInteger (non-negative semi-constrained or large unsigned)
    I128,      // __int128  — asn1::BigInteger (stub; future)
    ARBITRARY, // vector<uint8_t> — asn1::ArbitraryInteger (stub; unconstrained crypto keys)
};

/// @brief Backend-agnostic decision for one ENUMERATED type (X.680 §20) —
///        which named values apply, in declaration order, with automatic
///        numbering (X.680 §20.6) already resolved. No C++/Rust/etc. syntax.
/// @note `type_name` is already resolved via Generator's module-collision
///       logic (itself backend-agnostic — any target needs the same
///       cross-module disambiguation) and backend naming (Backend::type_name),
///       so it's a final identifier, not a raw ASN.1 name. Each `Value::asn1_name`
///       is deliberately left raw: a backend's `emit_enumerated_*` decides its
///       own identifier escaping/reserved-name set (e.g. CppBackend guards
///       against colliding with its own generated method names; a Rust
///       backend's needs will differ since Rust enum variants live in a
///       separate namespace from methods).
struct EnumeratedSpec {
    struct Value { std::string asn1_name; long value; };

    std::string       type_name;   // final type identifier (see note above)
    std::string       xer_name;    // XER tag name (X.693) — not an identifier, no escaping needed
    std::vector<Value> values;     // declaration order, auto-numbering resolved
    bool              extensible;  // true if def.enum_values contained "..."
    int               root_count;  // count of values before the first extension marker
};

/// @brief Backend-agnostic decision for one named INTEGER type (X.680 §19) —
///        storage class, named constants, and constraint bounds. No C++/
///        Rust/etc. syntax; a backend maps `storage_kind` to its own native
///        type and formats the constraint bounds into its own runtime API.
/// @note The constraint fields mirror Generator::IntRange
///       (`extract_integer_range`) already resolved into the shape a
///       TypeDescriptor needs — `range_bits` in particular is a PER-encoding
///       fact (X.691 §10.5.6), not a C++ concept: any backend implementing
///       PER needs the identical value, so it's computed once here rather
///       than re-derived per backend.
struct IntegerSpec {
    struct NamedValue { std::string asn1_name; int64_t value; };

    std::string       type_name;
    std::string       xer_name;
    IntStorageKind    storage_kind;
    std::vector<NamedValue> named_values;  // INTEGER { foo(0), bar(1) } style constants

    bool     has_constraint;    // false -> unconstrained; all fields below are meaningless
    bool     extensible;
    bool     semi_constrained;  // true -> upper endpoint was MAX (X.680 semi-constrained); no upper cap
    bool     hi_is_large;       // true -> upper was a positive literal > INT64_MAX
    int      range_bits;        // -1 when semi_constrained (no fixed upper -> no fixed bit width)
    int64_t  lower_s64, upper_s64;   // signed view (upper_s64 meaningless when hi_is_large)
    uint64_t lower_u64, upper_u64;   // unsigned view (exact when hi_is_large)
};

/// @brief Backend-agnostic decision for a builtin-alias type (X.680 §19) —
///        every ASN.1 builtin type except INTEGER and ENUMERATED, which
///        have their own IntegerSpec/EnumeratedSpec. No C++/Rust/etc.
///        syntax; a backend maps `builtin_type` to its own runtime codec
///        handler and native storage type.
/// @note `builtin_type` is the resolved AST type tag, not a string — reused
///       directly (matching the existing TagSpec::cls precedent) rather
///       than duplicated into a parallel backend-agnostic enum: any backend
///       needs to distinguish OCTET STRING from BOOLEAN etc. the same way,
///       so the AST's own classification is already the right shape.
struct BuiltinAliasSpec {
    std::string            type_name;
    std::string            xer_name;
    ast::BuiltinType        builtin_type;
    std::optional<TagSpec> tag;         // natural tag (X.690 §8.1); always present in practice —
                                         // builtin-alias types are never CHOICE, the only case
                                         // natural-tag resolution returns nullopt for
    std::vector<uint8_t>   alphabet;    // FROM-alphabet constraint (restricted string types); empty = none
    bool     has_size_constraint;       // true if a SIZE constraint is present at all (bounded or semi-constrained)
    bool     size_bounded;              // true iff the SIZE constraint has a finite upper bound;
                                         // false for SIZE(n..MAX) — semi-constrained, no upper cap.
                                         // Distinct from has_size_constraint: a semi-constrained
                                         // SIZE is still "present" (has_size_constraint=true) but
                                         // not "bounded" (size_upper is meaningless when false).
    int      size_range_bits;
    int64_t  size_lower, size_upper;    // size_upper meaningful only when size_bounded
    bool     extensible;
    bool     xer_base64;                // true -> XER encoding uses base64 (X.693, OCTET STRING option)
};

/// @brief Backend-agnostic DEFAULT value decision (X.680 §25.1) — which value
///        applies to a DEFAULT member, not how a backend spells it as a
///        literal. No C++/Rust/etc. syntax; a backend formats this into its
///        own literal/initializer syntax.
/// @note Lives here, not Generator.hpp, for the same reason as TagSpec:
///       Backend::emit_default_setter (below) needs it, and Backend.hpp
///       can't include Generator.hpp without a cycle.
/// @see Generator::default_value_spec_for.
struct DefaultValueSpec {
    enum class Kind { None, Bool, Int, String, EnumRef } kind = Kind::None;
    bool          bool_val = false;
    int64_t       int_val  = 0;
    std::string   string_val;  // Kind::String — raw (unescaped) value
    std::string   enum_name;   // Kind::EnumRef — ASN.1 name of the named value
};

/// @brief Escape a raw byte string for embedding in a quoted string literal.
///        Backslash, double-quote, and all control characters — identical
///        escaping rules in C++ and Rust string literal syntax (both use
///        `\\`, `\"`, `\n`, `\r`, `\t`, `\xHH`), so this one implementation
///        serves both backends' `emit_default_setter`.
/// @param raw Unescaped bytes (e.g. DefaultValueSpec::string_val).
/// @return Escaped text, without surrounding quotes — the caller wraps it
///         in its own language's string literal syntax.
inline std::string escape_string_literal(const std::string& raw) {
    std::string esc;
    for (unsigned char c : raw) {
        if      (c == '\\') esc += "\\\\";
        else if (c == '"')  esc += "\\\"";
        else if (c == '\n') esc += "\\n";
        else if (c == '\r') esc += "\\r";
        else if (c == '\t') esc += "\\t";
        else if (c < 0x20 || c == 0x7f)
            esc += std::format("\\x{:02x}", c);
        else
            esc += static_cast<char>(c);
    }
    return esc;
}

/// @brief Backend-agnostic decision for one inline-constrained SEQUENCE/
///        CHOICE member's per-member TypeDescriptor (X.691 §26.5 character
///        string constraints; X.680 §19 INTEGER value range). Built only
///        when the member carries an inline constraint or non-default XER
///        encoding; Generator::emit_member_type_descriptor falls back to a
///        plain type-descriptor reference otherwise (no spec built). No C++/
///        Rust/etc. syntax — all constraint fields are raw resolved data
///        (same convention as IntegerSpec/BuiltinAliasSpec); each backend
///        formats its own initializer/validator from them. `kind` selects
///        which field group is meaningful (INTEGER value range vs SIZE-able
///        primitive SIZE/FROM-alphabet constraints).
struct MemberTypeDescriptorSpec {
    enum class Kind { Integer, Sizeable } kind;
    std::string tname;            // static variable / synthetic identifier base, e.g. "asn_TYP_Parent_member"

    // Kind::Integer — mirrors IntegerSpec's constraint fields.
    IntStorageKind storage_kind;
    bool     extensible;
    bool     semi_constrained;    // true -> upper endpoint was MAX; no upper cap
    bool     hi_is_large;         // true -> upper was a positive literal > INT64_MAX
    int      range_bits;          // -1 when semi_constrained
    int64_t  lower_s64, upper_s64;
    uint64_t lower_u64, upper_u64;

    // Kind::Sizeable — mirrors BuiltinAliasSpec's SIZE/FROM-alphabet fields.
    ast::BuiltinType      builtin_type;
    std::vector<uint8_t>  alphabet;      // empty = no FROM-alphabet constraint
    std::string           alpha_prefix;  // empty = no FROM-alphabet arrays needed
    bool     has_size_constraint; // true if a SIZE constraint is present at all
    bool     size_bounded;        // true iff the SIZE constraint has a finite upper bound
    int      size_range_bits;
    int64_t  size_lower, size_upper; // size_upper meaningful only when size_bounded
    bool     needs_xer;           // non-default XER encoding (e.g. Base64) requested

    // Both kinds — target-agnostic BER/XER facts (X.690/X.693), not code.
    std::string xer_type_name;    // e.g. "INTEGER", "OCTET_STRING"
    int         universal_tag;    // asn1::UniversalTag::* value
};

/// @brief Backend-agnostic decision for one SEQUENCE OF / SET OF type
///        (X.680 §25/26) — element descriptor reference, collection SIZE
///        constraint, and optional element XER tag rename (X.693 §12). No
///        C++/Rust/etc. syntax; `elem_ref` is already a fully-formatted
///        reference expression since it comes from the (already
///        backend-delegated) emit_member_type_descriptor call.
struct SeqOfSpec {
    std::string type_name;
    std::string xer_name;
    std::string elem_ref;        // reference expression to the element's TypeDescriptor
    std::string elem_type;       // element's native storage type (hpp `using X = VectorSeqOf<elem_type>` only)
    int         range_bits;
    int64_t     size_lower;
    std::optional<int64_t> size_upper; // present = finite upper bound; absent = semi-constrained/unconstrained
    std::optional<std::string> elem_xer_name; // X.693 §12: element's declared identifier, if any
    bool        is_set_of;              // true -> natural tag is SET, else SEQUENCE
};

/// @brief Backend-agnostic decision for one SEQUENCE/SET member. Several
///        fields are pre-formatted C++ expression text (`ops`, `tdref`,
///        `def_setter`, `offset_expr`) rather than raw data — same
///        rationale as SeqOfSpec::elem_ref: they reference C++-runtime-only
///        constructs (UniquePtrOps aliases, static TypeDescriptor
///        variables, offsetof macros) that only CppBackend's own emitted
///        text can resolve. This issue's scope (#231) is moving the
///        existing C++ emission verbatim off Generator, not redesigning
///        SEQUENCE for a second backend — that's #239's job.
/// @note Used identically for both the `.hpp` and `.cpp` passes; the `.hpp`
///       pass only reads `mtype`/`mname`/`optional`/`setter_*` and leaves
///       the rest default-constructed (never read by emit_sequence_declaration).
struct SequenceMemberSpec {
    std::string asn1_name;      // raw ASN.1 name — MemberDescriptor "name" field
    std::string mtype;          // C++ storage type
    std::string mname;          // member identifier
    std::string eff_tag;        // pre-formatted tag literal expression
    bool        optional = false;
    bool        is_explicit = false;
    bool        has_default = false;
    std::string ops;            // pre-formatted Ops initializer, e.g. "{ &_Ops_X_Y::check, ... }"
    std::string tdref;          // reference expression to the member's TypeDescriptor
    std::string def_setter;     // "&_setdef_Parent_member" or "nullptr"
    std::string offset_expr;    // "ASN1CPP_OFFSETOF(...)" or "asn1::kInvalidMemberOffset"
    std::string setter_param_type;   // empty = no set_<member>() emitted
    bool        setter_is_move = false;
    bool        setter_is_int_alias = false;
    bool        setter_is_uint_alias = false;
};

/// @brief Backend-agnostic decision for one SEQUENCE/SET type (X.680 §24/25).
///        See SequenceMemberSpec's note on why several fields stay
///        pre-formatted C++ text for this issue's scope.
struct SequenceSpec {
    std::string type_name;
    std::string xer_name;
    bool        has_optional_members;
    int         mcount;
    int         ext_at;
    int         roms_count;
    bool        is_set;         // true -> natural tag is SET, else SEQUENCE
    std::vector<SequenceMemberSpec> members; // root members first, then extension members
};

/// @brief Backend-agnostic decision for one CHOICE alternative. Field
///        groups are pass-specific (see SequenceMemberSpec's note on the
///        same pattern): `mtype`/`accessor_name`/`pr_name` are read by
///        emit_choice_declaration; `asn1_name`/`eff_tag`/`tdref`/`is_explicit` by
///        emit_choice_definition. `mtype` is shared by both (same value, computed
///        once): the accessor return type in the header, and the
///        `ChoiceOps<T>` template parameter in the alternatives table.
struct ChoiceAlternativeSpec {
    std::string mtype;
    std::string accessor_name;
    std::string pr_name;

    std::string asn1_name;
    std::string eff_tag;
    std::string tdref;
    bool        is_explicit = false;
};

/// @brief Backend-agnostic decision for one CHOICE type (X.680 §28). The
///        `.hpp` and `.cpp` passes build independent `alternatives` lists
///        (mirroring the original code's independent canonical-ordering
///        computations for each — not unified here, to avoid any risk of
///        introducing a reordering divergence between the two).
/// @note `tag_index_table`/`ber_tags` are raw resolved data (same
///       convention as every other spec) — Generator's existing
///       density-heuristic / tag-flattening decision logic (X.691 §22.6)
///       decides *whether* and *what*; CppBackend formats the resulting
///       arrays and ChoiceSpec aggregate fields into C++ text.
struct ChoiceSpec {
    std::string type_name;
    std::string xer_name;
    int count;
    int ext_at;
    std::vector<ChoiceAlternativeSpec> alternatives;

    // O(1) context-tag dispatch table (density-heuristic gated).
    bool                  has_tag_index = false;
    int                   tag_index_base = 0;
    std::vector<int16_t>  tag_index_table; // -1 = no alternative at this tag; size == range

    // Flattened BER dispatch table (untagged-CHOICE-alternative case).
    bool                                     has_ber_table = false;
    std::vector<std::pair<std::string,int>>  ber_tags; // {pre-formatted tag literal, alt index}
};

/// @brief Confines identifier-escaping and naming-convention decisions that
///        are inherently target-language-specific.
///
/// `Generator` computes backend-agnostic decisions (`TagSpec`,
/// `DefaultValueSpec`, `IntStorageKind`, ...) from the resolved AST and asks
/// a `Backend` to turn ASN.1 names into valid identifiers for its target
/// language. `CppBackend` is the only implementation today; a future Rust
/// backend implements the same interface with its own keyword list and
/// naming conventions.
class Backend {
public:
    virtual ~Backend() = default;

    /// @brief ASN.1 type name -> target-language type identifier.
    ///        e.g. "My-Type" -> "MyType" in C++.
    virtual std::string type_name(std::string_view asn1_name) const = 0;

    /// @brief ASN.1 member/field name -> target-language member identifier,
    ///        escaped against keyword/extra-name collisions.
    /// @param asn1_name ASN.1 member name.
    /// @param extra     Additional reserved names to escape against (e.g.
    ///                  sibling generated method names), beyond the target
    ///                  language's own keywords.
    virtual std::string member_name(std::string_view asn1_name,
                                     std::initializer_list<std::string_view> extra = {}) const = 0;

    /// @brief ASN.1 named-INTEGER-value name -> target-language constant identifier.
    virtual std::string value_name(std::string_view asn1_name) const = 0;

    /// @brief Escape an identifier that collides with a target-language
    ///        keyword or any name in `extra`.
    /// @param name  Candidate identifier (already through type_name/member_name).
    /// @param extra Additional reserved names to escape against.
    virtual std::string escape(std::string name,
                                std::initializer_list<std::string_view> extra = {}) const = 0;

    /// @brief Build the synthetic identifier for an inline member type
    ///        (e.g. an inline SEQUENCE/CHOICE/ENUMERATED member with no
    ///        named ASN.1 type of its own): parent type name + capitalized
    ///        member name.
    virtual std::string synthetic_name(const std::string& parent,
                                        const std::string& member_name) const = 0;

    /// @brief Map an INTEGER storage-class decision to this backend's native
    ///        type for an *inline member* of that INTEGER type (e.g.
    ///        `asn1::UInteger` in C++). Distinct from the top-level named-type
    ///        alias target `emit_integer_declaration` picks — see its note.
    /// @note Default throws — same rationale as emit_enumerated_declaration: a
    ///       backend without INTEGER support yet stays valid and
    ///       instantiable, just can't be used for INTEGER-typed members
    ///       until it overrides this.
    virtual std::string native_int_type(IntStorageKind kind) const {
        (void)kind;
        throw std::logic_error("native_int_type: not implemented for this backend");
    }

    /// @brief Emit the header/type-declaration half of an ENUMERATED type.
    /// @param spec Resolved, backend-agnostic decision (see EnumeratedSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — a backend that hasn't implemented this
    ///       construct yet stays a valid, instantiable Backend; it just
    ///       can't be used for ENUMERATED types until it overrides this.
    ///       Loud failure beats silently emitting the wrong language's syntax.
    virtual void emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_enumerated_declaration: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition half of an ENUMERATED type.
    /// @param spec Resolved, backend-agnostic decision (see EnumeratedSpec).
    /// @param os   Output stream to write to.
    /// @note See emit_enumerated_declaration — same default-throws rationale.
    virtual void emit_enumerated_definition(const EnumeratedSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_enumerated_definition: not implemented for this backend");
    }

    /// @brief Emit the header/type-declaration half of a named INTEGER type.
    /// @param spec Resolved, backend-agnostic decision (see IntegerSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_integer_declaration(const IntegerSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_integer_declaration: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition half of a named INTEGER type.
    /// @param spec Resolved, backend-agnostic decision (see IntegerSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_integer_definition: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a builtin-alias type
    ///        (every builtin except INTEGER/ENUMERATED — those have their
    ///        own emit_integer_*/emit_enumerated_*). Builtin-alias types
    ///        have no separate header/type-declaration half analogous to
    ///        emit_enumerated_declaration/emit_integer_declaration — the type alias itself
    ///        is a one-line `using`/equivalent, generated directly by
    ///        Generator (not yet a Backend method).
    /// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_builtin_alias_definition: not implemented for this backend");
    }

    /// @brief Emit the static setter/checker pair for a SEQUENCE/SET member's
    ///        DEFAULT value (X.680 §25.1).
    /// @param spec        Resolved, backend-agnostic decision (see DefaultValueSpec).
    /// @param type_name   Target-language storage type for the member.
    /// @param parent_name Enclosing SEQUENCE/SET type identifier.
    /// @param member_name Member identifier.
    /// @param os          Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration. The
    ///       caller (Generator::emit_default_setter) derives the returned
    ///       reference string itself (deterministic from parent_name/
    ///       member_name), so this method is void, not string-returning.
    virtual void emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                                      const std::string& parent_name, const std::string& member_name,
                                      std::ostream& os) const {
        (void)spec; (void)type_name; (void)parent_name; (void)member_name; (void)os;
        throw std::logic_error("emit_default_setter: not implemented for this backend");
    }

    /// @brief Emit the static per-member TypeDescriptor for an inline-
    ///        constrained SEQUENCE/CHOICE member.
    /// @param spec Resolved, backend-agnostic decision (see MemberTypeDescriptorSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_member_type_descriptor: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a SEQUENCE OF / SET OF type.
    /// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_seq_of_definition: not implemented for this backend");
    }

    /// @brief Emit the class/type declaration for a SEQUENCE/SET type.
    /// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_sequence_declaration: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a SEQUENCE/SET type.
    /// @param spec Resolved, backend-agnostic decision (see SequenceSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_sequence_definition(const SequenceSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_sequence_definition: not implemented for this backend");
    }

    /// @brief Emit the class/type declaration for a CHOICE type.
    /// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_choice_declaration: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a CHOICE type.
    /// @param spec Resolved, backend-agnostic decision (see ChoiceSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_choice_definition: not implemented for this backend");
    }

    /// @brief Emit the file preamble for a generated header (module comment,
    ///        include guard, standard includes).
    /// @param module_comment Pre-formatted "Module: X { oid }" text — plain
    ///        content, no comment-syntax applied; the backend wraps it in
    ///        its own comment syntax.
    /// @param os Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_declaration_preamble(const std::string& module_comment, std::ostream& os) const {
        (void)module_comment; (void)os;
        throw std::logic_error("emit_declaration_preamble: not implemented for this backend");
    }

    /// @brief Emit the file preamble for a generated implementation file.
    /// @param declaration_filename The corresponding declaration file's filename, without extension.
    /// @param os Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_definition_preamble(const std::string& declaration_filename, std::ostream& os) const {
        (void)declaration_filename; (void)os;
        throw std::logic_error("emit_definition_preamble: not implemented for this backend");
    }

    /// @brief Emit the opening of a namespace/module wrapper (X: `-fprefix`).
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_namespace_open(const std::string& name, std::ostream& os) const {
        (void)name; (void)os;
        throw std::logic_error("emit_namespace_open: not implemented for this backend");
    }

    /// @brief Emit the closing of a namespace/module wrapper.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_namespace_close(const std::string& name, std::ostream& os) const {
        (void)name; (void)os;
        throw std::logic_error("emit_namespace_close: not implemented for this backend");
    }

    /// @brief Emit the header-side type declaration for a builtin-alias type
    ///        (the `.hpp` counterpart to emit_builtin_alias_definition — see its
    ///        note on why builtin-alias has no separate hpp/cpp split for
    ///        the definition itself; this is just the forward-visible alias
    ///        + extern descriptor declaration).
    /// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_builtin_alias_declaration(const BuiltinAliasSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_builtin_alias_declaration: not implemented for this backend");
    }

    /// @brief Emit the header-side type declaration for a SEQUENCE OF / SET
    ///        OF type (the `.hpp` counterpart to emit_seq_of_definition).
    /// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_seq_of_declaration: not implemented for this backend");
    }

    /// @brief Emit a plain type-reference alias (`MyType ::= OtherType`,
    ///        X.680 §17) — the only construct with no dedicated Spec struct,
    ///        since a type alias to another named type carries no
    ///        constraint/tag decisions of its own.
    /// @param type_name   This type's own final identifier.
    /// @param target_type The referenced type's final identifier.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual void emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                         std::ostream& os) const {
        (void)type_name; (void)target_type; (void)os;
        throw std::logic_error("emit_typeref_alias_declaration: not implemented for this backend");
    }

    /// @brief Output file extension (no leading dot) for a type's
    ///        declaration half (the content `emit_declaration` produces).
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual std::string declaration_extension() const {
        throw std::logic_error("declaration_extension: not implemented for this backend");
    }

    /// @brief Output file extension (no leading dot) for a type's
    ///        definition half (the content `emit_definition` produces).
    ///
    /// gambas-asn1#262: file identity used to be hardcoded ".hpp"/".cpp" in
    /// Generator, baking C++'s header+impl split into the whole pipeline.
    /// Now Backend decides both extensions; merging is implicit rather than
    /// a separate flag Generator has to consult — TypeOutputSession::buffer()
    /// returns the *same* stream when declaration_extension() ==
    /// definition_extension(), so returning the same value as
    /// declaration_extension() (as a single-file backend would) is itself
    /// the complete "combine into one file" decision.
    /// @note Default throws — same rationale as emit_enumerated_declaration.
    virtual std::string definition_extension() const {
        throw std::logic_error("definition_extension: not implemented for this backend");
    }
};

/// @brief Per-type output session (gambas-asn1#262). Backend decides file
///        identity via declaration_extension()/definition_extension();
///        Generator drives emission by requesting named buffers and, once
///        done, collects their content via finish() to write to disk (file
///        naming and the write-if-changed diffing stay Generator's job —
///        generic build hygiene, not backend-specific).
/// @note Concrete, not virtual: the buffering mechanics (one ostringstream
///       per distinct extension, first-requested order) are identical for
///       any backend — only *which* extensions get requested varies, and
///       that's already captured by declaration_extension()/definition_extension().
class TypeOutputSession {
    std::vector<std::pair<std::string, std::unique_ptr<std::ostringstream>>> buffers_;
public:
    /// @brief Returns a persistent stream for `ext`, creating it on first
    ///        use. A second call with the same `ext` returns the same
    ///        stream — this is how a single-file backend merges
    ///        declaration and definition content into one buffer.
    std::ostream& buffer(const std::string& ext) {
        for (auto& [e, buf] : buffers_)
            if (e == ext) return *buf;
        buffers_.emplace_back(ext, std::make_unique<std::ostringstream>());
        return *buffers_.back().second;
    }

    /// @brief Finalize the session: {extension, content} pairs in
    ///        first-requested order.
    std::vector<std::pair<std::string, std::string>> finish() {
        std::vector<std::pair<std::string, std::string>> out;
        for (auto& [e, buf] : buffers_) out.emplace_back(e, buf->str());
        return out;
    }
};

} // namespace asn1::codegen
