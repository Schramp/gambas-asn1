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
///        Pure wire-tag-*shape* data, deliberately minimal: reused
///        identically for a type's own top-level tag (TaggedTypeSpec,
///        below) and as the base of a member's resolved tag
///        (MemberTagSpec, below it) — a type never has an "is this an
///        override" concept (there's no member involved), so that fact
///        lives only in MemberTagSpec, not here.
/// @note Lives here, not Generator.hpp, for the same reason as
///       IntStorageKind: BuiltinAliasSpec (below) needs it, and Backend.hpp
///       can't include Generator.hpp without a cycle.
struct TypeTagSpec {
    ast::TagClass cls;          ///< Tag class (Universal/Application/Context/Private).
    int64_t       number;       ///< Tag number within the class.
    bool          constructed;  ///< True for constructed encoding form.
};

/// @brief A member/alternative's resolved wire tag (gambas-asn1#347) —
///        TypeTagSpec's shape plus the one extra fact only a member (not a
///        standalone type) can have: whether this tag came from the
///        member's own override (`[n]`/AUTOMATIC) or is simply the type's
///        natural tag passed through unchanged. Inheriting TypeTagSpec
///        (rather than a sibling `bool tag_is_override` field next to a
///        plain `std::optional<TypeTagSpec>`) makes "override without an
///        actual tag" unrepresentable — the flag only exists bundled with
///        a real tag.
/// @note resolved_tag (TaggedMemberSpec, below) is always populated except
///       for the one case a member's type genuinely has no tag at all (an
///       untagged CHOICE — X.680 §28, no universal tag) — see
///       Generator::TagResult's doc comment for how it's computed.
struct MemberTagSpec : TypeTagSpec {
    bool tag_is_override;  ///< True: member's own `[n]`/AUTOMATIC tag. False: type's natural tag, passed through.
};

/// @brief Backend-agnostic tag-bearing field shared by every construct that
///        can carry its own top-level [n] IMPLICIT/EXPLICIT tag (X.690 §8.14)
///        on its *standalone* TypeDescriptor — same base-class consolidation
///        gambas-asn1#338 already did for member-level tags
///        (TaggedMemberSpec), applied here at the type level after #342
///        found the field independently duplicated across EnumeratedSpec/
///        IntegerSpec/SequenceSpec/SeqOfSpec/BuiltinAliasSpec (raised on
///        #342's own review).
/// @note nullopt means the type's natural tag applies (a backend's own
///       per-kind universal-tag constant); set means this type assignment
///       carries its own declared tag, overriding the natural one on the
///       wire for a *standalone* encode/decode of this type (as opposed to
///       TaggedMemberSpec::resolved_tag, which covers the same override but
///       for a member/alternative referencing this type from inside another
///       construct — the two are independent: a member can override a
///       type's tag without that type's own standalone descriptor changing,
///       and vice versa).
struct TaggedTypeSpec {
    std::optional<TypeTagSpec> tag;
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
struct EnumeratedSpec : TaggedTypeSpec {
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
struct IntegerSpec : TaggedTypeSpec {
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
struct BuiltinAliasSpec : TaggedTypeSpec {
    std::string            type_name;
    std::string            xer_name;
    ast::BuiltinType        builtin_type;
    // tag (inherited): natural tag (X.690 §8.1); always present in practice —
    // builtin-alias types are never CHOICE, the only case natural-tag
    // resolution returns nullopt for.
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
struct SeqOfSpec : TaggedTypeSpec {
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

/// @brief Backend-agnostic tag-bearing fields shared by every construct that
///        can carry an ASN.1 tag on its own TLV (X.690 §8.1) — a SEQUENCE/SET
///        member, a CHOICE alternative, and (should it ever need one) a
///        SEQUENCE OF/SET OF element. gambas-asn1#338: factored out of
///        SequenceMemberSpec after #332 added `resolved_tag` there but a
///        sibling struct (`ChoiceAlternativeSpec`) kept an independent,
///        stale-prone copy of `eff_tag`/`is_explicit`/`mbuiltin` with no
///        `resolved_tag` at all (gambas-asn1#336's bug: CHOICE alternatives
///        never got their real IMPLICIT tag override, because the field
///        allowing one simply didn't exist there) — the exact failure mode a
///        shared base makes structurally harder to reintroduce (adding a
///        field here updates every derived construct, not just whichever
///        one a given PR happened to touch).
/// @note Pure field consolidation, no behavior change: every derived struct
///       still owns its own construct-specific fields (`asn1_name`, `tdref`,
///       etc. are *not* pulled up here even though both current derived
///       structs happen to have identically-named/typed copies — see this
///       issue's own filing for why that's left for a possible future pass,
///       not decided here).
struct TaggedMemberSpec {
    // gambas-asn1#347: always populated except when this member's type has
    // no tag at all (an untagged CHOICE — X.680 §28). No pre-formatted
    // string lives here anymore (the old eff_tag, C++-syntax-only, is
    // gone) — each backend calls its own format_tag_literal/
    // format_no_tag_literal on this structured data at the point of use.
    // MemberTagSpec::tag_is_override (not resolved_tag's mere presence)
    // is what a backend checks to decide whether the wire tag differs from
    // the member's natural one — used by RustBackend to pick
    // MemberAccess::TaggedScalar over Scalar.
    std::optional<MemberTagSpec> resolved_tag;
    bool        is_explicit = false;
    // Backend-agnostic builtin-type discriminant, set only when the member
    // is a direct (non-TypeRef, non-SEQUENCE/CHOICE) builtin type. `mtype`
    // (declared per-derived-struct, not here — its native storage type
    // string means different things per construct) alone can't drive
    // correct per-member BER tag selection for a second backend: it
    // deliberately collapses distinct ASN.1 types with the same native
    // representation (e.g. RustBackend::native_builtin_type maps
    // OCTET STRING/BIT STRING/OBJECT IDENTIFIER/Any all to "Vec<u8>", and
    // all 12 string kinds plus UtcTime/GeneralizedTime to "String" — see
    // that function's doc). `mbuiltin` gives a backend the real
    // discriminant to dispatch on; unset (nullopt) for TypeRef/SEQUENCE/
    // CHOICE/SEQUENCE OF/ENUMERATED members/alternatives.
    std::optional<ast::BuiltinType> mbuiltin;
    // gambas-asn1#350: only meaningful when mbuiltin == ast::BuiltinType::
    // Integer (default S64 otherwise, harmlessly unused) — mirrors
    // IntegerSpec::storage_kind, one level down. Before this field existed,
    // the only way to ask "is this member's storage the one Asn1Value
    // supports" was `mtype == "i64"`, a string literal coincidentally
    // matching what `native_int_type(IntStorageKind::S64)` returns rather
    // than a real reference to it — fragile (a silent, uncaught mismatch if
    // that mapping ever changed), not a bug today. Real enum comparison
    // instead: `storage_kind == IntStorageKind::S64`.
    IntStorageKind storage_kind = IntStorageKind::S64;
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
struct SequenceMemberSpec : TaggedMemberSpec {
    std::string asn1_name;      // raw ASN.1 name — MemberDescriptor "name" field
    std::string mtype;          // C++ storage type
    std::string mname;          // member identifier
    // gambas-asn1#303: true when this member's class type (direct
    // SEQUENCE/CHOICE/SET, or a TypeRef resolving to one) is reachable back
    // to the *enclosing* type by following further class-typed member
    // chains — i.e. this member sits on a real ASN.1 type-reference cycle
    // (Generator::member_type_in_cycle). RustBackend uses this to decide
    // `Box<T>` vs plain `T` inside the field's `Option<...>` (a
    // self-referential/mutually-recursive struct has no finite size in Rust
    // without heap indirection somewhere in the cycle — X.680 places no
    // restriction against a type referencing itself, so real schemas do
    // this; found on the ETSI LI PS-PDU schema, #299).
    //
    // Deliberately NOT "is this member class-typed" alone: C++ boxes every
    // OPTIONAL member unconditionally via `std::unique_ptr<T>`
    // (CppBackend.cpp: "matches asn1c semantics", a lifecycle/forward-decl
    // convention unrelated to recursion), but that's C++'s own reason, not
    // a recursion requirement — Rust's `Option<T>` needs no heap indirection
    // at all for the overwhelming majority of optional members (1 real
    // cycle found across ~1044 types on the real schema), so boxing
    // everything to mirror C++ would be needless indirection with no
    // upside. Only cycle-participating members get boxed.
    bool        member_type_in_cycle = false;
    bool        is_class_type = false;
    // True when `is_class_type` and the referenced/inline class type itself
    // qualifies for a real wire (BER) encoding — every one of ITS OWN
    // members recursively resolves to either a covered builtin/SEQUENCE-OF
    // element or another wire-covered class type, and this member doesn't
    // sit on a reference cycle (`member_type_in_cycle`; cyclic composite
    // members are conservatively excluded rather than reasoning about
    // `Box<T>` indirection through a trait impl). Computed once by
    // Generator::rust_wire_eligible (memoized per referenced TypeDef) and
    // consumed by RustBackend to decide whether a SEQUENCE/CHOICE member
    // whose own type is itself SEQUENCE/SET/CHOICE gets a real
    // MemberDescriptor row instead of falling out of table coverage
    // entirely. `false` (the default) is always safe — it just means this
    // member doesn't get composite coverage, same "known gap, not a
    // regression" scope every other coverage field in this struct uses.
    bool        class_type_wire_covered = false;
    // gambas-asn1#331: SEQUENCE OF member support. Set only for a member
    // whose body is ast::SequenceOfType (never ast::SetOfType — SET OF is a
    // separate, not-yet-covered follow-up) with a *direct* builtin-type
    // element (same "direct only, not TypeRef-resolved" precedent
    // `mbuiltin` above already establishes) — `elem_builtin`/`elem_mtype`
    // are the element's own discriminant/native-storage-type, the same
    // pairing `mbuiltin`/`mtype` are for a plain scalar member, just one
    // level down. A backend without SEQUENCE OF table support can ignore
    // all three fields; `is_seq_of` false leaves them meaningless.
    bool        is_seq_of = false;
    std::optional<ast::BuiltinType> elem_builtin;
    std::string elem_mtype;      // element's own native storage type (backend-specific)
    bool        optional = false;
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
struct SequenceSpec : TaggedTypeSpec {
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
struct ChoiceAlternativeSpec : TaggedMemberSpec {
    std::string mtype;
    std::string accessor_name;
    std::string pr_name;

    std::string asn1_name;
    std::string tdref;
    // gambas-asn1#336: resolved_tag (inherited from TaggedMemberSpec) is now
    // populated by Generator::emit_choice_definition, same as
    // SequenceMemberSpec::resolved_tag — nullopt means the alternative's own
    // natural tag applies; set means an explicit/AUTOMATIC-assigned tag
    // overrides it (X.690 §8.14). Consumed by RustBackend's CHOICE analogue
    // of MemberAccess::TaggedScalar.
    // Same meaning/computation as SequenceMemberSpec's identically-named
    // fields — an alternative whose own type is itself SEQUENCE/CHOICE/SET.
    bool        is_class_type = false;
    bool        member_type_in_cycle = false;
    bool        class_type_wire_covered = false;
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
/// @brief Forward declaration — full definition below, after Backend. Only a
///        reference to it appears in Backend's own method signatures, so a
///        forward declaration is enough here; the .cpp files that call
///        `session.buffer(...)` see the full definition via this same header.
class TypeOutputSession;

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

    /// @brief Format a resolved `TagSpec` (class/number/constructed — see
    ///        struct doc, already backend-agnostic data) as this backend's
    ///        tag-literal syntax, e.g. `"asn1::Tag{...}"` in C++.
    /// @param tag_spec Resolved tag decision (`Generator::tag_spec_for`/
    ///        `natural_tag_spec_for`).
    /// @note gambas-asn1#290: previously a plain namespace-level free
    ///       function (`format_tag_literal` in `CppBackend.cpp`) called
    ///       directly by `Generator::tag_literal()`/`natural_tag_for()`
    ///       regardless of the active backend — always produced C++ syntax,
    ///       leaking into `SequenceMemberSpec::eff_tag`/
    ///       `ChoiceAlternativeSpec::eff_tag` even under `--target=rust`.
    ///       Found on #282 review; not yet load-bearing there (RustBackend
    ///       computes its own tags via `mbuiltin`), but #284/#285's
    ///       table-driven CHOICE needs real EXPLICIT/IMPLICIT/auto-tag
    ///       literals for tagged alternatives, same as this field already
    ///       provides for C++.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual std::string format_tag_literal(const TypeTagSpec& tag_spec) const {
        (void)tag_spec;
        throw std::logic_error("format_tag_literal: not implemented for this backend");
    }

    /// @brief Format the placeholder used when a member's own natural tag
    ///        is absent entirely (an untagged CHOICE-typed member — X.680
    ///        §28, CHOICE has no universal tag of its own; `natural_tag_for`/
    ///        `natural_tag_spec_for` return an absent/empty result only for
    ///        this one case). Backend-agnostic counterpart to the C++-only
    ///        `"asn1::Tag{}"` string `Generator::compute_member_tag` used to
    ///        hardcode directly (gambas-asn1#347) — this method exists so
    ///        that hardcoding lives in each backend's own file instead of in
    ///        shared `Generator.cpp`.
    /// @note `eff_tag` is populated for every member unconditionally,
    ///       regardless of whether a particular backend's own coverage
    ///       gating (e.g. RustBackend's `all_covered`) would end up using
    ///       that member's row at all — so this must return a real,
    ///       syntactically valid placeholder, not throw, even on a backend
    ///       where the untagged-CHOICE-member case is otherwise unreachable
    ///       in covered output today.
    virtual std::string format_no_tag_literal() const {
        throw std::logic_error("format_no_tag_literal: not implemented for this backend");
    }

    /// @brief Map a plain builtin type (never INTEGER or ENUMERATED — those
    ///        have their own dispatch, `native_int_type` and a
    ///        backend-computed synthetic name respectively) to this
    ///        backend's native storage type for a *member/alternative/
    ///        element* of that type (e.g. `asn1::Boolean` in C++, `bool` in
    ///        Rust).
    /// @param bt Built-in type tag.
    /// @note gambas-asn1#270: previously a hardcoded switch inside
    ///       Generator::cpp_type_for, unconditionally returning C++ runtime
    ///       wrapper type names — broke RustBackend on any SEQUENCE/CHOICE/
    ///       SEQUENCE OF containing a plain builtin (BOOLEAN, OCTET STRING,
    ///       etc.) member/alternative/element.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual std::string native_builtin_type(ast::BuiltinType bt) const {
        (void)bt;
        throw std::logic_error("native_builtin_type: not implemented for this backend");
    }

    /// @brief Wrap an already-resolved element type in this backend's
    ///        native collection type, for a SEQUENCE OF / SET OF that
    ///        appears as a *member/alternative* type (not a top-level named
    ///        type — those go through emit_seq_of's own SeqOfSpec::elem_type
    ///        instead). E.g. `asn1::VectorSeqOf<T>` in C++, `Vec<T>` in Rust.
    /// @param elem_type Already-resolved native type of the collection's element.
    /// @note gambas-asn1#270: previously a hardcoded `"asn1::VectorSeqOf<{}>"`
    ///       format string inside Generator::cpp_type_for.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual std::string wrap_collection_type(const std::string& elem_type) const {
        (void)elem_type;
        throw std::logic_error("wrap_collection_type: not implemented for this backend");
    }

    /// @brief Emit both halves of an ENUMERATED type: declaration then definition.
    /// @param spec    Resolved, backend-agnostic decision (see EnumeratedSpec).
    /// @param session Per-type output session (gambas-asn1#262) — the override
    ///                pulls its own declaration/definition streams via
    ///                `session.buffer(declaration_extension())` /
    ///                `session.buffer(definition_extension())`.
    /// @note gambas-asn1#265: declaration/definition used to be two separate
    ///       virtuals, but every override called them back-to-back with the
    ///       same spec — combined into one call. Takes the session (not two
    ///       raw streams) because the two streams are already grouped there;
    ///       a single-file backend (declaration_extension() ==
    ///       definition_extension(), e.g. Rust) then makes exactly one
    ///       `session.buffer()` call instead of acquiring the same stream
    ///       under two different parameter names.
    /// @note Default throws — a backend that hasn't implemented this
    ///       construct yet stays a valid, instantiable Backend; it just
    ///       can't be used for ENUMERATED types until it overrides this.
    ///       Loud failure beats silently emitting the wrong language's syntax.
    virtual void emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_enumerated: not implemented for this backend");
    }

    /// @brief Emit both halves of a named INTEGER type: declaration then definition.
    /// @param spec    Resolved, backend-agnostic decision (see IntegerSpec).
    /// @param session Per-type output session — see emit_enumerated's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_integer: not implemented for this backend");
    }

    /// @brief Emit both halves of a builtin-alias type (every builtin except
    ///        INTEGER/ENUMERATED — those have their own emit_integer/emit_enumerated).
    /// @param spec    Resolved, backend-agnostic decision (see BuiltinAliasSpec).
    /// @param session Per-type output session — see emit_enumerated's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_builtin_alias: not implemented for this backend");
    }

    /// @brief Emit the static setter/checker pair for a SEQUENCE/SET member's
    ///        DEFAULT value (X.680 §25.1).
    /// @param spec        Resolved, backend-agnostic decision (see DefaultValueSpec).
    /// @param type_name   Target-language storage type for the member.
    /// @param parent_name Enclosing SEQUENCE/SET type identifier.
    /// @param member_name Member identifier.
    /// @param session     Per-type output session — always writes into
    ///                    `session.buffer(definition_extension())`; a
    ///                    DEFAULT setter is definition-only content, so
    ///                    there's no declaration-side counterpart to pick
    ///                    between.
    /// @note Default throws — same rationale as emit_enumerated. The
    ///       caller (Generator::emit_default_setter) derives the returned
    ///       reference string itself (deterministic from parent_name/
    ///       member_name), so this method is void, not string-returning.
    virtual void emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                                      const std::string& parent_name, const std::string& member_name,
                                      TypeOutputSession& session) const {
        (void)spec; (void)type_name; (void)parent_name; (void)member_name; (void)session;
        throw std::logic_error("emit_default_setter: not implemented for this backend");
    }

    /// @brief Emit the static per-member TypeDescriptor for an inline-
    ///        constrained SEQUENCE/CHOICE member.
    /// @param spec    Resolved, backend-agnostic decision (see MemberTypeDescriptorSpec).
    /// @param session Per-type output session — always writes into
    ///                `session.buffer(definition_extension())`, same
    ///                rationale as emit_default_setter.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_member_type_descriptor: not implemented for this backend");
    }

    /// @brief Emit both halves of a SEQUENCE OF / SET OF type: declaration then definition.
    /// @param spec    Resolved, backend-agnostic decision (see SeqOfSpec).
    /// @param session Per-type output session — see emit_enumerated's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_seq_of(const SeqOfSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_seq_of: not implemented for this backend");
    }

    /// @brief Emit both halves of a SEQUENCE/SET type: declaration then definition.
    /// @param spec    Resolved, backend-agnostic decision (see SequenceSpec).
    /// @param session Per-type output session — see emit_enumerated's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_sequence(const SequenceSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_sequence: not implemented for this backend");
    }

    /// @brief Emit both halves of a CHOICE type: declaration then definition.
    /// @param spec    Resolved, backend-agnostic decision (see ChoiceSpec).
    /// @param session Per-type output session — see emit_enumerated's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const {
        (void)spec; (void)session;
        throw std::logic_error("emit_choice: not implemented for this backend");
    }

    /// @brief Is `m` (ignoring `is_class_type`/`class_type_wire_covered`)
    ///        coverable by this backend's wire (BER) encoding — a plain
    ///        builtin-scalar or SEQUENCE-OF-of-builtin member? Used by
    ///        Generator::rust_wire_eligible to decide whether a type
    ///        qualifies as a nested composite member elsewhere, and by the
    ///        backend's own member-table emission (single source of truth
    ///        for both). C++ covers every member unconditionally (this
    ///        predicate is Rust-specific — CppBackend's own emission never
    ///        consults it), so the default is `true`.
    virtual bool sequence_member_ber_covered(const SequenceMemberSpec& m) const {
        (void)m;
        return true;
    }

    /// @brief CHOICE alternative analogue of sequence_member_ber_covered.
    virtual bool choice_alternative_ber_covered(const ChoiceAlternativeSpec& a) const {
        (void)a;
        return true;
    }

    /// @brief Emit the file preamble for a generated header (module comment,
    ///        include guard, standard includes).
    /// @param module_comment Pre-formatted "Module: X { oid }" text — plain
    ///        content, no comment-syntax applied; the backend wraps it in
    ///        its own comment syntax.
    /// @param session Per-type output session — writes into
    ///                `session.buffer(declaration_extension())`.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const {
        (void)module_comment; (void)session;
        throw std::logic_error("emit_declaration_preamble: not implemented for this backend");
    }

    /// @brief Emit the file preamble for a generated implementation file.
    /// @param declaration_filename The corresponding declaration file's filename, without extension.
    /// @param session Per-type output session — writes into
    ///                `session.buffer(definition_extension())`.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const {
        (void)declaration_filename; (void)session;
        throw std::logic_error("emit_definition_preamble: not implemented for this backend");
    }

    /// @brief Emit the opening of a namespace/module wrapper (X: `-fprefix`)
    ///        into both the declaration and definition buffers.
    /// @param session Per-type output session — writes into
    ///                `session.buffer(declaration_extension())` and, when
    ///                `definition_extension()` names a distinct buffer, into
    ///                that one too (a single-file backend, where they're the
    ///                same buffer, only wraps once).
    /// @note Unconditionally touches both buffers even for a construct with
    ///       no definition half (a plain TypeRef alias) — the two-sided
    ///       wrap is simpler than threading a "does this side exist" flag
    ///       through every backend. Generator::emit_type_body resets the
    ///       definition buffer back to empty afterward when there's no
    ///       definition, so this doesn't produce a stray near-empty file.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_namespace_open(const std::string& name, TypeOutputSession& session) const {
        (void)name; (void)session;
        throw std::logic_error("emit_namespace_open: not implemented for this backend");
    }

    /// @brief Emit the closing of a namespace/module wrapper, mirroring emit_namespace_open.
    /// @param session Per-type output session — see emit_namespace_open's note.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_namespace_close(const std::string& name, TypeOutputSession& session) const {
        (void)name; (void)session;
        throw std::logic_error("emit_namespace_close: not implemented for this backend");
    }

    /// @brief Emit a plain type-reference alias (`MyType ::= OtherType`,
    ///        X.680 §17) — the only construct with no dedicated Spec struct,
    ///        since a type alias to another named type carries no
    ///        constraint/tag decisions of its own.
    /// @param type_name   This type's own final identifier.
    /// @param target_type The referenced type's final identifier.
    /// @param session     Per-type output session — writes into
    ///                    `session.buffer(declaration_extension())` (a
    ///                    TypeRef alias has no definition half).
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                         TypeOutputSession& session) const {
        (void)type_name; (void)target_type; (void)session;
        throw std::logic_error("emit_typeref_alias_declaration: not implemented for this backend");
    }

    /// @brief Emit a dependency declaration for a reference to another
    ///        generated type from the current file (X.680 §17-ish notion of
    ///        "this file needs that other type to be visible").
    /// @param type_name Final identifier of the referenced type, as used
    ///                  elsewhere in this file's generated code.
    /// @param filename  The referenced type's on-disk filename, no
    ///                  extension (Generator::filename_for's result) —
    ///                  usually equals type_name; differs only when
    ///                  collision-prefixed with a module name.
    /// @param session   Per-call output session — always writes into
    ///                  `session.buffer(declaration_extension())`. Callers
    ///                  needing this reference to land somewhere other than
    ///                  the real per-type declaration buffer (a `.cpp`-side
    ///                  include, a pre-namespace redirect, a deferred
    ///                  post-namespace include, ...) pass a throwaway
    ///                  session with that key `seed()`-ed to the real
    ///                  target stream instead — Backend only owns the
    ///                  *text*, never touches a raw stream directly, and
    ///                  never needs to know which real file it ends up in.
    /// @note gambas-asn1#266: previously hardcoded `#include "X.hpp"\n` at
    ///       9 call sites in Generator.cpp regardless of backend — broke
    ///       RustBackend on any schema with cross-type references.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_type_reference(const std::string& type_name,
                                      const std::string& filename, TypeOutputSession& session) const {
        (void)type_name; (void)filename; (void)session;
        throw std::logic_error("emit_type_reference: not implemented for this backend");
    }

    /// @brief Whether `Generator::write_type_reference` should skip a call
    ///        to `emit_type_reference` for a type this file already
    ///        referenced once (gambas-asn1#300).
    /// @note Default `true`. CppBackend's `#include` is idempotent, so
    ///       today's duplicate `#include "X.hpp"` lines (one per member/
    ///       alternative referencing the same type — a real, pre-existing
    ///       pattern in generated output, confirmed on the real ETSI LI
    ///       PS-PDU schema) were harmless either way; deduping them too is a
    ///       strict improvement (fewer, cleaner lines, same semantics) —
    ///       reviewed and confirmed on #300/PR #308 rather than opting only
    ///       RustBackend in and leaving CppBackend's redundant duplicates as
    ///       a "don't touch it" byte-identical exception. RustBackend needs
    ///       this unconditionally: `use crate::X::X;` has no #include-guard
    ///       equivalent — a duplicate is a hard compile error (E0252), the
    ///       single largest error category found running the ETSI schema
    ///       through `--target=rust` (#299).
    virtual bool dedupe_type_references() const { return true; }

    /// @brief Whether a named SEQUENCE OF/SET OF member needs a reference to
    ///        its own synthetic SeqOf wrapper type (e.g. `X` in
    ///        `pub type X = Vec<Elem>;`/`using X = std::vector<Elem>;`), on
    ///        top of the deeper element-type reference gambas-asn1#301
    ///        already adds.
    /// @note Default `true`. CppBackend needs it unconditionally:
    ///       `Generator::type_descriptor_ref_for`'s SEQUENCE-OF branch
    ///       (Generator.cpp) always points a member's `tdref` at
    ///       `&asn_DEF_<wrapper>` — the wrapper's *descriptor*, declared in
    ///       its own header — regardless of whether the field's C++ type
    ///       text itself names the wrapper or inlines
    ///       `std::vector<Elem>` directly. RustBackend doesn't have this:
    ///       confirmed by grep, nothing in RustBackend.cpp ever reads
    ///       `SequenceMemberSpec::tdref`/`ChoiceAlternativeSpec::tdref` (no
    ///       codec table wiring yet) — so for Rust the wrapper reference is
    ///       always genuinely unused, in both the plain-TypeRef-element case
    ///       gambas-asn1#301 originally covered and the anonymous-inline-
    ///       element case (`cpp_type_for`'s SEQUENCE OF branch never emits
    ///       the bare wrapper name as a field type either way — only the
    ///       element type directly, or the doubly-suffixed "Anon" type).
    ///       80 `unused_imports` warnings on the real ETSI LI PS-PDU schema
    ///       (gambas-asn1#312).
    /// @note A plain bool, not a new emit_*() virtual mirroring
    ///       emit_type_reference — this is one of potentially several such
    ///       per-backend "does this schema-derived reference even apply to
    ///       you" questions as more backends (Java, Python, ...) join,
    ///       and Generator's *writing* path (write_type_reference: dedup via
    ///       emitted_type_refs_, filename_for, session-seeding) must not
    ///       fork per question — one write path, N boolean answers, not N
    ///       parallel write_*/emit_* method pairs to keep in sync forever.
    /// @note Provisional, not a permanent "Rust never needs this" claim
    ///       (raised on #312's own review) — "unused today" tracks Rust
    ///       having no codec dispatch tables wired at all yet, not a
    ///       structural fact about the wrapper type. The moment Rust grows
    ///       its own equivalent of `tdref`/`asn_DEF_<wrapper>` (a per-member
    ///       BER/XER table entry needing the wrapper's descriptor, the same
    ///       reason CppBackend needs it), `RustBackend::needs_seqof_wrapper_
    ///       reference()` should very possibly flip back to `true` — revisit
    ///       this override whenever that table wiring lands, don't assume
    ///       it's settled.
    virtual bool needs_seqof_wrapper_reference() const { return true; }

    /// @brief Emit a forward declaration for a type this file only needs as
    ///        an incomplete type (e.g. an optional member stored behind a
    ///        pointer, to break a circular #include). Backends with no
    ///        forward-declaration concept — a type is visible regardless of
    ///        declaration order once imported — write nothing. Always the
    ///        declaration side (a forward declaration only ever appears in
    ///        header-equivalent content).
    /// @param type_name Final identifier of the type being forward-declared.
    /// @param session   Per-call output session — writes into
    ///                  `session.buffer(declaration_extension())`.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_forward_declaration(const std::string& type_name, TypeOutputSession& session) const {
        (void)type_name; (void)session;
        throw std::logic_error("emit_forward_declaration: not implemented for this backend");
    }

    /// @brief Emit the special member functions (default ctor, dtor, copy,
    ///        move) a SEQUENCE/SET needs when it has optional members whose
    ///        backend-specific storage requires them defined where the
    ///        storage type is complete (C++: `unique_ptr<T>`'s deep-copy
    ///        semantics need the special members out-of-line, in the `.cpp`,
    ///        not defaulted in the class body). Backends whose optional
    ///        storage doesn't need this (Rust: `Option<T>` needs nothing
    ///        special) write nothing.
    /// @param type_name Final identifier of the SEQUENCE/SET type.
    /// @param session   Per-type output session — writes into
    ///                  `session.buffer(definition_extension())`.
    /// @note gambas-asn1#268: previously hardcoded directly in
    ///       Generator::emit_sequence_definition regardless of backend —
    ///       broke RustBackend on any SEQUENCE/SET with an optional member.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_special_members(const std::string& type_name, TypeOutputSession& session) const {
        (void)type_name; (void)session;
        throw std::logic_error("emit_special_members: not implemented for this backend");
    }

    /// @brief Emit the optional-member storage-ops helper for one optional
    ///        member (C++: the `UniquePtrOps<T>` `using`-alias that
    ///        `emit_default_setter`'s generated functions reference by
    ///        name). Backends whose optional storage needs no such helper
    ///        type write nothing.
    /// @param type_name   Final identifier of the enclosing SEQUENCE/SET type.
    /// @param member_name Sanitised member identifier.
    /// @param member_type Member's storage type.
    /// @param session     Per-type output session — writes into
    ///                    `session.buffer(definition_extension())`.
    /// @note gambas-asn1#268: same root cause as emit_special_members —
    ///       previously hardcoded unconditionally in Generator.cpp.
    /// @note Default throws — same rationale as emit_enumerated.
    virtual void emit_optional_member_ops(const std::string& type_name, const std::string& member_name,
                                           const std::string& member_type, TypeOutputSession& session) const {
        (void)type_name; (void)member_name; (void)member_type; (void)session;
        throw std::logic_error("emit_optional_member_ops: not implemented for this backend");
    }

    /// @brief Output file extension (no leading dot) for a type's
    ///        declaration half (the content `emit_declaration` produces).
    /// @note Default throws — same rationale as emit_enumerated.
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

    /// @brief Called once, after every type has been generated, to do any
    ///        whole-output-directory bookkeeping the backend needs (e.g. a
    ///        crate root). Default is a no-op — most backends (CppBackend:
    ///        each `.hpp`/`.cpp` pair is independently `#include`-able,
    ///        nothing to tie together) don't need this.
    /// @param out_dir Directory every generated file was written into.
    virtual void finalize_output(const std::string& out_dir) const {
        (void)out_dir;
    }

protected:
    /// @brief Write `text` into both the declaration and definition
    ///        buffers — shared by every backend's emit_namespace_open/close,
    ///        which otherwise duplicate this exact dedup-when-merged logic.
    ///        Defined out-of-line below, after TypeOutputSession's full
    ///        definition (only forward-declared at this point in the file).
    /// @param text Already-formatted output for this backend's syntax
    ///             (e.g. `"namespace X {\n\n"` for C++, `"pub mod X {\n\n"`
    ///             for Rust) — same string goes to both buffers.
    void write_to_both(TypeOutputSession& session, const std::string& text) const;
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
    std::vector<std::pair<std::string, std::ostream*>>                     external_;
    std::vector<std::pair<std::string, std::unique_ptr<std::ostringstream>>> buffers_;
public:
    /// @brief Pre-bind `ext` to an already-existing stream instead of an
    ///        internally-owned ostringstream. Used by Generator when the
    ///        real per-construct destination isn't the session's own file
    ///        buffer — e.g. under `-fprefix` namespace wrapping, where
    ///        construct dispatch must write into a temporary body buffer
    ///        that gets wrapped in `namespace X { ... }` afterward, not
    ///        directly into the file. A second seed() with the same `ext`
    ///        replaces the binding (last write wins).
    void seed(const std::string& ext, std::ostream& target) {
        for (auto& [e, s] : external_) if (e == ext) { s = &target; return; }
        external_.emplace_back(ext, &target);
    }

    /// @brief Returns a persistent stream for `ext`, creating it on first
    ///        use. A second call with the same `ext` returns the same
    ///        stream — this is how a single-file backend merges
    ///        declaration and definition content into one buffer. An
    ///        ext seeded via seed() takes priority over the internally-owned
    ///        buffer and is never collected by finish().
    std::ostream& buffer(const std::string& ext) {
        for (auto& [e, s] : external_)
            if (e == ext) return *s;
        for (auto& [e, buf] : buffers_)
            if (e == ext) return *buf;
        buffers_.emplace_back(ext, std::make_unique<std::ostringstream>());
        return *buffers_.back().second;
    }

    /// @brief Finalize the session: {extension, content} pairs in
    ///        first-requested order. Only internally-owned buffers are
    ///        collected — seeded (externally-owned) streams already write
    ///        straight to their real destination, so there's nothing to
    ///        hand back for them.
    std::vector<std::pair<std::string, std::string>> finish() {
        std::vector<std::pair<std::string, std::string>> out;
        for (auto& [e, buf] : buffers_) out.emplace_back(e, buf->str());
        return out;
    }
};

inline void Backend::write_to_both(TypeOutputSession& session, const std::string& text) const {
    session.buffer(declaration_extension()) << text;
    if (definition_extension() != declaration_extension())
        session.buffer(definition_extension()) << text;
}

} // namespace asn1::codegen
