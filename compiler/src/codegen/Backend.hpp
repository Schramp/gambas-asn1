#pragma once
#include <string>
#include <string_view>
#include <initializer_list>
#include <ostream>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <optional>
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

/// @brief Backend-agnostic decision for one inline-constrained SEQUENCE/
///        CHOICE member's per-member TypeDescriptor (X.691 §26.5 character
///        string constraints; X.680 §19 INTEGER value range). Built only
///        when the member carries an inline constraint or non-default XER
///        encoding; Generator::emit_member_type_descriptor falls back to a
///        plain type-descriptor reference otherwise (no spec built). No C++/
///        Rust/etc. syntax — `constraints_init` is pre-built via the shared
///        text-formatting helpers (make_integer_pc / make_string_constraints_init)
///        since those already take fully-resolved parameters and produce
///        target-agnostic-shaped text; only the surrounding TypeDescriptor
///        aggregate and FROM-alphabet array emission are backend-specific.
struct MemberTypeDescriptorSpec {
    std::string tname;            // static variable name, e.g. "asn_TYP_Parent_member"
    std::string xer_type_name;    // e.g. "INTEGER", "OCTET_STRING"
    int         universal_tag;    // asn1::UniversalTag::* value
    std::string constraints_init; // pre-built Constraints{...} initializer text
    std::string per_handler;      // e.g. "&asn1::per_integer_handler"
    std::string ber_handler;      // e.g. "&asn1::ber_integer_handler"
    std::string cpp_type;         // TypeLifecycleOps<T> storage type
    std::string xer_tail;         // ", asn1::XerEncoding::Base64" or ""
    std::string alpha_prefix;     // empty = no FROM-alphabet arrays needed
    std::vector<uint8_t> alphabet; // paired with alpha_prefix
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
    int         flags;
    int         range_bits;
    int64_t     size_lower, size_upper;
    bool        has_declared_elem_name; // X.693 §12: element carries a declared identifier
    std::string elem_xer_name;          // meaningful only when has_declared_elem_name
    bool        is_set_of;              // true -> natural tag is SET, else SEQUENCE
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
    ///        alias target `emit_integer_hpp` picks — see its note.
    /// @note Default throws — same rationale as emit_enumerated_hpp: a
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
    virtual void emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_enumerated_hpp: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition half of an ENUMERATED type.
    /// @param spec Resolved, backend-agnostic decision (see EnumeratedSpec).
    /// @param os   Output stream to write to.
    /// @note See emit_enumerated_hpp — same default-throws rationale.
    virtual void emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_enumerated_cpp: not implemented for this backend");
    }

    /// @brief Emit the header/type-declaration half of a named INTEGER type.
    /// @param spec Resolved, backend-agnostic decision (see IntegerSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_hpp.
    virtual void emit_integer_hpp(const IntegerSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_integer_hpp: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition half of a named INTEGER type.
    /// @param spec Resolved, backend-agnostic decision (see IntegerSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_hpp.
    virtual void emit_integer_cpp(const IntegerSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_integer_cpp: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a builtin-alias type
    ///        (every builtin except INTEGER/ENUMERATED — those have their
    ///        own emit_integer_*/emit_enumerated_*). Builtin-alias types
    ///        have no separate header/type-declaration half analogous to
    ///        emit_enumerated_hpp/emit_integer_hpp — the type alias itself
    ///        is a one-line `using`/equivalent, generated directly by
    ///        Generator (not yet a Backend method).
    /// @param spec Resolved, backend-agnostic decision (see BuiltinAliasSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_hpp.
    virtual void emit_builtin_alias_cpp(const BuiltinAliasSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_builtin_alias_cpp: not implemented for this backend");
    }

    /// @brief Emit the static setter/checker pair for a SEQUENCE/SET member's
    ///        DEFAULT value (X.680 §25.1).
    /// @param spec        Resolved, backend-agnostic decision (see DefaultValueSpec).
    /// @param type_name   Target-language storage type for the member.
    /// @param parent_name Enclosing SEQUENCE/SET type identifier.
    /// @param member_name Member identifier.
    /// @param os          Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_hpp. The
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
    /// @note Default throws — same rationale as emit_enumerated_hpp.
    virtual void emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_member_type_descriptor: not implemented for this backend");
    }

    /// @brief Emit the implementation/definition for a SEQUENCE OF / SET OF type.
    /// @param spec Resolved, backend-agnostic decision (see SeqOfSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — same rationale as emit_enumerated_hpp.
    virtual void emit_seq_of_cpp(const SeqOfSpec& spec, std::ostream& os) const {
        (void)spec; (void)os;
        throw std::logic_error("emit_seq_of_cpp: not implemented for this backend");
    }
};

} // namespace asn1::codegen
