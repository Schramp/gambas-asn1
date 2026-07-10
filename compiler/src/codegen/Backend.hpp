#pragma once
#include <string>
#include <string_view>
#include <initializer_list>
#include <ostream>
#include <stdexcept>
#include <vector>

namespace asn1::codegen {

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

/// @brief Confines identifier-escaping and naming-convention decisions that
///        are inherently target-language-specific.
///
/// `Generator` computes backend-agnostic decisions (`TagSpec`,
/// `DefaultValueSpec`, `IntStorageKind`, ...) from the resolved AST and asks
/// a `Backend` to turn ASN.1 names into valid identifiers for its target
/// language. `CppBackend` is the only implementation today; a future Rust
/// backend implements the same interface with its own keyword list and
/// naming conventions (part of gambas-asn1#214/#216).
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

    /// @brief Emit the header/type-declaration half of an ENUMERATED type.
    /// @param spec Resolved, backend-agnostic decision (see EnumeratedSpec).
    /// @param os   Output stream to write to.
    /// @note Default throws — a backend that hasn't implemented this
    ///       construct yet (gambas-asn1#225's pairwise migration) stays a
    ///       valid, instantiable Backend; it just can't be used for
    ///       ENUMERATED types until it overrides this. Loud failure beats
    ///       silently emitting the wrong language's syntax.
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
};

} // namespace asn1::codegen
