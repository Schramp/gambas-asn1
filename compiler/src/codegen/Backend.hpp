#pragma once
#include <string>
#include <string_view>
#include <initializer_list>

namespace asn1::codegen {

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
};

} // namespace asn1::codegen
