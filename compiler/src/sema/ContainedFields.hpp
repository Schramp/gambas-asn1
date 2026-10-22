#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"
#include "Contents.hpp"

namespace asn1::sema {

class Resolver;

/// Whether the inner value is decoded during the outer decode.
enum class ContainedDecode { Eager, Off };
/// What a failed inner decode does to the outer decode.
enum class ContainedOnError { KeepRaw, Fail };
/// XER/JER form of a contained value: the hex string, the inner value in
/// place of the hex (X.680 §22.4, X.697 §25.4), or the inner value plus
/// the raw hex (an extension, not standard-conformant).
enum class ContainedText { Hex, Inline, InlineRaw };

/// @brief Sibling condition for decoding a contained field: decode only
///        when the named sibling member has the given value.
struct ContainedWhen {
    enum class Kind { Enumerated, Integer, Boolean };
    std::string member;   ///< ASN.1 name of the sibling member
    std::string text;     ///< value as written in the configuration
    Kind        kind = Kind::Enumerated;
    int64_t     value = 0; ///< numeric value (enum number, integer, 0/1)
};

/// @brief One OCTET STRING field whose value is the encoding of another
///        type, from a schema contents constraint (X.682 §11) and/or the
///        `--container-config` sidecar.
struct ContainedField {
    std::string module;          ///< module of the enclosing type
    std::string type;            ///< enclosing type assignment name
    std::string field;           ///< member or alternative name
    bool        is_alternative = false;
    bool        from_constraint = false;
    bool        from_config = false;
    std::string inner_module;    ///< module that defines the inner type
    std::string inner_type;      ///< inner type assignment name
    ContentsEncoding encoding = ContentsEncoding::Outer;
    ContainedDecode  decode = ContainedDecode::Eager;
    std::string      decoder = "plain";
    std::optional<ContainedWhen> when;
    ContainedOnError on_error = ContainedOnError::KeepRaw;
    ContainedText    xer = ContainedText::Hex;
    ContainedText    jer = ContainedText::Hex;
};

/// @brief Collects the contained fields of a compilation: every member or
///        alternative with a usable contents constraint, plus the entries
///        of an optional sidecar configuration that override or extend
///        them. Codegen looks facts up by the member's own TypeDef.
class ContainedFields {
public:
    /// @brief Read a sidecar configuration file (JSON).
    /// @param path    File to read.
    /// @param errors  Receives one message per problem.
    /// @return false when the file cannot be read or is malformed.
    bool load_config(const std::string& path, std::vector<std::string>& errors);

    /// @brief Find contents constraints in the schema and apply the loaded
    ///        configuration. Unknown configuration targets are warnings;
    ///        conflicting or invalid options are errors.
    void build(const ast::ParseResult& pr, const Resolver& resolver,
               std::vector<std::string>& warnings, std::vector<std::string>& errors);

    /// @return The fact for a member/alternative TypeDef, or nullptr.
    const ContainedField* find(const ast::TypeDef* member) const;
    /// @return All facts: contents-constraint fields in schema order, then
    ///         configuration-only fields in configuration order.
    const std::vector<ContainedField>& all() const { return fields_; }

private:
    struct Entry {
        int line = 0;
        std::string module, module_oid, type, field;
        std::string inner_type, inner_module;
        std::optional<ContentsEncoding> encoding;
        std::optional<ContainedDecode>  decode;
        std::optional<std::string>      decoder;
        std::optional<ContainedWhen>    when;
        std::optional<ContainedOnError> on_error;
        std::optional<ContainedText>    xer, jer;
    };
    std::string config_path_;
    std::vector<Entry> entries_;
    std::vector<ContainedField> fields_;
    std::map<const ast::TypeDef*, std::size_t> by_member_;
};

/// @brief Configuration text of a ContainedText value ("hex", ...).
const char* to_string(ContainedText t);
/// @brief Configuration text of a ContentsEncoding value ("ber", ...).
const char* to_string(ContentsEncoding e);

} // namespace asn1::sema
