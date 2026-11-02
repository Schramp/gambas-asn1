#pragma once
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"

namespace asn1::sema {

class Resolver;

/// How PER treats a SIZE constraint on a non-known-multiplier character
/// string (UTF8String, TeletexString/T61String, VideotexString,
/// GraphicString, GeneralString, ObjectDescriptor).
enum class NkmSizeMode {
    /// X.691 §10.3.18, §30.6: the constraint is not PER-visible. The length
    /// is an unconstrained length determinant and there is no extension bit.
    Strict,
    /// The SIZE is encoded as if PER-visible (constrained length, extension
    /// bit when the SIZE is extensible), as asn1c does. Not X.691.
    Visible,
};

/// @brief Configuration text of a mode ("strict" / "visible").
const char* to_string(NkmSizeMode m);
/// @brief Parse "strict" / "visible"; false for any other text.
bool parse_nkm_size_mode(const std::string& s, NkmSizeMode& out);
/// @brief Whether a builtin type is a restricted character string type that
///        is not a known-multiplier type (X.691 §3.7.16, §30.1).
bool is_non_known_multiplier(ast::BuiltinType bt);

/// @brief Decides, per type assignment and per member, which NkmSizeMode
///        applies: a `per_nkm_size` sidecar entry for the member wins, then
///        one for its type assignment, then the `--per-nkm-size` default.
///        Codegen looks the mode up by the member's own TypeDef or by the
///        type assignment's module and name.
class PerNkmSize {
public:
    /// Where a mode came from, for `--list-per-nkm-size`.
    enum class Source { Default, Config };

    /// One SIZE-constrained non-known-multiplier string in the schema.
    struct Site {
        std::string module;
        std::string path;        ///< Type or Type.member[.member...]
        std::string builtin;     ///< ASN.1 name of the string type
        NkmSizeMode mode = NkmSizeMode::Strict;
        Source      source = Source::Default;
    };

    void set_default(NkmSizeMode m) { default_ = m; }
    NkmSizeMode default_mode() const { return default_; }

    /// @brief Read the optional `per_nkm_size` array of a sidecar file
    ///        (the same file as `--container-config`). A file without the
    ///        key is valid and adds no entries.
    /// @param path    File to read.
    /// @param errors  Receives one message per problem.
    /// @return false when the file cannot be read or an entry is malformed.
    bool load_config(const std::string& path, std::vector<std::string>& errors);

    /// @brief Resolve the loaded entries against the schema and collect the
    ///        sites. Entries naming nothing in this compilation are warnings.
    void build(const ast::ParseResult& pr, const Resolver& resolver,
               std::vector<std::string>& warnings, std::vector<std::string>& errors);

    /// @return Mode for a member, alternative or element TypeDef.
    NkmSizeMode mode_for(const ast::TypeDef* member) const;
    /// @return Mode for the type assignment \p type of \p module.
    NkmSizeMode mode_for(const std::string& module, const std::string& type) const;
    /// @return Every SIZE-constrained non-known-multiplier string, in schema order.
    const std::vector<Site>& sites() const { return sites_; }

private:
    struct Entry {
        int line = 0;
        std::string module, type, field;
        NkmSizeMode mode = NkmSizeMode::Strict;
    };
    NkmSizeMode default_ = NkmSizeMode::Strict;
    std::string config_path_;
    std::vector<Entry> entries_;
    std::map<std::tuple<std::string, std::string>, NkmSizeMode> by_type_;
    std::map<const ast::TypeDef*, NkmSizeMode> by_member_;
    std::vector<Site> sites_;
};

} // namespace asn1::sema
