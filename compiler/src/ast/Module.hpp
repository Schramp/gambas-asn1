#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "Node.hpp"
#include "TypeDef.hpp"
#include "Value.hpp"

namespace asn1::ast {

enum class TagDefault { Explicit, Implicit, Automatic };

// Holds parsed module flags. tag_default is unset until a TAGS clause is seen;
// EXTENSIBILITY IMPLIED is independent and never overrides tag_default.
struct ModuleFlags {
    std::optional<TagDefault> tag_default;
    bool extensibility_implied{false};
};

enum class ImportVersionPolicy { Exact, Successors, Descendants };

struct ImportList {
    std::string from_module;
    OidValue    module_oid;     // may be empty
    ImportVersionPolicy version_policy{ImportVersionPolicy::Exact};
    std::vector<std::string> names;
};

struct Module : Node {
    std::string   name;
    OidValue      oid;                              // may be empty
    TagDefault    tag_default{TagDefault::Explicit};
    bool          extensibility_implied{false};
    bool          exports_all{true};
    std::vector<std::string> exports;               // empty = ALL if exports_all
    std::vector<ImportList>  imports;
    std::vector<TypeDefPtr>  assignments;           // type and value assignments
};

using ModulePtr = std::shared_ptr<Module>;

// Top-level parse result: a collection of modules
struct ParseResult {
    std::vector<ModulePtr> modules;
};

} // namespace asn1::ast
