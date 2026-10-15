#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <utility>
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
    // ENCODING-CONTROL XER ... END block instructions (X.693 §21 BASE64
    // form and the legacy `TypeName OCTET STRING ::= base64` form) —
    // (type name, encoding) pairs applied to the matching assignment's
    // own xer_encoding field once the whole module is parsed (the block
    // may reference a type declared earlier or later in the module).
    std::vector<std::pair<std::string, XerEncoding>> xer_encoding_overrides;
};

using ModulePtr = std::shared_ptr<Module>;

// Top-level parse result: a collection of modules
struct ParseResult {
    std::vector<ModulePtr> modules;
    // Last extension addition group id handed out by the parser (`[[ … ]]`,
    // X.680 §3.6.26). Members of one group share an id so codegen can
    // encode the group as a single addition (X.691 §18.9); ids are unique
    // within one parse, 0 means "not in a group".
    int last_ext_group = 0;
};

} // namespace asn1::ast
