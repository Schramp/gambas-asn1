#pragma once
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <format>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"
#include "../sema/Resolver.hpp"

namespace asn1::codegen {

namespace fs = std::filesystem;

// Converts an ASN.1 type name to a valid C++ identifier.
// "My-Type" -> "MyType"
inline std::string to_cpp_name(std::string_view s) {
    std::string out;
    bool upper_next = false;
    for (char c : s) {
        if (c == '-') { upper_next = true; continue; }
        if (upper_next) { out += (char)std::toupper(c); upper_next = false; }
        else out += c;
    }
    return out;
}

// Converts a member (identifier) name: first letter lower-case
inline std::string to_member_name(std::string_view s) {
    auto n = to_cpp_name(s);
    if (!n.empty()) n[0] = (char)std::tolower(n[0]);
    return n;
}

class Generator {
    fs::path          out_dir_;
    sema::Resolver&   resolver_;

public:
    Generator(fs::path out_dir, sema::Resolver& res)
        : out_dir_(std::move(out_dir)), resolver_(res) {}

    void generate(const ast::ParseResult& pr) {
        fs::create_directories(out_dir_);
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker)
                    generate_type(*def, mod->name);
    }

private:
    void generate_type(const ast::TypeDef& def, const std::string& module_name);
    void emit_hpp(const ast::TypeDef& def, std::ostream& os);
    void emit_cpp(const ast::TypeDef& def, std::ostream& os);
    void emit_struct_members(const ast::TypeDef& def, std::ostream& os);
    void emit_ber_encode(const ast::TypeDef& def, std::ostream& os);
    void emit_ber_decode(const ast::TypeDef& def, std::ostream& os);
    std::string cpp_type_for(const ast::TypeDef& def);
    std::string ber_tag_for(const ast::TypeDef& def);
};

} // namespace asn1::codegen
