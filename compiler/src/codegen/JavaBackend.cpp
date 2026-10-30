#include "JavaBackend.hpp"

namespace asn1::codegen {

/// @brief Emit a generated compilation unit's header: a comment naming
///        the ASN.1 module, then the `package` declaration (JLS §7.4).
/// @param module_comment ASN.1 module name, with its OID when it has one.
/// @param session        Per-type output session; writes the `.java` buffer.
void JavaBackend::emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const {
    auto& os = session.buffer(declaration_extension());
    os << "// Module: " << module_comment << "\n\n";
    if (!package_.empty()) os << "package " << package_ << ";\n\n";
}

/// @brief Emit the implementation-half preamble: nothing, since the
///        declaration and definition share one `.java` file whose header
///        `emit_declaration_preamble` already wrote.
/// @param declaration_filename Unused.
/// @param session              Unused.
void JavaBackend::emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const {
    (void)declaration_filename;
    (void)session;
}

/// @brief Check a `--package` value against the Java package-name grammar.
/// @param pkg Candidate package name.
/// @return True when every dot-separated part is a Java identifier that
///         `java_escape` leaves unchanged.
/// @see JLS §6.5.3, §7.4.1 — package names.
bool JavaBackend::valid_package(std::string_view pkg) {
    if (pkg.empty()) return false;
    std::size_t start = 0;
    while (true) {
        auto dot = pkg.find('.', start);
        auto part = pkg.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (part.empty()) return false;
        if (!std::isalpha((unsigned char)part[0]) && part[0] != '_' && part[0] != '$') return false;
        for (char c : part)
            if (!std::isalnum((unsigned char)c) && c != '_' && c != '$') return false;
        if (java_escape(std::string(part)) != part) return false;
        if (dot == std::string_view::npos) return true;
        start = dot + 1;
    }
}

} // namespace asn1::codegen
