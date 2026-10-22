#pragma once
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "../ast/Constraint.hpp"

namespace asn1::sema {

/// Encoding rules named by a contents constraint's `ENCODED BY` (X.682 §11.6).
/// `Outer` means no `ENCODED BY`: the contents use the encoding rules applied
/// to the enclosing octet string (X.682 §11.4).
enum class ContentsEncoding {
    Outer,
    Ber,            ///< {joint-iso-itu-t asn1(1) basic-encoding(1)}, X.690 §8
    Cer,            ///< {... ber-derived(2) canonical-encoding(0)}, X.690 §9
    Der,            ///< {... ber-derived(2) distinguished-encoding(1)}, X.690 §10
    PerAligned,     ///< {... packed-encoding(3) basic(0) aligned(0)}, X.691
    PerUnaligned,   ///< {... packed-encoding(3) basic(0) unaligned(1)}, X.691
    Unknown,        ///< any other OID, or a value reference not resolved here
};

/// @brief Find the contents constraint (X.682 §11) among a type's own
///        constraints, looking through intersections and unions.
/// @return The constraint, or nullptr when the type has none.
inline const ast::ContentsConstraint*
find_contents_constraint(const std::vector<ast::ConstraintPtr>& constraints) {
    for (const auto& c : constraints) {
        if (!c) continue;
        if (auto* cc = std::get_if<ast::ContentsConstraint>(&c->body))
            return cc;
        if (auto* ic = std::get_if<ast::IntersectionConstraint>(&c->body))
            if (auto* r = find_contents_constraint(ic->operands)) return r;
        if (auto* uc = std::get_if<ast::UnionConstraint>(&c->body))
            if (auto* r = find_contents_constraint(uc->operands)) return r;
    }
    return nullptr;
}

/// @brief Turn the source text of an `ENCODED BY` OBJECT IDENTIFIER value
///        (X.682 §11.2) into its numeric arcs.
///
/// Handles `{ 2 1 1 }`, `{ joint-iso-itu-t asn1(1) basic-encoding(1) }` and
/// name-only arcs for the well-known ASN.1 encoding-rule arcs of X.690/X.691.
/// @return The arcs, or an empty vector when the text cannot be read without
///         value resolution (e.g. a value reference).
inline std::vector<int64_t> encoded_by_arcs(std::string_view text) {
    std::vector<int64_t> arcs;
    if (text.empty() || text.front() != '{') return arcs;
    std::size_t i = 1;
    auto skip_ws = [&] { while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i; };
    while (true) {
        skip_ws();
        if (i >= text.size()) return {};
        if (text[i] == '}') break;
        if (std::isdigit(static_cast<unsigned char>(text[i]))) {
            int64_t n = 0;
            while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i])))
                n = n * 10 + (text[i++] - '0');
            arcs.push_back(n);
            continue;
        }
        std::size_t start = i;
        while (i < text.size() && (std::isalnum(static_cast<unsigned char>(text[i])) || text[i] == '-'))
            ++i;
        if (i == start) return {};
        std::string_view name = text.substr(start, i - start);
        skip_ws();
        if (i < text.size() && text[i] == '(') {
            ++i;
            skip_ws();
            int64_t n = 0;
            bool any = false;
            while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
                n = n * 10 + (text[i++] - '0');
                any = true;
            }
            skip_ws();
            if (!any || i >= text.size() || text[i] != ')') return {};
            ++i;
            arcs.push_back(n);
            continue;
        }
        // Name-only arc: only the X.660 root arcs and the X.690/X.691
        // encoding-rule arcs are known without value resolution.
        struct Known { std::string_view name; std::size_t pos; int64_t value; };
        static constexpr Known known[] = {
            {"itu-t", 0, 0}, {"ccitt", 0, 0}, {"iso", 0, 1},
            {"joint-iso-itu-t", 0, 2}, {"joint-iso-ccitt", 0, 2},
            {"asn1", 1, 1},
            {"basic-encoding", 2, 1}, {"ber-derived", 2, 2}, {"packed-encoding", 2, 3},
            {"canonical-encoding", 3, 0}, {"distinguished-encoding", 3, 1},
            {"basic", 3, 0}, {"canonical", 3, 1},
            {"aligned", 4, 0}, {"unaligned", 4, 1},
        };
        bool found = false;
        for (const auto& k : known)
            if (k.name == name && k.pos == arcs.size()) {
                arcs.push_back(k.value);
                found = true;
                break;
            }
        if (!found) return {};
    }
    return arcs;
}

/// @brief Classify a contents constraint's encoding rules (X.682 §11.4/§11.6).
/// @param encoded_by The `ENCODED BY` value text; empty when absent.
inline ContentsEncoding classify_encoded_by(std::string_view encoded_by) {
    if (encoded_by.empty()) return ContentsEncoding::Outer;
    auto a = encoded_by_arcs(encoded_by);
    auto is = [&](std::initializer_list<int64_t> want) {
        return a.size() == want.size() && std::equal(want.begin(), want.end(), a.begin());
    };
    if (is({2, 1, 1}))       return ContentsEncoding::Ber;
    if (is({2, 1, 2, 0}))    return ContentsEncoding::Cer;
    if (is({2, 1, 2, 1}))    return ContentsEncoding::Der;
    if (is({2, 1, 3, 0, 0})) return ContentsEncoding::PerAligned;
    if (is({2, 1, 3, 0, 1})) return ContentsEncoding::PerUnaligned;
    return ContentsEncoding::Unknown;
}

} // namespace asn1::sema
