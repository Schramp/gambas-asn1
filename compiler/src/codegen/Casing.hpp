#pragma once
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace asn1::codegen {

// Backend-agnostic string case-conversion helpers. No dependency on Backend,
// AST types, or anything backend-specific — every ASN.1 codegen backend
// needing snake_case/PascalCase/etc. conversion shares these instead of
// reaching into whichever backend happened to define its own copy first.

// Converts an ASN.1 type name to a valid C++ identifier.
// "My-Type" -> "MyType"
inline std::string to_cpp_name(std::string_view s) {
    std::string out;
    for (char c : s)
        out += (c == '-') ? '_' : c;
    return out;
}

// Upper-cases the first character of an identifier string.
inline std::string capitalize_first(std::string s) {
    if (!s.empty()) s[0] = (char)std::toupper((unsigned char)s[0]);
    return s;
}

// Acronym-aware word splitter — inserting '_' before every uppercase letter
// would split a run of consecutive uppercase letters one at a time ("TYP"
// -> "t_y_p" instead of "typ"), treating every individual uppercase letter
// as its own word start rather than recognizing a whole acronym run as one
// word. Rule instead: '-' or '_' is always a hard word break
// (X.680's own identifier separator, plus the literal underscores already
// present in CppBackend-convention synthetic names like "asn_TYP_Parent_
// member" that also get routed through to_snake_case); a lowercase/digit ->
// uppercase transition starts a new word; a run of 2+ uppercase letters
// followed by a lowercase letter keeps the run together except its *last*
// letter, which starts the next word ("HTTPServer" -> ["HTTP", "Server"],
// not one letter per word). Shared by to_snake_case and
// to_upper_camel_case, which solve the same word-splitting problem in
// opposite case directions.
inline std::vector<std::string> split_words(std::string_view s) {
    std::vector<std::string> words;
    std::string cur;
    auto flush = [&]() { if (!cur.empty()) { words.push_back(cur); cur.clear(); } };
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '-' || c == '_') { flush(); continue; }
        if (std::isupper(static_cast<unsigned char>(c)) && !cur.empty()) {
            bool prev_upper = std::isupper(static_cast<unsigned char>(cur.back()));
            bool next_lower = (i + 1 < s.size()) && std::islower(static_cast<unsigned char>(s[i + 1]));
            if (!prev_upper || next_lower) flush();
        }
        cur += c;
    }
    flush();
    return words;
}

// snake_case conversion shared by member_name/value_name — word-split via
// split_words(), each word lower-cased and joined with '_'.
// "myMember" -> "my_member"; "MyType" -> "my_type"; "HTTPServer" ->
// "http_server" (not "h_t_t_p_server"); "already_snake" unchanged.
inline std::string to_snake_case(std::string_view s) {
    std::string out;
    for (const auto& w : split_words(s)) {
        if (!out.empty()) out += '_';
        for (char c : w) out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// SCREAMING_SNAKE_CASE conversion for Rust `const` names.
inline std::string to_screaming_snake_case(std::string_view s) {
    std::string out = to_snake_case(s);
    for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

// Real word-split UpperCamelCase conversion, unlike
// capitalize_first (which only uppercases the first character of the whole
// string). X.680 §11.2 identifiers are hyphen-separated lowercase words
// (e.g. "eight-bit-binary") — capitalize_first(to_cpp_name(...)) would turn
// the hyphen into a literal underscore first, producing "Eight_bit_binary"
// (fails rustc's non_camel_case_types lint) instead of "EightBitBinary".
// Splits on '-' (the only word separator X.680 allows in
// an identifier) and capitalizes the first letter of every segment, joining
// with no separator; single-word names behave identically to the old
// capitalize_first(to_cpp_name(...)) path.
inline std::string to_upper_camel_case(std::string_view s) {
    std::string out;
    bool new_word = true;
    for (char c : s) {
        if (c == '-') { new_word = true; continue; }
        if (new_word) {
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            new_word = false;
        } else {
            out += c;
        }
    }
    return out;
}

} // namespace asn1::codegen
