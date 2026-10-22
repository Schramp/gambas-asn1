#pragma once
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace asn1::config {

/// @brief A parsed JSON value (ECMA-404), as needed for compiler
///        configuration files. Numbers are kept as their source text so a
///        caller decides how to read them (integer, OID arc, ...).
struct JsonValue {
    struct Number { std::string text; };
    using Array  = std::vector<JsonValue>;
    /// Members in source order; duplicate names are rejected by the parser.
    using Object = std::vector<std::pair<std::string, JsonValue>>;
    std::variant<std::monostate, bool, Number, std::string, Array, Object> v;
    int line = 0;   ///< 1-based source line where the value starts

    bool is_null()   const { return std::holds_alternative<std::monostate>(v); }
    bool is_bool()   const { return std::holds_alternative<bool>(v); }
    bool is_number() const { return std::holds_alternative<Number>(v); }
    bool is_string() const { return std::holds_alternative<std::string>(v); }
    bool is_array()  const { return std::holds_alternative<Array>(v); }
    bool is_object() const { return std::holds_alternative<Object>(v); }
    /// @brief Member lookup on an object value.
    /// @return The member's value, or nullptr when absent or not an object.
    const JsonValue* find(std::string_view name) const;
};

/// @brief Parse a JSON text (ECMA-404) into a JsonValue.
/// @param text   The complete document.
/// @param error  Set to "line N: message" on failure.
/// @return The value, or nullptr on a syntax error.
std::unique_ptr<JsonValue> parse_json(std::string_view text, std::string& error);

} // namespace asn1::config
