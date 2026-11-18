#pragma once
#include "Asn1Object.hpp"
#include <cstdint>
#include <string>

namespace asn1 {

/// @brief Base class for all generated ENUMERATED types.
///
/// Generated code emits: class MyEnum : public asn1::EnumValue { enum Enm : long {...}; ... };
///
/// Besides one of its items, an extensible ENUMERATED can hold an item this
/// schema version does not define, received from a sender with a newer
/// version: X.680 §52.1 forbids treating it as a decoding error. Each codec
/// carries a different part of such an item, so the value records which:
///
/// | State        | Set by                       | \c value() holds         |
/// |--------------|------------------------------|--------------------------|
/// | Known        | \c set(), the generated API  | the item's value         |
/// | UnknownValue | BER decode                   | the number on the wire   |
/// | UnknownOrdinal | PER decode (X.691 §14)     | the extension ordinal    |
/// | UnknownIdentifier | XER/JER decode (X.693 §8.6.4) | 0 (the name is not kept) |
///
/// An unknown item re-encodes unchanged in the codec it came from; a codec
/// that cannot represent it fails the encode with an error naming it.
/// Check \c is_unknown() before reading \c value() as one of the items.
class EnumValue : public Asn1Object {
public:
    /// @brief Which kind of item the value holds (see the class table).
    enum class Unknown : uint8_t { None, Value, Ordinal, Identifier };

protected:
    long    value_   = 0;
    Unknown unknown_ = Unknown::None;

public:
    /// @brief The item's value, or for an unknown item what the class table lists.
    long value() const { return value_; }
    /// @brief Store a known item's value.
    void set(long v)   { value_ = v; unknown_ = Unknown::None; }

    /// @brief Store a value not among the items, read from BER.
    void set_unknown_value(long v)        { value_ = v; unknown_ = Unknown::Value; }
    /// @brief Store an extension ordinal past the known items, read from PER.
    void set_unknown_ordinal(long ordinal) { value_ = ordinal; unknown_ = Unknown::Ordinal; }
    /// @brief Record an identifier not among the items, read from XER or JER.
    void set_unknown_identifier()          { value_ = 0; unknown_ = Unknown::Identifier; }

    /// @brief True when the value is an item this schema version does not define.
    bool    is_unknown() const   { return unknown_ != Unknown::None; }
    /// @brief The kind of unknown item held, \c Unknown::None for a known one.
    Unknown unknown_kind() const { return unknown_; }

    /// @brief Compare two ENUMERATED values: same item, or the same unknown item.
    /// @return true when both hold the same value in the same state.
    /// A hidden friend rather than a member: with a member, C++20's reversed
    /// candidate for `Derived == Derived` needs the same derived-to-base
    /// conversions as the normal one, which clang reports as ambiguous.
    /// operator!= is rewritten from this one (C++20 [over.match.oper]).
    friend bool operator==(const EnumValue& a, const EnumValue& b) {
        return a.unknown_ == b.unknown_ && a.value_ == b.value_;
    }
};

/// @brief Text naming an unknown ENUMERATED item for error messages, e.g.
///        "value 7", "extension item #3" or "an unknown identifier".
inline std::string enum_unknown_text(const EnumValue& v) {
    switch (v.unknown_kind()) {
    case EnumValue::Unknown::Value:      return "value " + std::to_string(v.value());
    case EnumValue::Unknown::Ordinal:    return "extension item #" + std::to_string(v.value());
    case EnumValue::Unknown::Identifier: return "an unknown identifier";
    case EnumValue::Unknown::None:       break;
    }
    return "value " + std::to_string(v.value());
}

/// @brief Encode error for an unknown item that \p codec cannot represent,
///        e.g. "ENUMERATED Color: extension item #3 of a newer schema
///        version has no BER encoding".
inline std::string enum_unknown_encode_error(const char* type_name, const EnumValue& v, const char* codec) {
    return std::string("ENUMERATED ") + type_name + ": " + enum_unknown_text(v) +
           " of a newer schema version has no " + codec + " encoding";
}

} // namespace asn1
