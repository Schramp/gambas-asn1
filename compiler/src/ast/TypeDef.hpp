#pragma once
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <variant>
#include "Node.hpp"
#include "Tag.hpp"
#include "Value.hpp"
#include "Constraint.hpp"

namespace asn1::ast {

// Forward declaration
struct TypeDef;
using TypeDefPtr = std::shared_ptr<TypeDef>;

// --- Kinds of type expressions -----------------------------------------------

// Reference to a named type (possibly in another module)
struct TypeRef {
    std::string module_name;   // empty if same-module or unqualified
    std::string type_name;
    std::vector<TypeDefPtr> params;  // for parameterised type instantiation
};

// Primitive / built-in type tags
enum class BuiltinType {
    Boolean, Integer, BitString, OctetString, Null,
    ObjectIdentifier, RelativeOid, Real, Enumerated,
    Utf8String, NumericString, PrintableString, T61String, VideotexString,
    Ia5String, GraphicString, VisibleString, GeneralString,
    UniversalString, BmpString, ObjectDescriptor,
    UtcTime, GeneralizedTime,
    Any,  // deprecated ANY
};

struct SequenceType   {};   // SEQUENCE { members... }
struct SetType        {};   // SET      { members... }
struct ChoiceType     {};   // CHOICE   { alternatives... }
struct SequenceOfType { TypeDefPtr element; };
struct SetOfType      { TypeDefPtr element; };
struct InstanceOfType { std::string class_name; };

// ENUMERATED named values
struct EnumValue {
    std::string name;
    std::optional<int64_t> number;   // absent = auto-assigned
};

// Marker for OPTIONAL / DEFAULT on sequence members
enum class Marker { None, Optional, Default };

// Grammar-only carrier: optMarker returns marker + (for DEFAULT) the parsed value.
struct MarkerInfo {
    Marker marker{Marker::None};
    Value  default_value;
};

// XER encoding instruction (X.693 §21): affects how the value is serialised in XER.
// Utf8 (ENCODING-CONTROL XER `TypeName OCTET STRING ::= utf8`):
// content octets are interpreted as UTF-8 text and emitted directly as XML
// character data (X.680 §11.15's control-character/entity escaping applies),
// not hex/base64.
enum class XerEncoding { Default, Base64, Utf8 };

// --- The main TypeDef node ---------------------------------------------------
struct TypeDef : Node {
    std::string name;            // identifier or type reference name (may be empty for anonymous)
    std::string xer_name;        // override for XER element tag (anonymous types use ASN.1 keyword: SEQUENCE/SET/CHOICE)
    // Set only when this TypeDef is a synthetic promotion of an anonymous
    // inline construct (generate_inline_types) — `name` at that point holds
    // the compiler-generated backend identifier, not a real ASN.1 name, so
    // callers wanting a human-traceable label (e.g. generated doc comments)
    // need this instead: the original ASN.1 identifier if the promoted
    // element had one of its own, otherwise the enclosing field/type name
    // it was promoted from. Empty for an ordinary named type (use `name`
    // there).
    std::string origin_label;
    XerEncoding xer_encoding = XerEncoding::Default;

    // What kind of type is this?
    using TypeBody = std::variant<
        std::monostate,    // not yet resolved
        BuiltinType,
        TypeRef,
        SequenceType,
        SetType,
        ChoiceType,
        SequenceOfType,
        SetOfType,
        InstanceOfType
    >;
    TypeBody body;

    // Members (for SEQUENCE, SET, CHOICE) or named values (for ENUMERATED/BIT STRING with names)
    std::vector<TypeDefPtr> members;

    // For ENUMERATED / INTEGER named values
    std::vector<EnumValue>  enum_values;

    // Tag override
    Tag tag;

    // OPTIONAL / DEFAULT marker (for SEQUENCE/SET members)
    Marker marker{Marker::None};
    Value  default_value;

    // Constraints (size, range, etc.)
    std::vector<ConstraintPtr> constraints;

    // Whether this is an extension marker (...)
    bool is_extension_marker{false};

    // Whether UNIQUE keyword is present (for CLASS fields)
    bool unique{false};

    bool is_parameterized{false};
    std::vector<std::string> formal_params;  // formal parameter names, e.g. {"Color"} in Flag{Color}

    // Helpers
    bool is_optional()  const { return marker == Marker::Optional || marker == Marker::Default; }
    bool has_default()  const { return marker == Marker::Default; }
    bool is_sequence()  const { return std::holds_alternative<SequenceType>(body); }
    bool is_set()       const { return std::holds_alternative<SetType>(body); }
    bool is_choice()    const { return std::holds_alternative<ChoiceType>(body); }
    bool is_seq_of()    const { return std::holds_alternative<SequenceOfType>(body); }
    bool is_set_of()    const { return std::holds_alternative<SetOfType>(body); }
    bool is_builtin()   const { return std::holds_alternative<BuiltinType>(body); }
    bool is_typeref()   const { return std::holds_alternative<TypeRef>(body); }
};

} // namespace asn1::ast
