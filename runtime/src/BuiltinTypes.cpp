#include <asn1cpp/TypeDescriptor.hpp>
#include <asn1cpp/codec/PerHandlers.hpp>

// Builtin TypeDescriptor definitions — separated from the header so that
// per_handler can reference runtime singletons without the compiler binary
// needing to link libasn1cpp_runtime.

namespace asn1 {

const TypeDescriptor asn_DEF_Any           = { "ANY",              Tag::universal( 4, false), nullptr, nullptr, nullptr, nullptr, {}, true,  TypeKind::Any,      &per_any_handler };
const TypeDescriptor asn_DEF_Integer       = { "INTEGER",          Tag::universal( 2, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_integer_handler };
const TypeDescriptor asn_DEF_Boolean       = { "BOOLEAN",          Tag::universal( 1, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_boolean_handler };
const TypeDescriptor asn_DEF_Null          = { "NULL",             Tag::universal( 5, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_null_handler };
const TypeDescriptor asn_DEF_Real          = { "REAL",             Tag::universal( 9, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_real_handler };
const TypeDescriptor asn_DEF_BitString     = { "BIT_STRING",       Tag::universal( 3, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_bitstring_handler };
const TypeDescriptor asn_DEF_Oid           = { "OBJECT_IDENTIFIER",Tag::universal( 6, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_oid_handler };
const TypeDescriptor asn_DEF_RelativeOid   = { "RELATIVE_OID",     Tag::universal(13, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_reloid_handler };
const TypeDescriptor asn_DEF_UtcTime       = { "UTCTime",          Tag::universal(23, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_GeneralizedTime={ "GeneralizedTime",  Tag::universal(24, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_OctetString   = { "OCTET_STRING",     Tag::universal( 4, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_octetstring_handler };
const TypeDescriptor asn_DEF_Utf8String    = { "UTF8String",       Tag::universal(12, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_Ia5String     = { "IA5String",        Tag::universal(22, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_NumericString = { "NumericString",    Tag::universal(18, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_PrintableString={ "PrintableString",  Tag::universal(19, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_T61String     = { "T61String",        Tag::universal(20, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_VisibleString = { "VisibleString",    Tag::universal(26, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_GeneralString = { "GeneralString",    Tag::universal(27, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_GraphicString = { "GraphicString",    Tag::universal(25, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_UniversalString={ "UniversalString",  Tag::universal(28, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_BmpString     = { "BMPString",        Tag::universal(30, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_VideotexString= { "VideotexString",   Tag::universal(21, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };
const TypeDescriptor asn_DEF_ObjectDescriptor={ "ObjectDescriptor",Tag::universal( 7, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler };

} // namespace asn1
