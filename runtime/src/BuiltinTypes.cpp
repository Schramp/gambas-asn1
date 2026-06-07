#include <asn1cpp/TypeDescriptor.hpp>
#include <asn1cpp/ChoiceInterface.hpp>
#include <asn1cpp/codec/PerHandlers.hpp>
#include <asn1cpp/codec/BerHandlers.hpp>
#include <asn1cpp/types/Boolean.hpp>
#include <asn1cpp/types/Integer.hpp>
#include <asn1cpp/types/Null.hpp>
#include <asn1cpp/types/Real.hpp>
#include <asn1cpp/types/BitString.hpp>
#include <asn1cpp/types/OctetString.hpp>
#include <asn1cpp/types/Oid.hpp>
#include <asn1cpp/types/Time.hpp>
#include <asn1cpp/types/Strings.hpp>

// Builtin TypeDescriptor definitions — separated from the header so that
// per_handler / ber_handler can reference runtime singletons without the
// compiler binary needing to link libasn1cpp_runtime.

namespace asn1 {

// No-op lifecycle for CHOICE NOTHING state — destroy/move are no-ops so
// ChoiceInterface dtor and move ops need no null check on active_lifecycle.
const TypeLifecycleOps ChoiceInterface::k_noop_lifecycle{
    [](void*){},
    [](void*){},
    [](void*, void*){}
};

const TypeDescriptor asn_DEF_Any           = { "ANY",              Tag::universal( 4, false), nullptr, nullptr, nullptr, nullptr, {}, true,  TypeKind::Any,      &per_any_handler,         &ber_any_handler,         TypeLifecycleOps(TypeTag<OctetString>{}) };
const TypeDescriptor asn_DEF_Integer       = { "INTEGER",          Tag::universal( 2, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_integer_handler,     &ber_integer_handler,     TypeLifecycleOps(TypeTag<Integer>{}) };
const TypeDescriptor asn_DEF_Boolean       = { "BOOLEAN",          Tag::universal( 1, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_boolean_handler,     &ber_boolean_handler,     TypeLifecycleOps(TypeTag<Boolean>{}) };
const TypeDescriptor asn_DEF_Null          = { "NULL",             Tag::universal( 5, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_null_handler,        &ber_null_handler,        TypeLifecycleOps(TypeTag<Null>{}) };
const TypeDescriptor asn_DEF_Real          = { "REAL",             Tag::universal( 9, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_real_handler,        &ber_real_handler,        TypeLifecycleOps(TypeTag<Real>{}) };
const TypeDescriptor asn_DEF_BitString     = { "BIT_STRING",       Tag::universal( 3, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_bitstring_handler,   &ber_bitstring_handler,   TypeLifecycleOps(TypeTag<BitString>{}) };
const TypeDescriptor asn_DEF_Oid           = { "OBJECT_IDENTIFIER",Tag::universal( 6, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_oid_handler,         &ber_oid_handler,         TypeLifecycleOps(TypeTag<Oid>{}) };
const TypeDescriptor asn_DEF_RelativeOid   = { "RELATIVE_OID",     Tag::universal(13, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_reloid_handler,      &ber_reloid_handler,      TypeLifecycleOps(TypeTag<RelativeOid>{}) };
const TypeDescriptor asn_DEF_UtcTime       = { "UTCTime",          Tag::universal(23, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_utctime_handler,     TypeLifecycleOps(TypeTag<UtcTime>{}) };
const TypeDescriptor asn_DEF_GeneralizedTime={ "GeneralizedTime",  Tag::universal(24, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_gentime_handler,     TypeLifecycleOps(TypeTag<GeneralizedTime>{}) };
const TypeDescriptor asn_DEF_OctetString   = { "OCTET_STRING",     Tag::universal( 4, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_octetstring_handler, &ber_octetstring_handler, TypeLifecycleOps(TypeTag<OctetString>{}) };
const TypeDescriptor asn_DEF_Utf8String    = { "UTF8String",       Tag::universal(12, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<Utf8String>{}) };
const TypeDescriptor asn_DEF_Ia5String     = { "IA5String",        Tag::universal(22, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<Ia5String>{}) };
const TypeDescriptor asn_DEF_NumericString = { "NumericString",    Tag::universal(18, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<NumericString>{}) };
const TypeDescriptor asn_DEF_PrintableString={ "PrintableString",  Tag::universal(19, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<PrintableString>{}) };
const TypeDescriptor asn_DEF_T61String     = { "T61String",        Tag::universal(20, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<T61String>{}) };
const TypeDescriptor asn_DEF_VisibleString = { "VisibleString",    Tag::universal(26, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<VisibleString>{}) };
const TypeDescriptor asn_DEF_GeneralString = { "GeneralString",    Tag::universal(27, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<GeneralString>{}) };
const TypeDescriptor asn_DEF_GraphicString = { "GraphicString",    Tag::universal(25, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<GraphicString>{}) };
const TypeDescriptor asn_DEF_UniversalString={ "UniversalString",  Tag::universal(28, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<UniversalString>{}) };
const TypeDescriptor asn_DEF_BmpString     = { "BMPString",        Tag::universal(30, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<BmpString>{}) };
const TypeDescriptor asn_DEF_VideotexString= { "VideotexString",   Tag::universal(21, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<VideotexString>{}) };
const TypeDescriptor asn_DEF_ObjectDescriptor={ "ObjectDescriptor",Tag::universal( 7, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<ObjectDescriptor>{}) };

} // namespace asn1
