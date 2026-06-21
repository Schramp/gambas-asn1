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
#include <array>

// Builtin TypeDescriptor definitions — separated from the header so that
// per_handler / ber_handler can reference runtime singletons without the
// compiler binary needing to link libasn1cpp_runtime.

namespace {

/// @brief Build a 256-entry encode lookup table from a sorted alphabet array.
/// @param alpha  Sorted byte values of the alphabet (must be non-empty).
/// @return Array where [char_value] = constrained_index, or 0xFFFF if not in alphabet.
/// @see X.691 §26.5 — known-multiplier character string PER canonical index.
template<std::size_t N>
static constexpr std::array<uint16_t, 256> make_enc_table(const uint8_t (&alpha)[N]) {
    std::array<uint16_t, 256> t{};
    t.fill(0xFFFFu);
    for (std::size_t i = 0; i < N; ++i)
        t[alpha[i]] = static_cast<uint16_t>(i);
    return t;
}

// NumericString (X.680 §41.2): space + '0'..'9' — 11 chars, sorted ASCII.
// Space (0x20) precedes digits (0x30..) so sort order = canonical X.691 index order.
static constexpr uint8_t k_num_alpha[] = {
    ' ','0','1','2','3','4','5','6','7','8','9'
};
static constexpr auto k_num_enc = make_enc_table(k_num_alpha);

// PrintableString (X.680 Table 8): 74 chars, sorted ASCII.
static constexpr uint8_t k_prt_alpha[] = {
    ' ', '\'','(',')','+',',','-','.','/',
    '0','1','2','3','4','5','6','7','8','9',
    ':','=','?',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z'
};
static constexpr auto k_prt_enc = make_enc_table(k_prt_alpha);

// VisibleString and IA5String: printable ASCII 0x20..0x7E (95 chars), sorted.
// Matches the current builtin_alphabet() behaviour — control chars excluded.
// alphabet_bits left 0: PerCodec uses string_params() raw-ASCII path, not this table.
static constexpr auto k_vis_alpha = []() {
    std::array<uint8_t, 95> a{};
    for (int i = 0; i < 95; ++i) a[i] = static_cast<uint8_t>(0x20 + i);
    return a;
}();
static constexpr auto k_vis_enc = []() {
    std::array<uint16_t, 256> t{};
    t.fill(0xFFFFu);
    for (int i = 0; i < 95; ++i) t[0x20 + i] = static_cast<uint16_t>(i);
    return t;
}();

} // anonymous namespace

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
// alphabet_bits intentionally 0: PerCodec uses string_params() raw-bit path for these
// types, not the encode_table index path. alphabet/encode_table are used only by
// validate() and (FROM-constrained) RandomFiller for O(1) membership testing.
const TypeDescriptor asn_DEF_Ia5String     = { "IA5String",        Tag::universal(22, false), nullptr, nullptr, nullptr, nullptr, { .alphabet=k_vis_alpha.data(), .alphabet_size=95u, .encode_table=k_vis_enc.data() }, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<Ia5String>{}) };
const TypeDescriptor asn_DEF_NumericString = { "NumericString",    Tag::universal(18, false), nullptr, nullptr, nullptr, nullptr, { .alphabet=k_num_alpha, .alphabet_size=11u, .encode_table=k_num_enc.data() }, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<NumericString>{}) };
const TypeDescriptor asn_DEF_PrintableString={ "PrintableString",  Tag::universal(19, false), nullptr, nullptr, nullptr, nullptr, { .alphabet=k_prt_alpha, .alphabet_size=74u, .encode_table=k_prt_enc.data() }, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<PrintableString>{}) };
const TypeDescriptor asn_DEF_T61String     = { "T61String",        Tag::universal(20, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<T61String>{}) };
const TypeDescriptor asn_DEF_VisibleString = { "VisibleString",    Tag::universal(26, false), nullptr, nullptr, nullptr, nullptr, { .alphabet=k_vis_alpha.data(), .alphabet_size=95u, .encode_table=k_vis_enc.data() }, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<VisibleString>{}) };
const TypeDescriptor asn_DEF_GeneralString = { "GeneralString",    Tag::universal(27, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<GeneralString>{}) };
const TypeDescriptor asn_DEF_GraphicString = { "GraphicString",    Tag::universal(25, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<GraphicString>{}) };
const TypeDescriptor asn_DEF_UniversalString={ "UniversalString",  Tag::universal(28, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<UniversalString>{}) };
const TypeDescriptor asn_DEF_BmpString     = { "BMPString",        Tag::universal(30, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<BmpString>{}) };
const TypeDescriptor asn_DEF_VideotexString= { "VideotexString",   Tag::universal(21, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<VideotexString>{}) };
const TypeDescriptor asn_DEF_ObjectDescriptor={ "ObjectDescriptor",Tag::universal( 7, false), nullptr, nullptr, nullptr, nullptr, {}, false, TypeKind::Primitive, &per_string_handler,      &ber_string_handler,      TypeLifecycleOps(TypeTag<ObjectDescriptor>{}) };

} // namespace asn1
