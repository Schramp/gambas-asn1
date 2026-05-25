#pragma once
// Extern references to the per-type PER handler singletons defined in PerCodec.cpp.
// Include in generated .cpp files to fill TypeDescriptor::per_handler.

namespace asn1 {
struct IPerTypeHandler;
extern const IPerTypeHandler& per_any_handler;
extern const IPerTypeHandler& per_boolean_handler;
extern const IPerTypeHandler& per_integer_handler;
extern const IPerTypeHandler& per_uinteger_handler;
extern const IPerTypeHandler& per_null_handler;
extern const IPerTypeHandler& per_real_handler;
extern const IPerTypeHandler& per_bitstring_handler;
extern const IPerTypeHandler& per_octetstring_handler;
extern const IPerTypeHandler& per_oid_handler;
extern const IPerTypeHandler& per_reloid_handler;
extern const IPerTypeHandler& per_string_handler;
extern const IPerTypeHandler& per_enumerated_handler;
extern const IPerTypeHandler& per_seqof_handler;
extern const IPerTypeHandler& per_sequence_handler;
extern const IPerTypeHandler& per_choice_handler;
} // namespace asn1
