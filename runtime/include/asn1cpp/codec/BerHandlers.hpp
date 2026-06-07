#pragma once
namespace asn1 {
struct IBerTypeHandler;
extern const IBerTypeHandler& ber_any_handler;
extern const IBerTypeHandler& ber_boolean_handler;
extern const IBerTypeHandler& ber_integer_handler;
extern const IBerTypeHandler& ber_uinteger_handler;
extern const IBerTypeHandler& ber_null_handler;
extern const IBerTypeHandler& ber_real_handler;
extern const IBerTypeHandler& ber_bitstring_handler;
extern const IBerTypeHandler& ber_octetstring_handler;
extern const IBerTypeHandler& ber_oid_handler;
extern const IBerTypeHandler& ber_reloid_handler;
extern const IBerTypeHandler& ber_utctime_handler;
extern const IBerTypeHandler& ber_gentime_handler;
extern const IBerTypeHandler& ber_string_handler;
extern const IBerTypeHandler& ber_enumerated_handler;
extern const IBerTypeHandler& ber_seqof_handler;
extern const IBerTypeHandler& ber_sequence_handler;
extern const IBerTypeHandler& ber_choice_handler;
} // namespace asn1
