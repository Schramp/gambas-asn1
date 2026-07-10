#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / safe_name / to_member_name / to_value_name / make_synthetic_name

namespace asn1::codegen {

/// @brief Emit a `const asn1::TypeDescriptor ... = {...};` initializer.
///        Pure C++ text formatting from already-resolved parameters — no
///        decision logic, no Generator state. Shared across every emit_*
///        family that produces a TypeDescriptor (ENUMERATED here; INTEGER/
///        SEQUENCE/CHOICE still call it from Generator.cpp until their own
///        gambas-asn1#225 migrations land). Defined in CppBackend.cpp.
/// @param use_class_scope true for types that generate a C++ class
///        (ENUMERATED, SEQUENCE, CHOICE — descriptor is `Type::asn_DEF`);
///        false for free-standing `asn_DEF_Type` (aliases).
void emit_type_descriptor(std::ostream& os,
                           const std::string& cname,
                           const std::string& xer_name,
                           const std::string& tag_expr,
                           bool has_enum, bool has_seq,
                           bool has_choice, bool has_seqof,
                           const std::string& kind,
                           const std::string& per_handler = "nullptr",
                           const std::string& ber_handler = "nullptr",
                           bool use_class_scope = false);

/// @brief Build a Constraints designated-initializer literal for an INTEGER
///        constraint. Pure C++ text formatting from already-resolved
///        parameters — shared between CppBackend::emit_integer_cpp and
///        Generator.cpp's inline-constrained-member INTEGER handling
///        (emit_member_type_descriptor, not yet migrated — SEQUENCE/CHOICE's
///        gambas-asn1#225 migration). Defined in CppBackend.cpp.
std::string make_integer_pc(int flags, int range_bits, int int_kind,
                             int64_t lower_s64, int64_t upper_s64,
                             uint64_t lower_u64, uint64_t upper_u64);

/// @brief C++ backend: the only `Backend` implementation today.
///
/// Wraps the pre-existing naming free functions (`Generator.hpp`) as the
/// `Backend` interface — no new logic, this is the seam extraction
/// (gambas-asn1#216), not a behavior change.
class CppBackend : public Backend {
public:
    std::string type_name(std::string_view asn1_name) const override {
        return to_cpp_name(asn1_name);
    }

    std::string member_name(std::string_view asn1_name,
                             std::initializer_list<std::string_view> extra = {}) const override {
        return to_member_name(asn1_name, extra);
    }

    std::string value_name(std::string_view asn1_name) const override {
        return to_value_name(asn1_name);
    }

    std::string escape(std::string name,
                        std::initializer_list<std::string_view> extra = {}) const override {
        return safe_name(std::move(name), extra);
    }

    std::string synthetic_name(const std::string& parent,
                                const std::string& member_name) const override {
        return make_synthetic_name(parent, member_name);
    }

    std::string native_int_type(IntStorageKind kind) const override {
        switch (kind) {
            case IntStorageKind::U64:       return "asn1::UInteger";
            case IntStorageKind::I128:      return "asn1::BigInteger";
            case IntStorageKind::ARBITRARY: return "asn1::ArbitraryInteger";
            default:                        return "asn1::Integer";
        }
    }

    // Defined in CppBackend.cpp — real emission logic (moved from Generator.cpp,
    // gambas-asn1#226/#227), not a one-liner like the naming methods above.
    void emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const override;
    void emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const override;
    void emit_integer_hpp(const IntegerSpec& spec, std::ostream& os) const override;
    void emit_integer_cpp(const IntegerSpec& spec, std::ostream& os) const override;
};

} // namespace asn1::codegen
