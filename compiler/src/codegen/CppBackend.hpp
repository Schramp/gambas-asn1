#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / safe_name / to_member_name / to_value_name / make_synthetic_name

namespace asn1::codegen {

/// @brief Format a tag decision as a C++ `asn1::Tag{...}` literal string.
/// @param tag_spec The decision to format (class, number, encoding form).
/// @return A C++ expression string, e.g. `"asn1::Tag{asn1::TagClass::Context, 1, false}"`.
/// @note Shared by Generator::tag_literal/natural_tag_for (not yet
///       migrated — used throughout SEQUENCE/CHOICE emission) and
///       CppBackend::emit_builtin_alias_definition. Defined in CppBackend.cpp.
std::string format_tag_literal(const TagSpec& tag_spec);

/// @brief Returns the name of the global `asn_DEF_*` descriptor for a
///        restricted built-in string type, or nullptr for types without a
///        fixed alphabet (UTF8String, etc.). Pure text lookup — shared
///        between CppBackend::make_string_constraints_init's helpers and
///        Generator.cpp's emit_member_type_descriptor. Defined in
///        CppBackend.cpp.
/// @see X.680 §41 — restricted character string types and their canonical alphabets.
const char* builtin_def_name(ast::BuiltinType bt);

/// @brief Emit static FROM-alphabet lookup tables (decode + encode arrays)
///        into a generated `.cpp` file. Pure C++ text formatting — shared
///        between CppBackend::emit_builtin_alias_definition and Generator.cpp's
///        inline-constrained-member handling (emit_member_type_descriptor).
///        Defined in CppBackend.cpp.
/// @param prefix   Name prefix for the static arrays (e.g. `"asn_FROM_MyStr"`).
/// @param alphabet Sorted FROM-alphabet character values (non-empty).
void emit_from_alphabet_arrays(std::ostream& os, const std::string& prefix,
                                const std::vector<uint8_t>& alphabet);

/// @brief Build a `Constraints` aggregate-initializer string for a
///        character string type. Pure C++ text formatting — shared between
///        CppBackend::emit_builtin_alias_definition and Generator.cpp's
///        inline-constrained-member handling (emit_member_type_descriptor).
///        Defined in CppBackend.cpp.
/// @see The original Generator::make_string_constraints_init docs (moved
///      here) for the parameter-by-parameter contract — unchanged.
std::string make_string_constraints_init(
    int flags, int sc_range_bits, int64_t sc_lower, int64_t sc_upper,
    const std::vector<uint8_t>& alphabet,
    const std::string& alpha_prefix = "",
    std::optional<ast::BuiltinType> builtin_bt = std::nullopt);

/// @brief Emit a `const asn1::TypeDescriptor ... = {...};` initializer.
///        Pure C++ text formatting from already-resolved parameters — no
///        decision logic, no Generator state. Used by CppBackend's
///        ENUMERATED emission here; SEQUENCE/CHOICE still call it from
///        Generator.cpp (INTEGER hand-rolls its own — see
///        CppBackend::emit_integer_definition's note). Defined in CppBackend.cpp.
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
///        parameters — shared between CppBackend::emit_integer_definition and
///        Generator.cpp's inline-constrained-member INTEGER handling
///        (emit_member_type_descriptor). Defined in CppBackend.cpp.
std::string make_integer_pc(int flags, int range_bits, int int_kind,
                             int64_t lower_s64, int64_t upper_s64,
                             uint64_t lower_u64, uint64_t upper_u64);

/// @brief C++ backend: the only `Backend` implementation today.
///
/// Wraps the pre-existing naming free functions (`Generator.hpp`) as the
/// `Backend` interface.
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

    // Defined in CppBackend.cpp — real emission logic, not a one-liner
    // like the naming methods above.
    void emit_enumerated(const EnumeratedSpec& spec, TypeOutputSession& session) const override;
    void emit_integer(const IntegerSpec& spec, TypeOutputSession& session) const override;
    void emit_builtin_alias(const BuiltinAliasSpec& spec, TypeOutputSession& session) const override;
    void emit_default_setter(const DefaultValueSpec& spec, const std::string& type_name,
                              const std::string& parent_name, const std::string& member_name,
                              TypeOutputSession& session) const override;
    void emit_member_type_descriptor(const MemberTypeDescriptorSpec& spec, TypeOutputSession& session) const override;
    void emit_seq_of(const SeqOfSpec& spec, TypeOutputSession& session) const override;
    void emit_sequence(const SequenceSpec& spec, TypeOutputSession& session) const override;
    void emit_choice(const ChoiceSpec& spec, TypeOutputSession& session) const override;
    void emit_declaration_preamble(const std::string& module_comment, TypeOutputSession& session) const override;
    void emit_definition_preamble(const std::string& declaration_filename, TypeOutputSession& session) const override;
    void emit_namespace_open(const std::string& name, TypeOutputSession& session) const override;
    void emit_namespace_close(const std::string& name, TypeOutputSession& session) const override;
    void emit_typeref_alias_declaration(const std::string& type_name, const std::string& target_type,
                                 TypeOutputSession& session) const override;
    void emit_type_reference(const std::string& type_name, const std::string& filename,
                              TypeOutputSession& session) const override;
    void emit_forward_declaration(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_special_members(const std::string& type_name, TypeOutputSession& session) const override;
    void emit_optional_member_ops(const std::string& type_name, const std::string& member_name,
                                   const std::string& member_type, TypeOutputSession& session) const override;

    std::string declaration_extension() const override { return "hpp"; }
    std::string definition_extension() const override { return "cpp"; }

private:
    // Split declaration/definition halves — kept as private helpers so the
    // (substantial) per-construct emission bodies don't need reshaping;
    // the public emit_* overrides above just call both in sequence
    // (gambas-asn1#265: combine the pair into one call taking both streams).
    void emit_enumerated_declaration(const EnumeratedSpec& spec, std::ostream& os) const;
    void emit_enumerated_definition(const EnumeratedSpec& spec, std::ostream& os) const;
    void emit_integer_declaration(const IntegerSpec& spec, std::ostream& os) const;
    void emit_integer_definition(const IntegerSpec& spec, std::ostream& os) const;
    void emit_builtin_alias_declaration(const BuiltinAliasSpec& spec, std::ostream& os) const;
    void emit_builtin_alias_definition(const BuiltinAliasSpec& spec, std::ostream& os) const;
    void emit_seq_of_declaration(const SeqOfSpec& spec, std::ostream& os) const;
    void emit_seq_of_definition(const SeqOfSpec& spec, std::ostream& os) const;
    void emit_sequence_declaration(const SequenceSpec& spec, std::ostream& os) const;
    void emit_sequence_definition(const SequenceSpec& spec, std::ostream& os) const;
    void emit_choice_declaration(const ChoiceSpec& spec, std::ostream& os) const;
    void emit_choice_definition(const ChoiceSpec& spec, std::ostream& os) const;
};

} // namespace asn1::codegen
