#pragma once
#include "Backend.hpp"
#include "Generator.hpp"  // to_cpp_name / safe_name / to_member_name / to_value_name / make_synthetic_name

namespace asn1::codegen {

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
};

} // namespace asn1::codegen
