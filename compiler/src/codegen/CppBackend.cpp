#include "CppBackend.hpp"
#include "asn1cpp/Tag.hpp"
#include <algorithm>

namespace asn1::codegen {

// Moved verbatim from Generator.cpp (was `static`, file-local) —
// gambas-asn1#226. No behavior change: same parameters, same output.
void emit_type_descriptor(std::ostream& os,
                           const std::string& cname,
                           const std::string& xer_name,
                           const std::string& tag_expr,
                           bool has_enum, bool has_seq,
                           bool has_choice, bool has_seqof,
                           const std::string& kind,
                           const std::string& per_handler,
                           const std::string& ber_handler,
                           bool use_class_scope) {
    auto sp = [&](bool h) -> std::string {
        if (!h) return "nullptr";
        return use_class_scope ? std::format("&{}::asn_SPC", cname)
                               : std::format("&asn_SPC_{}", cname);
    };
    if (use_class_scope)
        os << std::format("const asn1::TypeDescriptor {}::asn_DEF = {{\n", cname);
    else
        os << std::format("const asn1::TypeDescriptor asn_DEF_{} = {{\n", cname);
    os << std::format("    \"{}\",\n", xer_name);
    os << std::format("    {},\n", tag_expr);
    os << std::format("    {}, {}, {}, {}, {{}} /* constraints */,\n",
                      sp(has_enum), sp(has_seq), sp(has_choice), sp(has_seqof));
    os << std::format("    false, {} /* kind */,\n", kind);
    os << std::format("    {} /* per_handler */,\n", per_handler);
    os << std::format("    {} /* ber_handler */,\n", ber_handler);
    os << std::format("    asn1::TypeLifecycleOps(asn1::TypeTag<{}>{{}}) /* lifecycle */\n", cname);
    os << "};\n\n";
}

// Moved from Generator::emit_enumerated_hpp (gambas-asn1#226) — same output,
// now driven by the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
void CppBackend::emit_enumerated_hpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // class inheriting EnumValue — plain inner enum so values leak into class scope
    os << std::format("class {} : public asn1::EnumValue {{\npublic:\n", cname);
    // Enum values are plain enum (not enum class) — they inject into class scope.
    // Reserve all generated method names so values can't clash with them.
    os << "    enum Enm : long {\n";
    for (const auto& v : spec.values) {
        os << std::format("        {} = {},\n",
            escape(type_name(v.asn1_name), {"present", "value_", "value", "set", "Enm"}),
            v.value);
    }
    if (spec.extensible)
        os << "        /* extensible */\n";
    os << "    };\n";
    os << std::format("    {}() = default;\n", cname);
    os << std::format("    {}(Enm v) {{ value_ = static_cast<long>(v); }}\n", cname);
    os << std::format("    {}& operator=(Enm v) {{ value_ = static_cast<long>(v); return *this; }}\n", cname);
    os << std::format("    Enm present() const {{ return static_cast<Enm>(value_); }}\n");
    os << std::format("    bool operator==(Enm v) const {{ return value_ == static_cast<long>(v); }}\n");
    os << std::format("    bool operator!=(Enm v) const {{ return value_ != static_cast<long>(v); }}\n");
    os << "    using asn1::EnumValue::operator==;\n";
    os << "    using asn1::EnumValue::operator!=;\n";
    os << std::format("    static const asn1::EnumEntry    asn_MAP_value2enum[{}];\n",
                       static_cast<int>(spec.values.size()));
    os << "    static const asn1::EnumSpec     asn_SPC;\n";
    os << "    static const asn1::TypeDescriptor asn_DEF;\n";
    os << "};\n\n";
}

// Moved from Generator::emit_enumerated_cpp (gambas-asn1#226) — same output,
// now driven by the backend-agnostic EnumeratedSpec instead of ast::TypeDef.
void CppBackend::emit_enumerated_cpp(const EnumeratedSpec& spec, std::ostream& os) const {
    const std::string& cname = spec.type_name;

    // value2enum table (sorted by value for binary search)
    auto sorted = spec.values;
    std::sort(sorted.begin(), sorted.end(),
              [](const EnumeratedSpec::Value& a, const EnumeratedSpec::Value& b) {
                  return a.value < b.value;
              });

    os << std::format("const asn1::EnumEntry {}::asn_MAP_value2enum[] = {{\n", cname);
    for (const auto& v : sorted)
        os << std::format("    {{ {}, \"{}\" }},\n", v.value, v.asn1_name);
    os << "};\n\n";

    // PER: root values in definition order (ordinal -> value mapping). File-local — not in header.
    os << std::format("static const long asn_PER_{}_value_order[] = {{\n", cname);
    for (int i = 0; i < spec.root_count; ++i)
        os << std::format("    {},\n", spec.values[i].value);
    os << "};\n\n";

    // EnumSpec
    os << std::format("const asn1::EnumSpec {}::asn_SPC = {{\n", cname);
    os << std::format("    {}::asn_MAP_value2enum,\n", cname);
    os << std::format("    {},\n", static_cast<int>(sorted.size()));
    os << std::format("    {}, /* extensible */\n", spec.extensible ? "true" : "false");
    os << std::format("    {}, /* root_count */\n", spec.root_count);
    os << std::format("    asn_PER_{}_value_order\n", cname);
    os << "};\n\n";

    // TypeDescriptor
    emit_type_descriptor(os, cname, spec.xer_name,
        std::format("asn1::Tag::universal({}, false)", asn1::UniversalTag::Enumerated),
        true, false, false, false, "asn1::TypeKind::Enumerated",
        "&asn1::per_enumerated_handler", "&asn1::ber_enumerated_handler",
        /*use_class_scope=*/true);
}

} // namespace asn1::codegen
