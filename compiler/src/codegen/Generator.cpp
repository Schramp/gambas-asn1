#include "Generator.hpp"
#include <algorithm>
#include <limits>
#include "asn1cpp/Tag.hpp"

namespace asn1::codegen {

// Returns the C++ type string for a member TypeDef.
std::string Generator::cpp_type_for(const ast::TypeDef& def) {
    using BT = ast::BuiltinType;
    if (auto* bt = std::get_if<BT>(&def.body)) {
        switch (*bt) {
        case BT::Boolean:           return "asn1::Boolean";
        case BT::Integer:           return "asn1::Integer";
        case BT::Real:              return "asn1::Real";
        case BT::Null:              return "asn1::Null";
        case BT::BitString:         return "asn1::BitString";
        case BT::OctetString:       return "asn1::OctetString";
        case BT::ObjectIdentifier:  return "asn1::Oid";
        case BT::RelativeOid:       return "asn1::RelativeOid";
        case BT::Enumerated:        return to_cpp_name(def.name.empty() ? "Enum" : def.name);
        case BT::Utf8String:        return "asn1::Utf8String";
        case BT::NumericString:     return "asn1::NumericString";
        case BT::PrintableString:   return "asn1::PrintableString";
        case BT::T61String:         return "asn1::T61String";
        case BT::Ia5String:         return "asn1::Ia5String";
        case BT::VisibleString:     return "asn1::VisibleString";
        case BT::GeneralString:     return "asn1::GeneralString";
        case BT::GraphicString:     return "asn1::GraphicString";
        case BT::UniversalString:   return "asn1::UniversalString";
        case BT::BmpString:         return "asn1::BmpString";
        case BT::VideotexString:    return "asn1::VideotexString";
        case BT::ObjectDescriptor:  return "asn1::ObjectDescriptor";
        case BT::UtcTime:           return "asn1::UtcTime";
        case BT::GeneralizedTime:   return "asn1::GeneralizedTime";
        case BT::Any:               return "asn1::OctetString"; // ANY -> raw bytes
        }
    }
    if (auto* tr = std::get_if<ast::TypeRef>(&def.body))
        return to_cpp_name(tr->type_name);
    if (def.is_seq_of()) {
        const auto& sof = std::get<ast::SequenceOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_set_of()) {
        const auto& sof = std::get<ast::SetOfType>(def.body);
        return std::format("std::vector<{}>", cpp_type_for(*sof.element));
    }
    if (def.is_sequence() || def.is_choice())
        return to_cpp_name(def.name.empty() ? "Anon" : def.name);
    return "asn1::OctetString"; // fallback
}

std::string Generator::ber_tag_for(const ast::TypeDef& def) {
    // If the member has an explicit tag override, emit it
    if (def.tag.present()) {
        std::string cls;
        switch (def.tag.cls) {
        case ast::TagClass::Universal:    cls = "asn1::TagClass::Universal"; break;
        case ast::TagClass::Application:  cls = "asn1::TagClass::Application"; break;
        case ast::TagClass::Private:      cls = "asn1::TagClass::Private"; break;
        default:                          cls = "asn1::TagClass::Context"; break;
        }
        bool constr = def.is_sequence() || def.is_choice() || def.is_seq_of() || def.is_set_of();
        return std::format("asn1::Tag{{{}, {}, {}}}", cls, def.tag.number, constr ? "true" : "false");
    }
    return ""; // no override — use natural tag from BerTraits
}

void Generator::emit_struct_members(const ast::TypeDef& def, std::ostream& os) {
    for (const auto& m : def.members) {
        if (m->is_extension_marker) continue;
        std::string type = cpp_type_for(*m);
        std::string name = to_member_name(m->name);
        if (m->is_optional())
            os << std::format("    std::optional<{}> {};\n", type, name);
        else
            os << std::format("    {} {}{{}};\n", type, name);
    }
}

void Generator::emit_ber_encode(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    os << std::format("void asn1::BerTraits<{}>::encode(asn1::BerWriter& w, const {}& v) {{\n",
        cname, cname);

    if (def.is_sequence()) {
        os << std::format("    w.write_constructed(asn1::Tag::universal({}, true), [&](asn1::BerWriter& inner) {{\n",
            asn1::UniversalTag::Sequence);
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string fname = to_member_name(m->name);
            std::string mtype = cpp_type_for(*m);
            if (m->is_optional()) {
                os << std::format("        if (v.{}) asn1::BerTraits<{}>::encode(inner, *v.{});\n",
                    fname, mtype, fname);
            } else {
                os << std::format("        asn1::BerTraits<{}>::encode(inner, v.{});\n", mtype, fname);
            }
        }
        os << "    });\n";
    } else if (def.is_choice()) {
        os << "    std::visit([&](const auto& alt) {\n";
        os << "        using T = std::decay_t<decltype(alt)>;\n";
        os << "        if constexpr (!std::is_same_v<T, std::monostate>)\n";
        os << "            asn1::BerTraits<T>::encode(w, alt);\n";
        os << "    }, v.choice);\n";
    } else {
        os << "    // TODO: encode body for " << def.name << "\n";
    }
    os << "}\n\n";
}

void Generator::emit_ber_decode(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    os << std::format("asn1::Expected<{}, asn1::DecodeError> asn1::BerTraits<{}>::decode(asn1::BerReader& r) {{\n",
        cname, cname);

    if (def.is_sequence()) {
        os << std::format("    auto tlv = r.read_tlv();\n");
        os << std::format("    if (!tlv) return asn1::make_unexpected<{}, asn1::DecodeError>(tlv.error());\n", cname);
        os << std::format("    {} result{{}};\n", cname);
        os << std::format("    asn1::BerReader inner = r.sub(tlv->value);\n");
        for (const auto& m : def.members) {
            if (m->is_extension_marker) continue;
            std::string fname  = to_member_name(m->name);
            std::string mtype  = cpp_type_for(*m);
            if (m->is_optional()) {
                os << std::format("    if (!inner.at_end()) {{\n");
                os << std::format("        auto v = asn1::BerTraits<{}>::decode(inner);\n", mtype);
                os << std::format("        if (v) result.{} = std::move(*v);\n", fname);
                os << std::format("    }}\n");
            } else {
                os << std::format("    {{\n");
                os << std::format("        auto v = asn1::BerTraits<{}>::decode(inner);\n", mtype);
                os << std::format("        if (!v) return asn1::make_unexpected<{}, asn1::DecodeError>(v.error());\n", cname);
                os << std::format("        result.{} = std::move(*v);\n", fname);
                os << std::format("    }}\n");
            }
        }
        os << std::format("    return result;\n");
    } else {
        os << std::format("    return asn1::make_unexpected<{}, asn1::DecodeError>(\n", cname);
        os << std::format("        asn1::DecodeError(\"decode not yet implemented for {}\"));\n", cname);
    }
    os << "}\n\n";
}

void Generator::emit_hpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    os << "#pragma once\n";
    os << "#include <optional>\n";
    os << "#include <variant>\n";
    os << "#include <vector>\n";
    os << "#include <asn1cpp/asn1cpp.hpp>\n\n";

    if (def.is_sequence() || def.is_set_of() || def.is_seq_of()) {
        // Forward-declare referenced types
        for (const auto& m : def.members) {
            if (auto* tr = std::get_if<ast::TypeRef>(&m->body))
                os << std::format("struct {};\n", to_cpp_name(tr->type_name));
        }
        os << "\n";
    }

    if (def.is_sequence()) {
        os << std::format("struct {} {{\n", cname);
        emit_struct_members(def, os);
        os << "};\n\n";
        // Trait declaration
        os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
        os << std::format("    static asn1::Tag tag() {{ return asn1::Tag::universal({}, true); }}\n",
            asn1::UniversalTag::Sequence);
        os << std::format("    static void encode(asn1::BerWriter& w, const {}& v);\n", cname);
        os << std::format("    static asn1::Expected<{}, asn1::DecodeError> decode(asn1::BerReader& r);\n", cname);
        os << "};\n";
    } else if (def.is_choice()) {
        // CHOICE: variant + enum
        os << std::format("// CHOICE {}\n", cname);
        os << std::format("struct {} {{\n", cname);
        // present enum
        os << std::format("    enum class PR {{ NOTHING");
        for (const auto& m : def.members)
            if (!m->is_extension_marker)
                os << std::format(", {}", to_cpp_name(m->name));
        os << " } present{PR::NOTHING};\n";
        // union via variant
        os << "    std::variant<std::monostate";
        for (const auto& m : def.members)
            if (!m->is_extension_marker)
                os << std::format(", {}", cpp_type_for(*m));
        os << "> choice;\n";
        os << "};\n\n";
        os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
        os << std::format("    static asn1::Tag tag() {{ return asn1::Tag::universal({}, true); }}\n",
            asn1::UniversalTag::Sequence);
        os << std::format("    static void encode(asn1::BerWriter& w, const {}& v);\n", cname);
        os << std::format("    static asn1::Expected<{}, asn1::DecodeError> decode(asn1::BerReader& r);\n", cname);
        os << "};\n";
    } else if (def.is_seq_of() || def.is_set_of()) {
        const auto& sof = def.is_seq_of()
            ? std::get<ast::SequenceOfType>(def.body)
            : ast::SequenceOfType{std::get<ast::SetOfType>(def.body).element};
        std::string elem = cpp_type_for(*sof.element);
        os << std::format("using {} = std::vector<{}>;\n", cname, elem);
    } else if (auto* bt = std::get_if<ast::BuiltinType>(&def.body)) {
        if (*bt == ast::BuiltinType::Enumerated) {
            os << std::format("enum class {} : long {{\n", cname);
            long auto_val = 0;
            for (const auto& ev : def.enum_values) {
                long v = ev.number.value_or(auto_val);
                os << std::format("    {} = {},\n", to_cpp_name(ev.name), v);
                auto_val = v + 1;
            }
            os << "};\n\n";
            os << std::format("template<> struct asn1::BerTraits<{}> {{\n", cname);
            os << std::format("    static asn1::Tag tag() {{ return asn1::Tag::universal({}, false); }}\n",
                asn1::UniversalTag::Enumerated);
            os << std::format("    static void encode(asn1::BerWriter& w, const {}& v) {{\n", cname);
            os << std::format("        asn1::BerTraits<asn1::Integer>::encode(w, asn1::Integer{{static_cast<int64_t>(v)}});\n");
            os << "    }\n";
            os << std::format("    static asn1::Expected<{0}, asn1::DecodeError> decode(asn1::BerReader& r) {{\n", cname);
            os << "        auto v = asn1::BerTraits<asn1::Integer>::decode(r);\n";
            os << std::format("        if (!v) return asn1::make_unexpected<{}, asn1::DecodeError>(v.error());\n", cname);
            os << std::format("        return static_cast<{}>(v->value());\n", cname);
            os << "    }\n};\n";
        } else if (*bt == ast::BuiltinType::Integer && !def.enum_values.empty()) {
            // INTEGER with named values
            os << std::format("// INTEGER {} with named values\n", cname);
            os << std::format("using {} = asn1::Integer;\n", cname);
            for (const auto& ev : def.enum_values) {
                os << std::format("inline constexpr int64_t {}_{} = {};\n",
                    cname, to_cpp_name(ev.name), ev.number.value_or(-1));
            }
        } else {
            // Simple alias to runtime type
            os << std::format("using {} = {};\n", cname, cpp_type_for(def));
        }
    } else if (auto* tr = std::get_if<ast::TypeRef>(&def.body)) {
        os << std::format("using {} = {};\n", cname, to_cpp_name(tr->type_name));
    }
}

void Generator::emit_cpp(const ast::TypeDef& def, std::ostream& os) {
    std::string cname = to_cpp_name(def.name);
    std::string hname = cname + ".hpp";
    os << std::format("#include \"{}\"\n\n", hname);

    if (def.is_sequence()) {
        emit_ber_encode(def, os);
        emit_ber_decode(def, os);
    } else if (def.is_choice()) {
        emit_ber_encode(def, os);
        emit_ber_decode(def, os);
    }
}

void Generator::generate_type(const ast::TypeDef& def, const std::string& /*module_name*/) {
    std::string cname = to_cpp_name(def.name);
    {
        std::ofstream hpp(out_dir_ / (cname + ".hpp"));
        emit_hpp(def, hpp);
    }
    // Only emit a .cpp for types that need out-of-line method bodies
    if (def.is_sequence() || def.is_choice()) {
        std::ofstream cpp(out_dir_ / (cname + ".cpp"));
        emit_cpp(def, cpp);
    }
}

} // namespace asn1::codegen
