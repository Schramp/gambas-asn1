#include "asn1cpp/TableDump.hpp"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>
#include "asn1cpp/types/Containing.hpp"

namespace asn1 {

namespace {

/// @brief JSON string literal for @p s (RFC 8259 §7 escapes).
std::string jstr(const char* s) {
    std::string out = "\"";
    for (const char* p = s ? s : ""; *p; ++p) {
        unsigned char c = static_cast<unsigned char>(*p);
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04X", c); out += b; }
        else out += static_cast<char>(c);
    }
    return out + "\"";
}

const char* class_name(TagClass c) {
    switch (c) {
    case TagClass::Universal:   return "UNIVERSAL";
    case TagClass::Application: return "APPLICATION";
    case TagClass::Context:     return "CONTEXT";
    case TagClass::Private:     return "PRIVATE";
    }
    return "?";
}

std::string jtag(const Tag& t) {
    return std::string("{\"class\":\"") + class_name(t.cls) + "\",\"number\":" + std::to_string(t.number)
         + ",\"constructed\":" + (t.constructed ? "true" : "false") + "}";
}

/// @brief The builtin's universal tag: \c natural_tag when the type
///        assignment carries its own tag, else \c tag (X.680 §31.2).
Tag builtin_tag_of(const TypeDescriptor& d) {
    if (d.natural_tag.cls != TagClass::Universal || d.natural_tag.number != 0) return d.natural_tag;
    return d.tag;
}

/// @brief Canonical kind name: the builtin's X.693 element name for a
///        primitive (X.680 §8 Table 1 universal tag numbers), else the construct.
std::string kind_of(const TypeDescriptor& d) {
    switch (d.kind) {
    case TypeKind::Any:        return "ANY";
    case TypeKind::Enumerated: return "ENUMERATED";
    case TypeKind::Sequence:   return d.sequence_spec && d.sequence_spec->is_set ? "SET" : "SEQUENCE";
    case TypeKind::Choice:     return "CHOICE";
    case TypeKind::SeqOf:      return builtin_tag_of(d).number == 17 ? "SET_OF" : "SEQUENCE_OF";
    case TypeKind::Primitive:  break;
    }
    if (d.is_any) return "ANY";
    switch (builtin_tag_of(d).number) {
    case 1:  return "BOOLEAN";
    case 2:  return "INTEGER";
    case 3:  return "BIT_STRING";
    case 4:  return "OCTET_STRING";
    case 5:  return "NULL";
    case 6:  return "OBJECT_IDENTIFIER";
    case 7:  return "ObjectDescriptor";
    case 9:  return "REAL";
    case 12: return "UTF8String";
    case 13: return "RELATIVE_OID";
    case 18: return "NumericString";
    case 19: return "PrintableString";
    case 20: return "T61String";
    case 21: return "VideotexString";
    case 22: return "IA5String";
    case 23: return "UTCTime";
    case 24: return "GeneralizedTime";
    case 25: return "GraphicString";
    case 26: return "VisibleString";
    case 27: return "GeneralString";
    case 28: return "UniversalString";
    case 30: return "BMPString";
    default: return "UNIVERSAL_" + std::to_string(builtin_tag_of(d).number);
    }
}

/// @brief The constraint fields that carry meaning, so two runtimes that
///        leave unused fields at different values still dump alike:
///        - the value bounds of the INTEGER storage in use (signed or
///          unsigned, \c int_kind), and only when there is a bound at all;
///        - \c range_bits only for a finite range (X.691 §10.5);
///        - the upper SIZE bound only for a finite SIZE range;
///        - the permitted alphabet only with a FROM constraint (X.691 §26.5.4).
std::string jconstraints(const Constraints& c) {
    std::string a;
    for (int i = 0; c.alphabet_bits && i < c.alphabet_size && c.alphabet; ++i) {
        char b[4]; std::snprintf(b, sizeof b, "%02X", c.alphabet[i]); a += b;
    }
    bool bounded = c.flags & (Constraints::CONSTRAINED | Constraints::SEMI_CONSTRAINED);
    bool u64 = c.int_kind == Constraints::INT_U64;
    std::string lower = !bounded ? "null" : u64 ? std::to_string(c.lower_u64) : std::to_string(c.lower_bound);
    std::string upper = !(c.flags & Constraints::CONSTRAINED) ? "null"
                      : u64 ? std::to_string(c.upper_u64) : std::to_string(c.upper_bound);
    return "{\"flags\":" + std::to_string(c.flags)
         + ",\"range_bits\":" + ((c.flags & Constraints::CONSTRAINED) ? std::to_string(c.range_bits) : "null")
         + ",\"lower\":" + lower + ",\"upper\":" + upper
         + ",\"size_range_bits\":" + std::to_string(c.size_range_bits)
         + ",\"size_lower\":" + std::to_string(c.size_lower)
         + ",\"size_upper\":" + ((c.flags & Constraints::SIZE_CONSTRAINED) ? std::to_string(c.size_upper) : "null")
         + ",\"alphabet_bits\":" + std::to_string(c.alphabet_bits) + ",\"alphabet\":\"" + a + "\"}";
}

const char* xer_name(XerEncoding e) {
    switch (e) {
    case XerEncoding::Base64: return "BASE64";
    case XerEncoding::Utf8:   return "UTF8";
    default:                  return "DEFAULT";
    }
}

/// @brief A type's own constraints: for a SEQUENCE OF / SET OF its SIZE,
///        kept in the SeqOfSpec (X.680 §51.5).
const Constraints& own_constraints(const TypeDescriptor& t) {
    return t.seq_of_spec ? t.seq_of_spec->size_constraints : t.constraints;
}

/// @brief True for a CHOICE with no tag of its own: a tagged CHOICE is
///        always EXPLICIT (X.680 §31.2.7).
bool untagged_choice(const TypeDescriptor* t) {
    return t && t->kind == TypeKind::Choice && !t->is_explicit;
}

/// @brief One member or alternative row. Tagging: a row that restates the
///        referenced type's own tag frames nothing itself (NONE), an
///        untagged CHOICE has no tag to restate (UNTAGGED_CHOICE), and an
///        override is EXPLICIT or IMPLICIT (X.680 §31.2).
std::string jmember(const MemberDescriptor& m) {
    const TypeDescriptor* t = m.type_descriptor;
    bool no_tag = !m.tag_is_override && untagged_choice(t);
    const char* tagging = no_tag ? "UNTAGGED_CHOICE" : !m.tag_is_override ? "NONE" : m.is_explicit ? "EXPLICIT" : "IMPLICIT";
    return "{\"name\":" + jstr(m.name) + ",\"tag\":" + (no_tag ? std::string("null") : jtag(m.tag)) + ",\"tagging\":\"" + tagging
         + "\",\"optional\":" + (m.optional ? "true" : "false")
         + ",\"has_default\":" + (m.set_default ? "true" : "false")
         + ",\"constraints\":" + (t ? jconstraints(own_constraints(*t)) : "null")
         + ",\"xer_instruction\":\"" + (t ? xer_name(t->xer_encoding) : "DEFAULT")
         + "\",\"contained\":" + (t && t->contained ? "true" : "false") + "}";
}

std::string jmembers(const MemberDescriptor* m, int n) {
    std::string out = "[";
    for (int i = 0; i < n; ++i) out += (i ? "," : "") + jmember(m[i]);
    return out + "]";
}

} // namespace

void dump_tables(const TypeDescriptor& d, std::ostream& os) {
    std::string kind = kind_of(d);
    std::string out = "{\"name\":" + jstr(d.name) + ",\"kind\":\"" + kind + "\"";
    // A CHOICE has no tag of its own unless the type assignment gives it
    // one, and that tag is always EXPLICIT (X.680 §31.2.7).
    if (untagged_choice(&d)) out += ",\"tag\":null";
    else out += ",\"tag\":" + jtag(d.tag);
    out += ",\"constraints\":" + jconstraints(own_constraints(d));

    if (const SequenceSpec* s = d.sequence_spec) {
        out += ",\"ext_at\":" + std::to_string(s->ext_at) + ",\"roms_count\":" + std::to_string(s->roms_count)
             + ",\"members\":" + jmembers(s->members, s->count);
        out += ",\"ext_units\":[";
        for (int i = 0; i < s->ext_unit_count; ++i)
            out += std::string(i ? "," : "") + "{\"end\":" + std::to_string(s->ext_unit_end[i])
                 + ",\"group\":" + (s->ext_unit_group[i] ? "true" : "false") + "}";
        out += "],\"contained_members\":[";
        for (int i = 0; i < s->contained_count; ++i)
            out += (i ? "," : "") + std::to_string(s->contained_members[i]);
        out += "]";
    }
    if (const ChoiceSpec* c = d.choice_spec) {
        std::vector<std::pair<Tag, int>> tags;
        if (c->ber_tags)
            for (int i = 0; i < c->ber_tag_count; ++i) tags.emplace_back(c->ber_tags[i].tag, c->ber_tags[i].alt_index);
        else
            for (int i = 0; i < c->count; ++i) tags.emplace_back(c->alternatives[i].tag, i);
        std::sort(tags.begin(), tags.end(), [](const auto& a, const auto& b) {
            return std::pair(a.first.cls, a.first.number) < std::pair(b.first.cls, b.first.number);
        });
        out += ",\"ext_at\":" + std::to_string(c->ext_at) + ",\"range_bits\":" + std::to_string(c->constraints.range_bits)
             + ",\"alternatives\":" + jmembers(c->alternatives, c->count) + ",\"ber_tags\":[";
        for (std::size_t i = 0; i < tags.size(); ++i)
            out += std::string(i ? "," : "") + "{\"tag\":" + jtag(tags[i].first) + ",\"alt\":" + std::to_string(tags[i].second) + "}";
        out += "]";
    }
    if (const SeqOfSpec* q = d.seq_of_spec) {
        out += ",\"element_xer_tag\":" + (q->element_xer_tag ? jstr(q->element_xer_tag) : "null")
             + ",\"element\":" + (q->element ? "{\"kind\":\"" + kind_of(*q->element) + "\",\"constraints\":"
                                                + jconstraints(q->element->constraints) + "}" : "null");
    }
    if (const EnumSpec* e = d.enum_spec) {
        out += std::string(",\"extensible\":") + (e->extensible ? "true" : "false")
             + ",\"root_count\":" + std::to_string(e->root_count) + ",\"entries\":[";
        for (int i = 0; i < e->count; ++i)
            out += std::string(i ? "," : "") + "{\"value\":" + std::to_string(e->entries[i].value)
                 + ",\"name\":" + jstr(e->entries[i].name) + "}";
        out += "],\"per_value_order\":[";
        for (int i = 0; i < e->root_count && e->per_value_order; ++i)
            out += (i ? "," : "") + std::to_string(e->per_value_order[i]);
        out += "]";
    }
    os << out << "}\n";
}

} // namespace asn1
