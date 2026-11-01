#include "ContainedFields.hpp"
#include <fstream>
#include <functional>
#include <sstream>
#include "../config/Json.hpp"
#include "EnumValues.hpp"
#include "Resolver.hpp"

namespace asn1::sema {

const char* to_string(ContainedText t) {
    switch (t) {
    case ContainedText::Hex:       return "hex";
    case ContainedText::Inline:    return "inline";
    case ContainedText::InlineRaw: return "inline_raw";
    }
    return "?";
}

const char* to_string(ContentsEncoding e) {
    switch (e) {
    case ContentsEncoding::Outer:        return "outer";
    case ContentsEncoding::Ber:          return "ber";
    case ContentsEncoding::Cer:          return "cer";
    case ContentsEncoding::Der:          return "der";
    case ContentsEncoding::PerAligned:   return "aper";
    case ContentsEncoding::PerUnaligned: return "per";
    case ContentsEncoding::Unknown:      return "unknown";
    }
    return "?";
}

namespace {

/// @brief Dotted-number form of a module OID (`0.4.0.2.2.5.1.42`), used to
///        match a sidecar `module_oid`; empty when an arc has no number.
std::string dotted_oid(const ast::OidValue& oid) {
    std::string s;
    for (const auto& arc : oid.arcs) {
        if (arc.number < 0) return {};
        if (!s.empty()) s += '.';
        s += std::to_string(arc.number);
    }
    return s;
}

/// @brief Contents constraint (X.682 §11) that applies to a member: its own
///        constraints first, then those along its type-reference alias chain.
/// @param scope  Set to the module the constraint is written in, which
///               scopes its type reference.
/// @return The constraint, or nullptr.
const ast::ContentsConstraint* member_contents(const ast::TypeDef& m, const std::string& mod,
                                               const Resolver& r, std::string& scope) {
    if (auto* cc = find_contents_constraint(m.constraints)) { scope = mod; return cc; }
    const ast::TypeDef* cur = &m;
    std::string cur_mod = mod;
    for (int depth = 0; depth < 64; ++depth) {
        auto* tr = std::get_if<ast::TypeRef>(&cur->body);
        if (!tr) return nullptr;
        std::string next_mod = tr->module_name.empty() ? r.module_of(tr->type_name, cur_mod) : tr->module_name;
        if (next_mod.empty()) return nullptr;
        auto def = r.resolve_in_module(tr->type_name, next_mod);
        if (!def) return nullptr;
        if (auto* cc = find_contents_constraint(def->constraints)) { scope = next_mod; return cc; }
        cur = def.get();
        cur_mod = next_mod;
    }
    return nullptr;
}

/// @brief Whether a member is an OCTET STRING, directly or through aliases.
bool is_octet_string(const ast::TypeDef& m, const std::string& mod, const Resolver& r) {
    auto base = r.follow_aliases(std::make_shared<ast::TypeDef>(m), mod);
    const ast::TypeDef* b = base ? base.get() : &m;
    auto* bt = std::get_if<ast::BuiltinType>(&b->body);
    return bt && *bt == ast::BuiltinType::OctetString;
}

/// @brief Read a sidecar `xer`/`jer` value.
std::optional<ContainedText> parse_text(const std::string& s) {
    if (s == "hex") return ContainedText::Hex;
    if (s == "inline") return ContainedText::Inline;
    if (s == "inline_raw") return ContainedText::InlineRaw;
    return std::nullopt;
}

} // namespace

bool ContainedFields::load_config(const std::string& path, std::vector<std::string>& errors) {
    config_path_ = path;
    std::ifstream in(path);
    if (!in) {
        errors.push_back("cannot open container config '" + path + "'");
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string err;
    auto doc = config::parse_json(ss.str(), err);
    if (!doc) {
        errors.push_back(path + ": " + err);
        return false;
    }
    auto where = [&](int line) { return path + ":" + std::to_string(line) + ": "; };
    if (!doc->is_object()) {
        errors.push_back(where(doc->line) + "top level must be an object");
        return false;
    }
    std::size_t before = errors.size();
    for (const auto& [k, v] : std::get<config::JsonValue::Object>(doc->v))
        if (k != "container_fields" && k != "per_nkm_size")
            errors.push_back(where(v.line) + "unknown top-level key \"" + k + "\"");
    // "per_nkm_size" is read by PerNkmSize::load_config.
    const auto* list = doc->find("container_fields");
    if (!list && doc->find("per_nkm_size")) return errors.size() == before;
    if (!list || !list->is_array()) {
        errors.push_back(where(doc->line) + "\"container_fields\" must be an array");
        return false;
    }
    for (const auto& item : std::get<config::JsonValue::Array>(list->v)) {
        if (!item.is_object()) {
            errors.push_back(where(item.line) + "each container_fields entry must be an object");
            continue;
        }
        Entry e;
        e.line = item.line;
        auto str = [&](const config::JsonValue& v, const std::string& key, std::string& out) {
            if (!v.is_string()) {
                errors.push_back(where(v.line) + "\"" + key + "\" must be a string");
                return false;
            }
            out = std::get<std::string>(v.v);
            return true;
        };
        for (const auto& [k, v] : std::get<config::JsonValue::Object>(item.v)) {
            std::string s;
            if (k == "module")                { str(v, k, e.module); }
            else if (k == "module_oid")       { str(v, k, e.module_oid); }
            else if (k == "module_name")      { str(v, k, e.module); }
            else if (k == "type")             { str(v, k, e.type); }
            else if (k == "field")            { str(v, k, e.field); }
            else if (k == "inner_type")       { str(v, k, e.inner_type); }
            else if (k == "inner_module" || k == "inner_module_name") { str(v, k, e.inner_module); }
            else if (k == "encoding") {
                if (!str(v, k, s)) continue;
                if (s == "ber") e.encoding = ContentsEncoding::Ber;
                else if (s == "der") e.encoding = ContentsEncoding::Der;
                else if (s == "cer") e.encoding = ContentsEncoding::Cer;
                else if (s == "per") e.encoding = ContentsEncoding::PerUnaligned;
                else if (s == "aper") e.encoding = ContentsEncoding::PerAligned;
                else errors.push_back(where(v.line) + "\"encoding\" must be ber, der, cer, per or aper");
            } else if (k == "decode") {
                if (!str(v, k, s)) continue;
                if (s == "eager") e.decode = ContainedDecode::Eager;
                else if (s == "off") e.decode = ContainedDecode::Off;
                else errors.push_back(where(v.line) + "\"decode\" must be eager or off");
            } else if (k == "decoder") {
                if (!str(v, k, s)) continue;
                if (s.empty()) errors.push_back(where(v.line) + "\"decoder\" must not be empty");
                else e.decoder = s;
            } else if (k == "on_error") {
                if (!str(v, k, s)) continue;
                if (s == "keep_raw") e.on_error = ContainedOnError::KeepRaw;
                else if (s == "fail") e.on_error = ContainedOnError::Fail;
                else errors.push_back(where(v.line) + "\"on_error\" must be keep_raw or fail");
            } else if (k == "xer" || k == "jer") {
                if (!str(v, k, s)) continue;
                auto t = parse_text(s);
                if (!t) errors.push_back(where(v.line) + "\"" + k + "\" must be hex, inline or inline_raw");
                else (k == "xer" ? e.xer : e.jer) = *t;
            } else if (k == "when") {
                if (!v.is_object()) {
                    errors.push_back(where(v.line) + "\"when\" must be an object {\"member\": ..., \"equals\": ...}");
                    continue;
                }
                ContainedWhen w;
                for (const auto& [wk, wv] : std::get<config::JsonValue::Object>(v.v)) {
                    if (wk == "member") str(wv, "when.member", w.member);
                    else if (wk == "equals") {
                        if (wv.is_string()) w.text = std::get<std::string>(wv.v);
                        else if (wv.is_number()) w.text = std::get<config::JsonValue::Number>(wv.v).text;
                        else if (wv.is_bool()) w.text = std::get<bool>(wv.v) ? "true" : "false";
                        else errors.push_back(where(wv.line) + "\"when.equals\" must be a string, number or boolean");
                    } else errors.push_back(where(wv.line) + "unknown key \"when." + wk + "\"");
                }
                if (w.member.empty() || w.text.empty())
                    errors.push_back(where(v.line) + "\"when\" needs both \"member\" and \"equals\"");
                else e.when = w;
            } else {
                errors.push_back(where(v.line) + "unknown key \"" + k + "\"");
            }
        }
        if (e.module.empty() && e.module_oid.empty())
            errors.push_back(where(e.line) + "entry needs \"module\" or \"module_oid\"");
        if (e.type.empty() || e.field.empty())
            errors.push_back(where(e.line) + "entry needs \"type\" and \"field\"");
        if (e.decoder == "none") { e.decoder.reset(); e.decode = ContainedDecode::Off; }
        entries_.push_back(std::move(e));
    }
    return errors.size() == before;
}

void ContainedFields::build(const ast::ParseResult& pr, const Resolver& r,
                            std::vector<std::string>& warnings, std::vector<std::string>& errors) {
    // Enclosing type and member/alternative of every contained field,
    // plus which members the configuration may target (direct members of
    // a type assignment).
    struct Site {
        const ast::Module* mod;
        const ast::TypeDef* owner;   // the SEQUENCE/SET/CHOICE holding the member
        std::string type_name;       // enclosing type assignment name
        const ast::TypeDef* member;
    };
    std::map<std::tuple<std::string, std::string, std::string>, Site> direct;

    auto add_from_constraint = [&](const Site& s) {
        std::string scope;
        const auto* cc = member_contents(*s.member, s.mod->name, r, scope);
        if (!cc) return;
        if (!is_octet_string(*s.member, s.mod->name, r)) return;  // BIT STRING contents: raw only
        std::string where = s.mod->name + "." + s.type_name + "." + s.member->name;
        auto enc = classify_encoded_by(cc->encoded_by);
        if (enc == ContentsEncoding::Unknown) return;  // Resolver already warned
        if (!cc->type) return;                          // bare ENCODED BY: no type to decode
        auto* tr = std::get_if<ast::TypeRef>(&cc->type->body);
        if (!tr || !tr->params.empty() || !tr->class_field.empty()) {
            warnings.push_back("CONTAINING on " + where
                + ": only a named contained type is decoded; contents kept as raw bytes");
            return;
        }
        std::string inner_mod = tr->module_name.empty() ? r.module_of(tr->type_name, scope) : tr->module_name;
        if (inner_mod.empty()) return;
        ContainedField f;
        f.module = s.mod->name;
        f.type = s.type_name;
        f.field = s.member->name;
        f.is_alternative = s.owner->is_choice();
        f.from_constraint = true;
        f.inner_module = inner_mod;
        f.inner_type = tr->type_name;
        f.encoding = enc;
        by_member_[s.member] = fields_.size();
        fields_.push_back(std::move(f));
    };

    std::function<void(const ast::Module&, const ast::TypeDef&, const std::string&, bool)> walk =
        [&](const ast::Module& mod, const ast::TypeDef& def, const std::string& tname, bool top) {
            if (def.is_seq_of() || def.is_set_of()) {
                const auto& el = def.is_seq_of() ? std::get<ast::SequenceOfType>(def.body).element
                                                 : std::get<ast::SetOfType>(def.body).element;
                if (el) walk(mod, *el, tname, false);
                return;
            }
            if (!def.is_sequence() && !def.is_set() && !def.is_choice()) return;
            for (const auto& m : def.members) {
                if (!m || m->is_extension_marker || m->name.empty()) continue;
                Site s{&mod, &def, tname, m.get()};
                if (top) direct[{mod.name, tname, m->name}] = s;
                add_from_constraint(s);
                walk(mod, *m, tname, false);
            }
        };
    for (const auto& mod : pr.modules)
        for (const auto& a : mod->assignments)
            if (a && !a->name.empty()) walk(*mod, *a, a->name, true);

    std::map<const ast::TypeDef*, int> configured;   // member -> entry line
    for (const auto& e : entries_) {
        auto where = config_path_ + ":" + std::to_string(e.line) + ": ";
        // Module by OID (wins) or name.
        const ast::Module* mod = nullptr;
        for (const auto& m : pr.modules) {
            if (!e.module_oid.empty() ? dotted_oid(m->oid) == e.module_oid : m->name == e.module) {
                mod = m.get();
                break;
            }
        }
        if (!mod) {
            warnings.push_back(where + "module '" + (e.module_oid.empty() ? e.module : e.module_oid)
                + "' not in this compilation; entry skipped");
            continue;
        }
        auto it = direct.find({mod->name, e.type, e.field});
        if (it == direct.end()) {
            warnings.push_back(where + "'" + mod->name + "." + e.type + "." + e.field
                + "' is not a member or alternative of a type assignment; entry skipped");
            continue;
        }
        const Site& s = it->second;
        if (auto [prev, fresh] = configured.emplace(s.member, e.line); !fresh) {
            errors.push_back(where + "'" + mod->name + "." + e.type + "." + e.field
                + "' is already configured at line " + std::to_string(prev->second));
            continue;
        }
        if (!is_octet_string(*s.member, mod->name, r)) {
            errors.push_back(where + "'" + mod->name + "." + e.type + "." + e.field
                + "' is not an OCTET STRING");
            continue;
        }
        ContainedField* f = nullptr;
        auto bm = by_member_.find(s.member);
        if (bm != by_member_.end()) {
            f = &fields_[bm->second];
        } else {
            ContainedField nf;
            nf.module = mod->name;
            nf.type = e.type;
            nf.field = e.field;
            nf.is_alternative = s.owner->is_choice();
            nf.encoding = ContentsEncoding::Ber;
            by_member_[s.member] = fields_.size();
            fields_.push_back(std::move(nf));
            f = &fields_.back();
        }
        f->from_config = true;
        std::string label = mod->name + "." + e.type + "." + e.field;

        if (!e.inner_type.empty()) {
            std::string inner_mod = e.inner_module.empty() ? r.module_of(e.inner_type, mod->name) : e.inner_module;
            if (inner_mod.empty() || !r.resolve_in_module(e.inner_type, inner_mod)) {
                errors.push_back(where + "inner type '"
                    + (e.inner_module.empty() ? "" : e.inner_module + ".") + e.inner_type
                    + "' for '" + label + "' is not defined");
                continue;
            }
            if (f->from_constraint && (f->inner_type != e.inner_type || f->inner_module != inner_mod)) {
                errors.push_back(where + "inner type " + inner_mod + "." + e.inner_type + " for '" + label
                    + "' conflicts with its CONTAINING " + f->inner_module + "." + f->inner_type);
                continue;
            }
            f->inner_module = inner_mod;
            f->inner_type = e.inner_type;
        } else if (!f->from_constraint) {
            errors.push_back(where + "'" + label + "' has no CONTAINING constraint, so \"inner_type\" is required");
            continue;
        }
        if (e.encoding) {
            if (f->from_constraint && f->encoding != ContentsEncoding::Outer && f->encoding != *e.encoding) {
                errors.push_back(where + "\"encoding\" for '" + label + "' conflicts with its ENCODED BY");
                continue;
            }
            f->encoding = *e.encoding;
        }
        if (e.decode)   f->decode = *e.decode;
        if (e.decoder)  f->decoder = *e.decoder;
        if (e.on_error) f->on_error = *e.on_error;
        if (e.xer)      f->xer = *e.xer;
        if (e.jer)      f->jer = *e.jer;
        if (e.when) {
            if (f->is_alternative) {
                errors.push_back(where + "\"when\" on CHOICE alternative '" + label
                    + "': a CHOICE has no sibling members");
                continue;
            }
            const ast::TypeDef* sib = nullptr;
            for (const auto& m : s.owner->members)
                if (m && m->name == e.when->member) sib = m.get();
            if (!sib || sib == s.member) {
                errors.push_back(where + "\"when.member\" '" + e.when->member + "' is not a sibling of '" + label + "'");
                continue;
            }
            auto base = r.follow_aliases(std::make_shared<ast::TypeDef>(*sib), mod->name);
            const ast::TypeDef* b = base ? base.get() : sib;
            auto* bt = std::get_if<ast::BuiltinType>(&b->body);
            ContainedWhen w = *e.when;
            bool ok = false;
            if (bt && *bt == ast::BuiltinType::Enumerated) {
                w.kind = ContainedWhen::Kind::Enumerated;
                auto vals = enumerated_values(b->enum_values);
                for (std::size_t i = 0; i < b->enum_values.size(); ++i)
                    if (b->enum_values[i].name == w.text) { w.value = vals[i]; ok = true; }
            } else if (bt && *bt == ast::BuiltinType::Integer) {
                w.kind = ContainedWhen::Kind::Integer;
                try {
                    std::size_t used = 0;
                    w.value = std::stoll(w.text, &used);
                    ok = used == w.text.size();
                } catch (...) {}
                if (!ok)
                    for (const auto& ev : b->enum_values)
                        if (ev.name == w.text && ev.number) { w.value = *ev.number; ok = true; }
            } else if (bt && *bt == ast::BuiltinType::Boolean) {
                w.kind = ContainedWhen::Kind::Boolean;
                if (w.text == "true" || w.text == "TRUE") { w.value = 1; ok = true; }
                if (w.text == "false" || w.text == "FALSE") { w.value = 0; ok = true; }
            } else {
                errors.push_back(where + "\"when.member\" '" + e.when->member
                    + "' must be ENUMERATED, INTEGER or BOOLEAN");
                continue;
            }
            if (!ok) {
                errors.push_back(where + "\"when.equals\" '" + w.text + "' is not a value of '"
                    + e.when->member + "'");
                continue;
            }
            f->when = w;
        }
    }
}

const ContainedField* ContainedFields::find(const ast::TypeDef* member) const {
    auto it = by_member_.find(member);
    return it == by_member_.end() ? nullptr : &fields_[it->second];
}

} // namespace asn1::sema
