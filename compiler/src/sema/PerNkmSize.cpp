#include "PerNkmSize.hpp"
#include <fstream>
#include <functional>
#include <sstream>
#include "../config/Json.hpp"
#include "Resolver.hpp"

namespace asn1::sema {

const char* to_string(NkmSizeMode m) {
    return m == NkmSizeMode::Visible ? "visible" : "strict";
}

bool parse_nkm_size_mode(const std::string& s, NkmSizeMode& out) {
    if (s == "strict")  { out = NkmSizeMode::Strict;  return true; }
    if (s == "visible") { out = NkmSizeMode::Visible; return true; }
    return false;
}

bool is_non_known_multiplier(ast::BuiltinType bt) {
    using B = ast::BuiltinType;
    switch (bt) {
    case B::Utf8String: case B::T61String: case B::VideotexString:
    case B::GraphicString: case B::GeneralString: case B::ObjectDescriptor:
        return true;
    default:
        return false;
    }
}

namespace {

/// @brief Whether a constraint tree contains a SIZE constraint (top level or
///        inside an intersection, the forms codegen reads a SIZE from).
bool has_size(const ast::Constraint& c) {
    if (std::holds_alternative<ast::SizeConstraint>(c.body)) return true;
    if (auto* ic = std::get_if<ast::IntersectionConstraint>(&c.body))
        for (const auto& op : ic->operands)
            if (op && has_size(*op)) return true;
    return false;
}

bool has_size(const ast::TypeDef& def) {
    for (const auto& c : def.constraints)
        if (c && has_size(*c)) return true;
    return false;
}

} // namespace

bool PerNkmSize::load_config(const std::string& path, std::vector<std::string>& errors) {
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
    if (!doc->is_object()) return true;  // reported by ContainedFields::load_config
    const auto* list = doc->find("per_nkm_size");
    if (!list) return true;
    if (!list->is_array()) {
        errors.push_back(where(list->line) + "\"per_nkm_size\" must be an array");
        return false;
    }
    std::size_t before = errors.size();
    for (const auto& item : std::get<config::JsonValue::Array>(list->v)) {
        if (!item.is_object()) {
            errors.push_back(where(item.line) + "each per_nkm_size entry must be an object");
            continue;
        }
        Entry e;
        e.line = item.line;
        bool have_mode = false;
        for (const auto& [k, v] : std::get<config::JsonValue::Object>(item.v)) {
            if (!v.is_string()) {
                errors.push_back(where(v.line) + "\"" + k + "\" must be a string");
                continue;
            }
            const auto& s = std::get<std::string>(v.v);
            if (k == "module" || k == "module_name") e.module = s;
            else if (k == "type")  e.type = s;
            else if (k == "field") e.field = s;
            else if (k == "mode") {
                if (parse_nkm_size_mode(s, e.mode)) have_mode = true;
                else errors.push_back(where(v.line) + "\"mode\" must be strict or visible");
            } else {
                errors.push_back(where(v.line) + "unknown key \"" + k + "\" in per_nkm_size entry");
            }
        }
        if (e.module.empty() || e.type.empty())
            errors.push_back(where(e.line) + "per_nkm_size entry needs \"module\" and \"type\"");
        if (!have_mode)
            errors.push_back(where(e.line) + "per_nkm_size entry needs \"mode\"");
        entries_.push_back(std::move(e));
    }
    return errors.size() == before;
}

void PerNkmSize::build(const ast::ParseResult& pr, const Resolver& r,
                       std::vector<std::string>& warnings, std::vector<std::string>& errors) {
    // Every member, alternative and element below a type assignment, with
    // its dotted path; type assignments by (module, name).
    struct Node {
        const ast::Module* mod;
        std::string type;
        std::string path;
        const ast::TypeDef* def;
    };
    std::vector<Node> nodes;
    std::map<std::tuple<std::string, std::string>, const ast::TypeDef*> types;
    std::function<void(const ast::Module&, const ast::TypeDef&, const std::string&, const std::string&)> walk =
        [&](const ast::Module& mod, const ast::TypeDef& def, const std::string& type, const std::string& path) {
            if (def.is_seq_of() || def.is_set_of()) {
                const auto& el = def.is_seq_of() ? std::get<ast::SequenceOfType>(def.body).element
                                                 : std::get<ast::SetOfType>(def.body).element;
                if (el) {
                    nodes.push_back({&mod, type, path + ".*", el.get()});
                    walk(mod, *el, type, path + ".*");
                }
                return;
            }
            if (!def.is_sequence() && !def.is_set() && !def.is_choice()) return;
            for (const auto& m : def.members) {
                if (!m || m->is_extension_marker || m->name.empty()) continue;
                std::string p = path + "." + m->name;
                nodes.push_back({&mod, type, p, m.get()});
                walk(mod, *m, type, p);
            }
        };
    for (const auto& mod : pr.modules)
        for (const auto& a : mod->assignments)
            if (a && !a->name.empty() && !a->is_parameterized) {
                types[{mod->name, a->name}] = a.get();
                walk(*mod, *a, a->name, a->name);
            }

    std::map<const ast::TypeDef*, Source> field_source;
    std::map<std::tuple<std::string, std::string>, int> type_line;
    std::map<std::tuple<std::string, std::string, std::string>, int> field_line;
    for (const auto& e : entries_) {
        auto where = config_path_ + ":" + std::to_string(e.line) + ": ";
        std::string label = e.module + "." + e.type + (e.field.empty() ? "" : "." + e.field);
        if (!types.count({e.module, e.type})) {
            warnings.push_back(where + "per_nkm_size: '" + e.module + "." + e.type
                + "' is not a type assignment in this compilation; entry skipped");
            continue;
        }
        if (e.field.empty()) {
            if (auto [prev, fresh] = type_line.emplace(std::tuple{e.module, e.type}, e.line); !fresh) {
                errors.push_back(where + "per_nkm_size: '" + label + "' is already configured at line "
                    + std::to_string(prev->second));
                continue;
            }
            by_type_[{e.module, e.type}] = e.mode;
            continue;
        }
        if (auto [prev, fresh] = field_line.emplace(std::tuple{e.module, e.type, e.field}, e.line); !fresh) {
            errors.push_back(where + "per_nkm_size: '" + label + "' is already configured at line "
                + std::to_string(prev->second));
            continue;
        }
        const Node* hit = nullptr;
        for (const auto& n : nodes)
            if (n.mod->name == e.module && n.path == e.type + "." + e.field) { hit = &n; break; }
        if (!hit) {
            warnings.push_back(where + "per_nkm_size: '" + label
                + "' is not a member, alternative or element path; entry skipped");
            continue;
        }
        by_member_[hit->def] = e.mode;
        field_source[hit->def] = Source::Config;
    }
    // A type entry covers every node below that type the field entries left.
    for (const auto& n : nodes) {
        if (by_member_.count(n.def)) continue;
        auto it = by_type_.find({n.mod->name, n.type});
        if (it == by_type_.end()) continue;
        by_member_[n.def] = it->second;
        field_source[n.def] = Source::Config;
    }

    auto add_site = [&](const ast::Module& mod, const std::string& path, ast::BuiltinType bt,
                        NkmSizeMode m, Source s) {
        sites_.push_back({mod.name, path, builtin_type_name(bt), m, s});
    };
    for (const auto& mod : pr.modules)
        for (const auto& a : mod->assignments) {
            if (!a || a->name.empty() || a->is_parameterized || !has_size(*a)) continue;
            auto base = r.follow_aliases(a, mod->name);
            const ast::TypeDef* b = base ? base.get() : a.get();
            auto* bt = std::get_if<ast::BuiltinType>(&b->body);
            if (!bt || !is_non_known_multiplier(*bt)) continue;
            bool cfg = by_type_.count({mod->name, a->name});
            add_site(*mod, a->name, *bt, mode_for(mod->name, a->name), cfg ? Source::Config : Source::Default);
        }
    for (const auto& n : nodes) {
        auto* bt = std::get_if<ast::BuiltinType>(&n.def->body);
        if (!bt || !is_non_known_multiplier(*bt) || !has_size(*n.def)) continue;
        add_site(*n.mod, n.path, *bt, mode_for(n.def),
                 field_source.count(n.def) ? Source::Config : Source::Default);
    }
}

NkmSizeMode PerNkmSize::mode_for(const ast::TypeDef* member) const {
    auto it = by_member_.find(member);
    return it == by_member_.end() ? default_ : it->second;
}

NkmSizeMode PerNkmSize::mode_for(const std::string& module, const std::string& type) const {
    auto it = by_type_.find({module, type});
    return it == by_type_.end() ? default_ : it->second;
}

} // namespace asn1::sema
