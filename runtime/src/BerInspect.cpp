#include <asn1cpp/codec/BerInspect.hpp>
#include <asn1cpp/codec/BerCursor.hpp>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

namespace asn1 {

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string tag_to_str(Tag t)
{
    char buf[32];
    switch (t.cls) {
    case TagClass::Context:
        std::snprintf(buf, sizeof(buf), "[%u]", t.number);
        break;
    case TagClass::Universal:
        std::snprintf(buf, sizeof(buf), "U[%u]", t.number);
        break;
    case TagClass::Application:
        std::snprintf(buf, sizeof(buf), "A[%u]", t.number);
        break;
    case TagClass::Private:
        std::snprintf(buf, sizeof(buf), "P[%u]", t.number);
        break;
    }
    return buf;
}

static void emit_path(const std::vector<std::string>& path, std::ostream& out)
{
    for (size_t i = 0; i < path.size(); ++i) {
        if (i) out << '/';
        out << path[i];
    }
    out << '\n';
}

static std::string join_path(const std::vector<std::string>& path)
{
    std::string s;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i) s += '/';
        s += path[i];
    }
    return s;
}

// Case-insensitive glob match; '*' matches any sequence of chars (including '/').
static bool glob_matches(std::string_view pattern, std::string_view text)
{
    // Consume leading '*'s — consecutive stars collapse.
    while (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '*')
        pattern.remove_prefix(1);

    if (pattern.empty())
        return text.empty();

    if (pattern[0] == '*') {
        std::string_view rest = pattern.substr(1);
        // '*' matches zero or more chars (including '/').
        for (size_t i = 0; i <= text.size(); ++i) {
            if (glob_matches(rest, text.substr(i)))
                return true;
        }
        return false;
    }

    if (text.empty())
        return false;

    if (std::tolower((unsigned char)pattern[0]) != std::tolower((unsigned char)text[0]))
        return false;

    return glob_matches(pattern.substr(1), text.substr(1));
}

static bool tag_matches_desc(Tag t, Tag desc_tag)
{
    return t.cls == desc_tag.cls && t.number == desc_tag.number;
}

// ── Schema-free walk ──────────────────────────────────────────────────────────

static void walk_free(BerCursor            c,
                      std::vector<std::string>& path,
                      std::ostream&        out,
                      bool                 leaves_only)
{
    while (c.valid()) {
        path.push_back(tag_to_str(c.tag()));

        bool is_leaf = !c.tag().constructed;
        if (!leaves_only || is_leaf)
            emit_path(path, out);

        if (c.tag().constructed && !c.value().empty())
            walk_free(BerCursor(c.value()), path, out, leaves_only);

        path.pop_back();
        c.next();
    }
}

// ── Schema-aware walk ─────────────────────────────────────────────────────────

// Writes paths to `out` when non-null; appends to `collected` when non-null.
static void walk_schema(BerCursor                 c,
                        const TypeDescriptor*     desc,
                        std::vector<std::string>& path,
                        std::ostream*             out,
                        std::vector<std::string>* collected,
                        bool                      leaves_only)
{
    while (c.valid()) {
        // Reverse-lookup: find member/alternative name for this tag.
        std::string              name       = tag_to_str(c.tag());  // fallback
        const TypeDescriptor*    child_desc = nullptr;

        if (desc && desc->sequence_spec) {
            const SequenceSpec& ss = *desc->sequence_spec;
            for (int i = 0; i < ss.count; ++i) {
                if (tag_matches_desc(c.tag(), ss.members[i].tag)) {
                    name       = ss.members[i].name;
                    child_desc = ss.members[i].type_descriptor;
                    break;
                }
            }
        } else if (desc && desc->choice_spec) {
            const ChoiceSpec& cs = *desc->choice_spec;
            for (int i = 0; i < cs.count; ++i) {
                if (tag_matches_desc(c.tag(), cs.alternatives[i].tag)) {
                    name       = cs.alternatives[i].name;
                    child_desc = cs.alternatives[i].type_descriptor;
                    break;
                }
            }
        }

        path.push_back(name);

        bool is_leaf = !c.tag().constructed;
        if (!leaves_only || is_leaf) {
            if (out)       emit_path(path, *out);
            if (collected) collected->push_back(join_path(path));
        }

        if (c.tag().constructed && !c.value().empty())
            walk_schema(BerCursor(c.value()), child_desc, path, out, collected, leaves_only);

        path.pop_back();
        c.next();
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

void ber_dump_paths(std::span<const uint8_t> buf,
                    std::ostream&            out,
                    bool                     leaves_only)
{
    BerCursor root(buf);
    if (!root.valid()) return;
    std::vector<std::string> path;
    walk_free(root, path, out, leaves_only);
}

void ber_dump_paths_impl(std::span<const uint8_t> buf,
                         const TypeDescriptor*    root_desc,
                         std::ostream&            out,
                         bool                     leaves_only)
{
    BerCursor root(buf);
    if (!root.valid()) return;

    std::vector<std::string> path;
    // Enter the root TLV and name it after the root descriptor.
    path.push_back(root_desc ? root_desc->name : tag_to_str(root.tag()));

    bool root_is_leaf = !root.tag().constructed;
    if (!leaves_only || root_is_leaf)
        emit_path(path, out);

    if (root.tag().constructed && !root.value().empty())
        walk_schema(BerCursor(root.value()), root_desc, path, &out, nullptr, leaves_only);
}

std::vector<std::string> ber_find_paths_impl(std::span<const uint8_t> buf,
                                              const TypeDescriptor*    root_desc,
                                              std::string_view         glob)
{
    BerCursor root(buf);
    if (!root.valid()) return {};

    std::vector<std::string> path;
    std::vector<std::string> all;

    path.push_back(root_desc ? root_desc->name : tag_to_str(root.tag()));

    bool root_is_leaf = !root.tag().constructed;
    if (root_is_leaf)
        all.push_back(join_path(path));

    if (root.tag().constructed && !root.value().empty())
        walk_schema(BerCursor(root.value()), root_desc, path, nullptr, &all, /*leaves_only=*/true);

    std::vector<std::string> result;
    for (const auto& p : all)
        if (glob_matches(glob, p))
            result.push_back(p);
    return result;
}

} // namespace asn1
