#pragma once
#include <string>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <asn1cpp/compat/format.hpp>
#include <stdexcept>
#include "../ast/Module.hpp"
#include "../ast/TypeDef.hpp"
#include "../ast/Tag.hpp"
#include "../sema/Resolver.hpp"
#include "Backend.hpp"
#include "Casing.hpp"
#include <optional>
#include <limits>
#include <memory>

namespace asn1::codegen {

namespace fs = std::filesystem;

// FNV-1a hash of s — used to generate a deterministic, build-constant suffix.
inline uint32_t fnv1a_hash(std::string_view s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

// Escape an identifier that clashes with C++ keywords or any name in `extra`.
// Tries name+"_" first; if that also clashes, appends "_HHHHHHHH" (FNV-1a hash).
// The hash suffix is constant across builds for a given input name.
inline std::string safe_name(std::string n,
                              std::initializer_list<std::string_view> extra = {}) {
    static const std::unordered_set<std::string> kw = {
        "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool",
        "break","case","catch","char","char8_t","char16_t","char32_t","class",
        "compl","concept","const","consteval","constexpr","constinit","const_cast",
        "continue","co_await","co_return","co_yield","decltype","default","delete",
        "do","double","dynamic_cast","else","enum","explicit","export","extern",
        "false","float","for","friend","goto","if","inline","int","long","mutable",
        "namespace","new","noexcept","not","not_eq","nullptr","operator","or",
        "or_eq","private","protected","public","register","reinterpret_cast",
        "requires","return","short","signed","sizeof","static","static_assert",
        "static_cast","struct","switch","template","this","thread_local","throw",
        "true","try","typedef","typeid","typename","union","unsigned","using",
        "virtual","void","volatile","wchar_t","while","xor","xor_eq"
    };
    auto is_reserved = [&](const std::string& s) {
        if (kw.count(s)) return true;
        for (auto e : extra) if (s == e) return true;
        return false;
    };
    if (!is_reserved(n)) return n;
    std::string with_suffix = n + "_";
    if (!is_reserved(with_suffix)) return with_suffix;
    // Both n and n+"_" are reserved — append build-constant hash suffix.
    char buf[10];
    snprintf(buf, sizeof(buf), "%08x", fnv1a_hash(n));
    return n + "_" + buf;
}

// Builds the synthetic C++ name for an inline member type: parent + CapitalizedMember.
inline std::string make_synthetic_name(const std::string& parent, const std::string& member_name) {
    return parent + capitalize_first(to_cpp_name(member_name));
}

// Converts a member (identifier) name: first letter lower-case, escapes keywords + extra.
inline std::string to_member_name(std::string_view s,
                                  std::initializer_list<std::string_view> extra = {}) {
    auto n = to_cpp_name(s);
    if (!n.empty()) n[0] = (char)std::tolower(n[0]);
    return safe_name(std::move(n), extra);
}

// Converts a named-value (INTEGER constant) name: hyphens → underscores, matching asn1c.
inline std::string to_value_name(std::string_view s) {
    std::string out;
    for (char c : s)
        out += (c == '-') ? '_' : c;
    return out;
}

// IntStorageKind, TypeTagSpec, MemberTagSpec, and DefaultValueSpec live in Backend.hpp, included transitively above.

class Generator {
    fs::path                out_dir_;
    sema::Resolver&         resolver_;
    std::set<std::string>   generated_names_;
    // Synthetic type names promoted for an anonymous nested SEQUENCE OF/SET
    // OF element (generate_inline_types) — needed because
    // type_descriptor_ref_spec_for's own TypeRef-fallback branch (reached when
    // resolver_.resolve_ref can't find a dynamically-created synthetic
    // TypeDef, which is the normal case for every synthetic promotion) has
    // no other way to know the synthetic type isn't SEQUENCE/CHOICE/
    // ENUMERATED (its own long-standing assumption for every *other* kind
    // of synthetic promotion, still correct for those — only SEQUENCE
    // OF/SET OF needs a *free* asn_DEF_X reference, not a class-scoped
    // X::asn_DEF one).
    std::set<std::string>   seq_of_synthetic_names_;
    // Per-member primary synthetic name, as actually assigned by
    // generate_inline_types' dedupe pass over all promotable siblings at a
    // given level (SeqOf/SetOf wrapper, inline SEQUENCE/CHOICE/SET, inline
    // non-empty ENUMERATED). Every other call site that independently needs
    // "the synthetic name for member m" (native_member_type_for,
    // type_descriptor_ref_spec_for, emit_sequence_declaration's/
    // emit_choice_declaration's #include lambdas, ...) must look it up here
    // instead of recomputing backend_.synthetic_name(parent, m.name) itself
    // — two distinct raw member names can fold to the same styled name
    // (e.g. Rust's "field-one"/"fieldOne"), and only the dedupe pass knows
    // the disambiguated result. Keyed by the member TypeDef's own address,
    // stable for the lifetime of one compile. See member_synth_name().
    std::unordered_map<const ast::TypeDef*, std::string> promoted_member_name_;
    std::set<std::string>   collision_types_;   // ASN.1 type names defined in >1 module
    std::string             current_module_;    // module being generated right now
    std::string             current_type_;      // C++ name of type currently being generated
    ast::TagDefault         current_tag_default_{ast::TagDefault::Explicit};
    IntStorageKind          default_int_kind_{IntStorageKind::S64};  // --integer-type default
    std::string             namespace_;           // -fprefix wraps output in this namespace
    std::ostream*           pre_ns_os_{nullptr};  // when set, #include "X.hpp" writes here instead of body stream
    std::ostream*           post_ns_os_{nullptr}; // when set, deferred post-class includes write here (after namespace close)
    std::set<std::string>   pdu_roots_;           // ASN.1 names of -pdu= root types (empty = generate all)
    std::set<std::string>   reachable_asn_names_; // populated by compute_reachable(); ASN.1 names
    std::set<fs::path>      known_files_;         // every path emit_type_files() intended to (re)write
    // Type names already write_type_reference()'d for the current type's
    // declaration output. Cleared at the start of each emit_type_files()
    // call (one type's generation pass). Consulted when
    // backend_.dedupe_type_references() is true (the default — see that
    // method's doc, Backend.hpp).
    std::set<std::string>   emitted_type_refs_;
                                                    // this run, whether or not its content actually changed —
                                                    // consulted to remove now-stale generated files: file
                                                    // count/extension is backend-owned and can vary per
                                                    // type/backend, e.g. a SEQUENCE turning into a plain alias
                                                    // drops its .cpp file, or a schema regenerated under a
                                                    // single-file backend drops the .cpp/.hpp split entirely.
    std::unique_ptr<Backend> owned_backend_;      // set only when no external Backend is supplied
    Backend&                 backend_;            // naming/escaping — see Backend.hpp

public:
    /// @brief Construct with the default backend (CppBackend). Defined in
    ///        Generator.cpp to avoid a Generator.hpp <-> CppBackend.hpp cycle
    ///        (CppBackend.hpp includes Generator.hpp for the naming free functions).
    Generator(fs::path out_dir, sema::Resolver& res);
    /// @brief Construct with an explicit backend (e.g. RustBackend).
    Generator(fs::path out_dir, sema::Resolver& res, Backend& backend)
        : out_dir_(std::move(out_dir)), resolver_(res), backend_(backend) {}

    void set_default_int_kind(IntStorageKind k) { default_int_kind_ = k; }
    void set_namespace(std::string ns)           { namespace_ = std::move(ns); }
    void add_pdu_type(std::string asn_name)      { pdu_roots_.insert(std::move(asn_name)); }

    /// @brief Run codegen over all modules in `pr`, writing `.hpp`/`.cpp` files to `out_dir_`.
    /// @param pr  Resolved parse result containing all input modules.
    void generate(const ast::ParseResult& pr) {
        fs::create_directories(out_dir_);

        // First pass: detect type-name collisions across modules.
        // Compare on C++ names (hyphens stripped) so that ASN.1 types that differ
        // only in hyphenation (e.g. "Network-Identifier" vs "NetworkIdentifier")
        // are correctly treated as collisions.
        std::unordered_map<std::string, std::string> first_module;
        for (const auto& mod : pr.modules)
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker && !def->is_parameterized) {
                    auto cpp = backend_.type_name(def->name);
                    auto [it, inserted] = first_module.emplace(cpp, mod->name);
                    if (!inserted && it->second != mod->name)
                        collision_types_.insert(cpp);
                }

        if (!pdu_roots_.empty())
            compute_reachable(pr);

        for (const auto& mod : pr.modules) {
            current_module_ = mod->name;
            // generate_inline_types (promoted anonymous nested SEQUENCE/SET/
            // CHOICE types) must see the same AUTOMATIC/IMPLICIT/EXPLICIT
            // default as generate_type's own def — X.680 §24.9/§28.4's
            // per-alternative auto-tag assignment reads current_tag_default_
            // via should_apply_auto_tags. generate_type sets it too (kept
            // there for direct callers), but that happens *after*
            // generate_inline_types already ran for this def, so every
            // promoted type generated below saw whatever tag default was
            // left over from the previous type assignment (or the class's
            // default-initialized Explicit, before the first one) instead of
            // this module's real default.
            current_tag_default_ = mod->tag_default;
            for (const auto& def : mod->assignments)
                if (!def->name.empty() && !def->is_extension_marker && !def->is_parameterized) {
                    // A parameterized type (X.683) has no independent wire
                    // representation of its own — resolve_parameterized_
                    // instantiations already monomorphized every actual
                    // reference to it into its own concrete type (or, if
                    // never referenced, it's genuinely dead). Mirrors
                    // ground-truth asn1c, which forward-declares but never
                    // defines the un-instantiated generic.
                    if (!pdu_roots_.empty() && !reachable_asn_names_.count(def->name)) continue;
                    generated_names_.insert(effective_cpp_name(def->name, mod->name));
                    generate_inline_types(*def, *mod);
                    generate_type(*def, *mod);
                }
        }

        remove_stale_files();
    }

    /// @brief Delete generated files left over from a previous run that no
    ///        longer correspond to any type this run produced — e.g. a
    ///        SEQUENCE that became a plain alias (drops its `.cpp` file),
    ///        or the backend's declaration/definition extensions changing
    ///        (e.g. switching backends between a two-file and single-file
    ///        layout).
    /// @note Only considers files directly in out_dir_ whose extension
    ///       matches backend_.declaration_extension()/definition_extension()
    ///       — never touches unrelated files (e.g. a hand-maintained
    ///       sources.mk) or subdirectories.
    void remove_stale_files() const {
        std::set<std::string> exts{"." + backend_.declaration_extension(),
                                    "." + backend_.definition_extension()};
        if (!fs::exists(out_dir_)) return;
        for (const auto& entry : fs::directory_iterator(out_dir_)) {
            if (!entry.is_regular_file()) continue;
            if (!exts.count(entry.path().extension().string())) continue;
            if (known_files_.count(entry.path())) continue;
            fs::remove(entry.path());
        }
    }

    // Returns the C++ name to use for a type, prefixing with module when colliding.
    std::string effective_cpp_name(const std::string& asn_name,
                                   const std::string& mod_name) const {
        auto cname = backend_.type_name(asn_name);
        if (!collision_types_.count(cname))
            return cname;
        return backend_.type_name(mod_name) + cname;
    }

    // Returns the C++ name for a TypeRef encountered in `from_module`.
    std::string cpp_name_for_ref(const std::string& type_name,
                                 const std::string& from_module) const {
        auto cname = backend_.type_name(type_name);
        if (!collision_types_.count(cname))
            return cname;
        std::string def_mod = resolver_.module_of(type_name, from_module);
        if (def_mod.empty()) return cname;
        return backend_.type_name(def_mod) + cname;
    }

    // Returns the C++ name for a fully qualified TypeRef.
    // When module_name is set and the type is a collision type, uses module_name
    // directly instead of resolving through from_module imports.
    std::string cpp_name_for_typeref(const ast::TypeRef& tr) const {
        auto cname = backend_.type_name(tr.type_name);
        if (!tr.module_name.empty() && collision_types_.count(cname))
            return backend_.type_name(tr.module_name) + cname;
        return cpp_name_for_ref(tr.type_name, current_module_);
    }

private:
    void compute_reachable(const ast::ParseResult& pr);
    void collect_type_refs(const ast::TypeDef& def, std::vector<std::string>& worklist);
    void generate_type(const ast::TypeDef& def, const ast::Module& mod);
    void generate_inline_types(const ast::TypeDef& def, const ast::Module& mod);
    /// @brief Write the output file(s) for one type definition, driven by a
    ///        TypeOutputSession instead of hardcoding a ".hpp"/".cpp" pair.
    /// @param def  Type definition to emit.
    /// @param mod  Owning module (provides tag default and OID for the file header comment).
    /// @param session The type's output session (already created by the caller).
    /// @note Each per-construct dispatch branch makes one combined
    ///       backend_.emit_*() call covering both the declaration and
    ///       definition halves. The definition half decides for itself
    ///       whether a definition exists (e.g. none for a plain TypeRef
    ///       alias) rather than relying on a separately-computed flag, and
    ///       any buffer left empty afterward — including a backend's
    ///       genuinely-empty declaration half — is simply not written.
    void emit_type_body(const ast::TypeDef& def, const ast::Module& mod, TypeOutputSession& session);
    /// @brief Create the type's TypeOutputSession, call emit_type_body, then
    ///        write any non-empty resulting buffer to disk.
    /// @param name Final identifier used for the filename (via filename_for()).
    /// @param def  Type definition to emit.
    /// @param mod  Owning module (passed through to emit_type_body).
    void emit_type_files(const std::string& name, const ast::TypeDef& def,
                          const ast::Module& mod);

    /// @brief Route a cross-type reference through backend_.emit_type_reference,
    ///        seeding a throwaway session so Backend never touches `target`
    ///        directly — Generator picks the real
    ///        stream (declaration body, pre-namespace redirect, deferred
    ///        post-namespace includes, a `.cpp`-side include, ...), Backend
    ///        only owns the reference text.
    void write_type_reference(const std::string& type_name, std::ostream& target);
    /// @brief Same wiring as write_type_reference, for forward declarations.
    void write_forward_declaration(const std::string& type_name, std::ostream& target);

    /// @brief build_enumerated_spec/build_integer_spec/build_builtin_alias_spec
    ///        already feed both the declaration and definition halves from
    ///        one call — these three wrappers just do that and hand the spec
    ///        straight to the combined backend_.emit_*() call.
    void emit_enumerated(const ast::TypeDef& def, TypeOutputSession& session);
    void emit_integer(const ast::TypeDef& def, TypeOutputSession& session);
    /// @brief Decide the resolved IntegerSpec for a named INTEGER type —
    ///        storage kind, named constants, and constraint bounds. Needs
    ///        Generator state (extract_integer_range uses resolver_ for
    ///        named-value references), so unlike build_enumerated_spec this
    ///        is a member, not a free function.
    IntegerSpec build_integer_spec(const ast::TypeDef& def, const std::string& type_name) const;
    void emit_builtin_alias(const ast::TypeDef& def, TypeOutputSession& session);
    /// @brief Decide the resolved BuiltinAliasSpec for a builtin-alias type —
    ///        natural tag, FROM-alphabet, and SIZE constraint. Needs
    ///        Generator state (extract_size_range, resolver-backed
    ///        constraint walking), so a member like build_integer_spec.
    BuiltinAliasSpec build_builtin_alias_spec(const ast::TypeDef& def, const std::string& type_name) const;

    /// @brief SEQUENCE/SET: emit_sequence_declaration writes only the
    ///        declaration-side #include/forward-decl lines (no side content
    ///        beyond that — the class body itself is backend-emitted from
    ///        the spec emit_sequence_definition returns, which is a strict
    ///        superset of what the declaration side needs). Combined into
    ///        one backend_.emit_sequence() call by emit_sequence.
    void emit_sequence(const ast::TypeDef& def, TypeOutputSession& session);
    std::vector<std::string> emit_sequence_declaration(const ast::TypeDef& def, std::ostream& os);
    SequenceSpec emit_sequence_definition(const ast::TypeDef& def, TypeOutputSession& session);

    /// @brief SEQUENCE OF / SET OF: declaration and definition each
    ///        contribute disjoint SeqOfSpec fields (elem_type vs. xer_name/
    ///        size constraints/etc.) — emit_seq_of merges both into one
    ///        spec before the combined backend_.emit_seq_of() call.
    void emit_seq_of(const ast::TypeDef& def, TypeOutputSession& session);
    SeqOfSpec emit_seq_of_declaration(const ast::TypeDef& def, std::ostream& os);
    SeqOfSpec emit_seq_of_definition(const ast::TypeDef& def, TypeOutputSession& session);

    /// @brief CHOICE: declaration and definition compute their alternative
    ///        lists via genuinely different passes (canonical_choice_members()
    ///        vs. a separate tag-sort of `rows`) that are documented/relied-on
    ///        to produce the same canonical order — emit_choice zips
    ///        the declaration-only fields (mtype/accessor_name/pr_name) onto
    ///        the definition-built ChoiceSpec by index before the combined
    ///        backend_.emit_choice() call.
    void emit_choice(const ast::TypeDef& def, TypeOutputSession& session);
    std::vector<ChoiceAlternativeSpec> emit_choice_declaration(const ast::TypeDef& def, std::ostream& os);
    ChoiceSpec emit_choice_definition(const ast::TypeDef& def, TypeOutputSession& session);

    std::string native_member_type_for(const ast::TypeDef& def) const;
    TypeDescriptorRefSpec type_descriptor_ref_spec_for(const ast::TypeDef& def);
    std::string type_descriptor_ref_for(const ast::TypeDef& def);
    bool        member_is_constructed(const ast::TypeDef& m) const;
    bool        member_type_is_choice(const ast::TypeDef& m) const;
    bool        member_type_is_untagged_choice(const ast::TypeDef& m) const;
    bool        member_type_is_any(const ast::TypeDef& m) const;
    bool        member_is_explicit(const ast::Tag& tag, const ast::TypeDef& member_type) const;
    std::string emit_member_type_descriptor(const ast::TypeDef& m, const std::string& parent_cname,
                                            const std::string& mname, TypeOutputSession& session);
    /// @brief Decide the resolved MemberTypeDescriptorSpec for an inline-
    ///        constrained SEQUENCE/CHOICE member — INTEGER value range or
    ///        SIZE-able-primitive constraints. Needs Generator state
    ///        (extract_integer_range/extract_size_range/classify_integer_storage
    ///        use resolver_-backed decisions), so a member like build_integer_spec.
    /// @return nullopt when the member has no inline constraint worth a
    ///         dedicated descriptor — caller falls back to type_descriptor_ref_for().
    std::optional<MemberTypeDescriptorSpec> build_member_type_descriptor_spec(
        const ast::TypeDef& m, const std::string& parent_cname, const std::string& mname) const;
    /// @brief True for a directly-embedded SEQUENCE OF/SET OF element worth
    ///        promoting to a real named type (gambas-asn1#521) instead of an
    ///        ad hoc per-usage constraint table — a constrained INTEGER
    ///        element only for now (PR #520's original, confirmed-live
    ///        scope). Not yet extended to SIZE-able builtins (OCTET STRING/
    ///        BIT STRING/character strings): build_elem_shape doesn't
    ///        populate MemberTypeDescriptorSpec::Kind::Sizeable data today
    ///        (latent until #512/#513 land), and each of those kinds needs
    ///        its own correct XER tag keyword threaded through promotion
    ///        (synthetic->xer_name) the way Integer's "INTEGER" is here —
    ///        left for that follow-up rather than promoting something this
    ///        pass can't yet verify end-to-end.
    /// @param elem The SEQUENCE OF/SET OF element to check.
    bool is_promotable_seqof_int_elem(const ast::TypeDef& elem) const;
    /// @brief The actual, dedupe-disambiguated synthetic name for member `m`,
    ///        as assigned by generate_inline_types' pass over its siblings —
    ///        falls back to the raw (non-deduped) formula only if `m` was
    ///        never registered there (e.g. called before that pass ran).
    /// @param m             The member TypeDef to name.
    /// @param parent_cname  Parent type's C++/Rust name (fallback formula's parent).
    /// @param default_name  Raw ASN.1 name to style if `m` isn't in the map
    ///                       (m.name, or a fixed placeholder for anonymous members).
    std::string member_synth_name(const ast::TypeDef& m, const std::string& parent_cname,
                                   const std::string& default_name) const;
    /// @brief Returns "asn1::Tag{...}" literal for a tag override, empty string if absent.
    /// @param tag         The member's (possibly absent) tag override.
    /// @param constructed True if the encoding form is constructed, not primitive.
    std::string tag_literal(const ast::Tag& tag, bool constructed) const;
    /// @brief Decide whether a member carries an explicit BER tag override and,
    ///        if so, what class/number/encoding-form applies (X.690 §8.1).
    /// @param tag         The member's (possibly absent) tag override.
    /// @param constructed True if the encoding form is constructed, not primitive.
    /// @return The tag decision as plain data, or nullopt if `tag` is absent.
    /// @note Backend-agnostic: no C++ syntax. `tag_literal()` is now a thin
    ///       wrapper — tag_spec_for() decides, format_tag_literal() emits. A
    ///       future non-C++ backend consumes tag_spec_for() directly.
    std::optional<TypeTagSpec> tag_spec_for(const ast::Tag& tag, bool constructed) const;
    /// @brief Returns the natural (universal) tag for a member def's underlying
    ///        type. For types with an outer [N] tag, the outer tag IS the
    ///        wire-level tag.
    /// @param def Member or referenced type to compute the natural tag for.
    /// @return C++ `asn1::Tag{...}`/`asn1::Tag::universal(...)` literal, or ""
    ///         for CHOICE (no universal tag).
    std::string natural_tag_for(const ast::TypeDef& def) const;
    /// @brief Decide the natural (universal) BER tag for a member def's
    ///        underlying type — the decision half of natural_tag_for().
    /// @param def Member or referenced type to compute the natural tag for.
    /// @return The tag decision as plain data, or nullopt for CHOICE (no
    ///         universal tag).
    /// @note Backend-agnostic: no C++ syntax. `natural_tag_for()` is now a
    ///       thin wrapper — this decides, format_tag_literal() emits.
    std::optional<TypeTagSpec> natural_tag_spec_for(const ast::TypeDef& def) const;
    /// @brief Is this type's own top-level [n] tag (if any) EXPLICIT (X.690
    ///        §8.14.3)? False when untagged. See TaggedTypeSpec::is_explicit
    ///        (Backend.hpp) for why this matters: an EXPLICIT top-level tag
    ///        wraps a nested TLV using the type's own natural tag, it does
    ///        not substitute for it — unlike natural_tag_spec_for's own
    ///        `def.tag.present()` branch, which only decides the wire tag
    ///        text, not whether the encoding is a wrap or a substitution.
    bool type_is_explicit(const ast::TypeDef& def) const;
    /// @brief This type's own natural (universal, or resolved-through-alias)
    ///        tag, ignoring any [n] override `def` itself carries — the real
    ///        inner tag an EXPLICIT wrapper (type_is_explicit) needs to wrap.
    ///        A deliberately separate function from natural_tag_spec_for
    ///        (which folds `def`'s own override into its result when
    ///        present) rather than a refactor of it, to avoid touching that
    ///        function's existing, widely-used behavior.
    std::optional<TypeTagSpec> underlying_natural_tag_spec_for(const ast::TypeDef& def) const;
    /// @brief Map a CHOICE alternative's tag to a (class, number) sort key
    ///        for canonical PER ordering (X.691 §22.6).
    /// @param tag             The alternative's own `ast::Tag` (may already
    ///                        carry an AUTOMATIC-TAGS-resolved context tag —
    ///                        see call sites).
    /// @param natural_tag_src The alternative's TypeDef, consulted via
    ///                        natural_tag_spec_for() only when `tag` itself
    ///                        isn't present — the canonical fallback X.691
    ///                        requires for an alternative with no explicit
    ///                        `[n]` override, previously missing (gambas-
    ///                        asn1#622): every alternative had collapsed to
    ///                        the same sentinel key in that case, leaving
    ///                        them in declaration order instead.
    /// @param apply_auto_tags True when the enclosing module uses AUTOMATIC TAGS.
    /// @param auto_n          Declaration-order position used as tag number when auto-tagging.
    /// @return (class, number) pair; an alternative with no tag at all
    ///         (e.g. a nested untagged CHOICE) sorts last via (INT_MAX, INT_MAX).
    std::pair<int,int> canonical_tag_key(const ast::Tag& tag, const ast::TypeDef& natural_tag_src,
                                          bool apply_auto_tags, int auto_n) const;
    /// @brief Less-than comparator for canonical_tag_key.
    bool canonical_tag_less(const ast::Tag& a, const ast::TypeDef& a_src,
                             const ast::Tag& b, const ast::TypeDef& b_src,
                             bool apply_auto_tags, int auto_a, int auto_b) const;
    /// @brief Build the canonical ordered alternative list for a CHOICE type.
    /// @param def             The CHOICE TypeDef from the AST.
    /// @param apply_auto_tags Whether AUTOMATIC TAGS mode is in effect for this module.
    /// @return Root alternatives (sorted by tag unless AUTOMATIC TAGS) followed by extension
    ///         alternatives, with auto-generated tags applied if requested.
    /// @see X.680 §28 — CHOICE type; X.680 §24.8 — AUTOMATIC TAGS.
    std::vector<const ast::TypeDef*> canonical_choice_members(const ast::TypeDef& def, bool apply_auto_tags) const;
    /// @brief Follow a chain of top-level TypeRef aliases from `def` to its
    ///        ultimate non-TypeRef definition, reporting via `out_constructed`
    ///        whether the resulting wire shape is CONSTRUCTED — either
    ///        because the ultimate type is inherently constructed
    ///        (SEQUENCE/SET/CHOICE/SEQUENCE OF/SET OF), or because some
    ///        intermediate hop carries its own EXPLICIT tag (X.680 §31:
    ///        EXPLICIT tagging always produces a constructed encoding, and
    ///        further IMPLICIT re-tagging on top of it preserves that
    ///        wrapped nature — ground-truthed against asn1c's own wire
    ///        bytes for `Label2 ::= [1] Label; Label ::= [9] EXPLICIT
    ///        UTF8String` in 33-misc-OK.asn1: `[1]` stays CONSTRUCTED,
    ///        wrapping the UTF8String TLV, even though `[9]` never appears
    ///        on the wire).
    /// @param def             Type whose alias chain to follow.
    /// @param out_constructed Set to whether the chain is constructed, as above.
    /// @return The ultimate non-TypeRef TypeDef, or `def` itself if it isn't
    ///         a TypeRef, or the last resolvable hop if the chain breaks.
    const ast::TypeDef* resolve_alias_chain(const ast::TypeDef& def, bool& out_constructed) const;
    /// @brief Does `def` (a top-level type or a referenced-type hop) carry
    ///        its own [n] tag override on a TypeRef body whose ultimate
    ///        chain resolves to a plain builtin scalar? If so it gets its
    ///        own standalone descriptor (emit_type_body's
    ///        retag_alias_to_builtin path) rather than a bare `using`
    ///        alias sharing the referenced type's descriptor — any other
    ///        code that resolves a TypeRef one hop at a time (rather than
    ///        blindly flattening the whole chain) must stop here instead of
    ///        continuing past it, or it silently loses the override (see
    ///        resolve_alias_chain's own doc for the ground-truthed example).
    ///        Not extended to ENUMERATED/INTEGER (own emit_enumerated/
    ///        emit_integer paths) or SEQUENCE/CHOICE/SEQUENCE OF/SET OF
    ///        ultimates (would need real member-forwarding) — narrower
    ///        cases keep the pre-existing bare-alias behavior.
    bool has_own_retagged_descriptor(const ast::TypeDef& def) const;
    // Collect flattened BER dispatch tags for one CHOICE alternative.
    // alt_idx: 0-based index of the alternative in its parent CHOICE.
    // Appends BerTagEntry rows (raw class/number + formatted literal +
    // alt_idx); recurses if alt resolves to untagged CHOICE.
    // visited: set of type names already on the recursion stack (cycle guard).
    void collect_ber_tags_for(const ast::TypeDef& alt, int alt_idx,
                               std::vector<BerTagEntry>& out,
                               std::set<std::string>& visited);
    std::optional<int64_t> resolve_int_value(const ast::Value& v) const;
    std::optional<uint64_t> resolve_uint_value(const ast::Value& v) const;
    std::optional<std::pair<int64_t,int64_t>> extract_size_range(const ast::TypeDef& def) const;

    // Rich result from extract_integer_range.
    struct IntRange {
        bool has_value;   // false → no constraint found
        int64_t lo;
        int64_t hi;        // int64_t view of upper; INT64_MAX when truly_max=true
        bool truly_max;    // true → upper endpoint was the MAX keyword (semi-constrained)
        uint64_t hi_u64;   // actual upper as uint64_t; valid only when hi_is_large=true
        bool hi_is_large;  // true iff upper was TOK_number_large (positive literal > INT64_MAX)
    };

    // For DEFAULT members in SEQUENCE/SET: emits a static helper that sets the
    // optional and writes the DEFAULT value. Returns "&_setdef_..." or "nullptr".
    std::string emit_default_setter(const ast::TypeDef& m, const std::string& parent_cname,
                                    const std::string& mname, TypeOutputSession& session);
    /// @brief Decide which DEFAULT value (X.680 §25.1) applies to a member, if any.
    /// @param m Member to inspect.
    /// @return The decision as plain data. `Kind::None` covers: no DEFAULT
    ///         marker, no default_value set, or a NamedValueRef on a
    ///         non-ENUMERATED base (not supported as a literal today).
    /// @note Backend-agnostic: no C++ syntax. `emit_default_setter()` uses this
    ///       plus format_default_value_literal() (C++-specific emission) for
    ///       the value half of its output; the static-function wrapper it
    ///       emits around that value is itself a C++ codegen pattern, out of
    ///       scope for this decision/emission split.
    DefaultValueSpec default_value_spec_for(const ast::TypeDef& m) const;
    IntRange extract_integer_range(const ast::TypeDef& def) const;

    // Info for generating typed set_<member>() helpers on SEQUENCE/SET classes.
    struct MemberSetterInfo {
        std::string param_type;   // empty = skip this member
        bool is_int_alias;        // int64_t alias: wrap in asn1::Integer{} for validate
        bool is_uint_alias;       // uint64_t alias: wrap in asn1::UInteger{} for validate
        bool is_move;             // pass-by-value + std::move assignment
    };
    MemberSetterInfo classify_member_setter(const ast::TypeDef& m);

    // Choose INTEGER storage class from constraint analysis.
    IntStorageKind classify_integer_storage(const ast::TypeDef& def) const;

    // Classifies a TypeRef member/alternative's resolved target for PER
    // codegen purposes — see TaggedMemberSpec::RefTargetKind's own doc
    // (Backend.hpp) for what each case means and why only these two are
    // safe to resolve without tracking the target's own coverage state.
    struct TypeRefPerClass {
        TaggedMemberSpec::RefTargetKind kind = TaggedMemberSpec::RefTargetKind::NotRef;
        IntStorageKind storage_kind = IntStorageKind::S64;
    };
    TypeRefPerClass classify_typeref_for_per(const ast::TypeRef& tr) const;

    // Recursive shape of a SEQUENCE OF/SET OF element — see ElemShape's
    // own doc (Backend.hpp) for why this can't be a flat field.
    ElemShape build_elem_shape(const ast::TypeDef& elem, const std::string& wrapping_member_name,
                                const ast::TypeDef* wrapping_member = nullptr) const;

    // Shared helpers used by both SEQUENCE/SET and CHOICE codegen.
    struct MemberCount { int count; int ext_at; };
    static MemberCount count_members(const ast::TypeDef& def);

    bool should_apply_auto_tags(const ast::TypeDef& def) const;

    // resolved_tag is always populated with the member's final effective
    // wire tag (MemberTagSpec — Backend.hpp) — computed via
    // natural_tag_spec_for whether it comes from an override (explicit
    // `[n]`/AUTOMATIC, MemberTagSpec::tag_is_override true) or the type's
    // own natural tag (tag_is_override false). nullopt only for the one
    // case a member's type genuinely has no tag at all (an untagged
    // CHOICE — X.680 §28, no universal tag). No backend-specific string is
    // computed here — each backend calls its own
    // format_tag_literal/format_no_tag_literal on this structured data at
    // the point of use.
    struct TagResult { std::optional<MemberTagSpec> resolved_tag; bool is_explicit; };
    TagResult compute_member_tag(const ast::TypeDef& m,
                                 bool apply_auto_tags,
                                 int auto_tag_num) const;

    bool is_class_type(const ast::TypeDef& m) const;

    // Cycle detection for RustBackend's Box<T> decision — see
    // SequenceMemberSpec::member_type_in_cycle's doc (Backend.hpp) for the
    // full rationale.
    bool type_reaches(const ast::TypeDef& from, const std::string& target,
                       std::set<std::string>& visited) const;
    bool member_type_in_cycle(const ast::TypeDef& m, const std::string& enclosing_name) const;

    // Cycle detection for a bare top-level TypeRef alias's own #include-vs-
    // forward-declare decision (emit_type_body) — see
    // bare_alias_would_cycle's own doc for the full rationale. Unlike
    // type_reaches (member_type_in_cycle's traversal, scalar class-typed
    // members only), this also follows SEQUENCE OF/SET OF element types,
    // since a container-mediated cycle needs no boxing (VectorSeqOf<T>'s
    // declaration never needs T complete) but does need the alias sitting
    // on the cycle to forward-declare, or the #pragma once chain
    // destructively truncates before any type in the cycle is ever fully
    // defined.
    bool type_reaches_via_containers(const ast::TypeDef& from, const std::string& target,
                                      std::set<std::string>& visited) const;
    bool bare_alias_would_cycle(const std::string& target_name, const std::string& alias_name) const;

    // Full transitive closure of class-typed names reachable from `from` via
    // any member path (direct, inline, or SEQUENCE OF/SET OF-mediated) —
    // collect_extra_includes_for's own doc for why a single direct level
    // (bare_alias_would_cycle's own check) isn't always enough: a class
    // without OPTIONAL members gets an *implicit* (compiler-generated,
    // inline) copy constructor, so instantiating it wherever needed
    // transitively needs every type it touches complete too, not just its
    // own direct members. An anonymous inline member has no independent
    // ASN.1 name, so it's recorded as a "$anon:<ptr>" placeholder — only
    // meaningful for terminating this DFS, never a real #include target
    // (collect_extra_includes_for filters these back out before returning).
    void collect_class_types_reachable(const ast::TypeDef& from, std::set<std::string>& out) const;
    // Extra #include set a type wrapping `elem_type_name` (a SEQUENCE OF/SET
    // OF element, direct or a class type) needs in its own .cpp, beyond
    // what the normal #include chain already provides — the full
    // transitive closure via collect_class_types_reachable, minus
    // `self_name` (already complete in that file).
    std::vector<std::string> collect_extra_includes_for(const std::string& elem_type_name,
                                                         const std::string& self_name) const;
};

} // namespace asn1::codegen
