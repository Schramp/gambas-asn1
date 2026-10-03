# Generator / Backend architecture

This document exists because the split between `Generator` and `Backend` grew
incrementally, one small PR at a time, while `RustBackend` was built out
alongside the original `CppBackend`. Nobody designed it end-to-end up front.
This is the write-up of a review done once Rust was feature-complete enough
to ask: does the split still make sense, or does it need an overhaul?

**Verdict: the split is sound. No major overhaul warranted.** What follows
is the contract as it actually exists today, the handful of concrete gaps
found while checking it, and a tutorial for adding a third backend.

## The split, in one sentence

`Generator` resolves every backend-agnostic decision from the AST/resolver
into a typed `*Spec` struct (declared in `Backend.hpp`); `Backend` turns an
already-resolved `*Spec` into target-language text. A backend should never
need to ask "what does the ASN.1 source say" — `Generator` has already
answered that by the time a `Backend::emit_*` method is called.

```
ast::TypeDef  --[Generator, resolver_-aware]-->  *Spec struct  --[Backend::emit_*]-->  generated text
```

Current implementations: `CppBackend` (two-file `.hpp`/`.cpp` split, the
original) and `RustBackend` (single `.rs` file per type, added second).

## Method policy: pure-virtual vs throw-by-default

`Backend` methods fall into three groups, by design (Backend.hpp:668-687):

1. **Naming primitives — pure virtual.** `type_name`, `member_name`,
   `value_name`, `escape`, `synthetic_name`. Everything else calls into
   these, so there is no useful "not implemented yet" state for a name.
2. **Everything else — throws by default.** `emit_sequence`, `emit_choice`,
   `format_tag_literal`, `native_int_type`, and so on. The default body is
   `throw std::logic_error(...)`. This is deliberate: it lets a backend that
   only supports a subset of ASN.1 constructs stay instantiable and
   compiling. It only fails loudly, at the moment generated output actually
   needs the missing construct — not at link time, not at every call site.
3. **Safe, non-throwing defaults** for methods whose contract still has to
   return *something* valid even from an unfinished backend: `module_name`
   (identity function), `format_type_descriptor_ref` (`{}`),
   `dedupe_type_references`/`needs_seqof_wrapper_reference`/
   `needs_forward_declare_for_cyclic_alias` (all default `true` — the
   conservative choice when a backend hasn't told you otherwise).

When adding a method to `Backend`, ask which group it's in before writing
the signature. Getting this wrong either makes a half-finished backend
impossible to compile (group 1 on something that should be group 2) or lets
a real bug compile silently (group 2 on something that should throw).

## The `*Spec` catalog

Every `*Spec` struct in `Backend.hpp` is meant to be backend-agnostic raw
data: tag class/number, bit widths, bounds, structural shape — never
pre-rendered syntax. This mostly holds. Two real exceptions were found (see
"Known gaps" below); everything else in the catalog is clean.

Reused building blocks worth knowing about before adding a field to any of
these: `TypeTagSpec`/`MemberTagSpec` (tag triple + override flag),
`TaggedTypeSpec`/`TaggedMemberSpec` (shared tag-bearing base, so every
construct gets `resolved_tag` from one place), `ElemShape` (recursive
SEQUENCE OF/SET OF element shape, deliberately structural — no text).

## `TypeOutputSession` and the declaration/definition split

`Backend::declaration_extension()`/`definition_extension()` decide file
identity. `TypeOutputSession::buffer(ext)` returns a persistent stream keyed
by that extension string — same extension twice returns the *same* stream,
appending in call order. `CppBackend` returns `"hpp"`/`"cpp"` (two files);
`RustBackend` returns `"rs"`/`"rs"` (one file, declaration-side and
definition-side content concatenated in order).

This works today with zero ordering workarounds, because Rust's whole-crate
name resolution has no declare-before-use requirement — `RustBackend`
overrides `needs_seqof_wrapper_reference()` and
`needs_forward_declare_for_cyclic_alias()` to `false` and makes
`emit_forward_declaration` a no-op, each with a comment saying exactly this.
A single-file backend only needs to worry about this if its target language
*does* require declare-before-use within one file.

**Per-construct, is there one Spec or two?** This was the concrete question
behind "would a multi-pass generator loop help." Answer: it depends on the
construct, and only one construct actually has a problem.

| Construct | Passes over members | One Spec reused for both halves? |
|---|---|---|
| SEQUENCE/SET | 2 (declaration only computes includes) | **Yes** — `emit_sequence` hands one `SequenceSpec` to both halves; the declaration pass returns `post_class_includes`, not a second Spec. |
| ENUMERATED / INTEGER / builtin-alias | 1 | Yes — single Spec, no member loop to duplicate. |
| SEQUENCE OF/SET OF | 2, but O(1) (one element, not N members) | Mostly — a one-field patch (`elem_type`) merges the two tiny partial specs. Harmless. |
| **CHOICE** | up to 3 | **No.** `emit_choice_declaration` and `emit_choice_definition` each independently sort alternatives into canonical PER tag order and walk `def.members`, producing two overlapping-but-distinct row sets reconciled only by a runtime `assert` zipping them by index. This is the one real duplication in the emission model — see "Known gaps." |

Conclusion: a generic "N-pass loop" abstraction is not worth building — only
CHOICE needs restructuring, and it needs the same one-Spec shape SEQUENCE
already has, not a new abstraction layered on top.

## Naming: the project's actual philosophy

**Generated identifiers must preserve the ASN.1-declared name as closely as
target-language syntax allows. Never recase to satisfy a target language's
own style lint — suppress the lint instead.**

This was learned the hard way: `RustBackend::type_name`/`synthetic_name`
used to do real word-split PascalCase recasing (`to_upper_camel_case`)
purely to dodge rustc's `non_camel_case_types` lint. Two distinct ASN.1
identifiers (`field-one`, `fieldOne`) could fold to the *same* recased name
— a silent type/field collision, not just a style choice. Fixed by switching
to the same minimal transliteration `CppBackend` already used (hyphen →
underscore only, case preserved) and suppressing the lint with
`#[allow(non_camel_case_types)]` on the generated item — the same tradeoff
already made for `#[path = "..."]` module filenames.

Post-fix, `type_name`/`synthetic_name` are byte-identical formulas between
`CppBackend` and `RustBackend`. `member_name`/`value_name`/`escape` still
differ, but only in the *escape* mechanism (disjoint keyword lists, disjoint
escape syntax: trailing `_` vs `r#...`) — a real syntax need, not drift.

**This fix was incomplete.** `RustBackend::variant_name()` — a file-local
helper used for ENUMERATED/CHOICE variant identifiers, living outside the
formal `Backend` interface entirely — still does the same `to_upper_camel_case`
recasing the rest of the backend moved away from. It's the identical bug
class, just missed. Any contributor extending naming logic should check
every naming *surface*, not just the five documented `Backend` primitives —
a bug of this shape can hide in a local helper just as easily.

Known, separately-tracked naming gaps (not fixed by the above, intentionally
left open): #615 — neither backend gives an ASN.1 module its own namespace;
cross-module collisions are handled only by name-prefixing. The C++ and
Rust runtimes also don't document any mapping between type names that
legitimately differ (`Oid` in C++ vs `ObjectIdentifier` in Rust) — grepping
one runtime for the other's name finds nothing.

## Known gaps (filed as issues, not fixed by this doc)

- **Tag-class ranking exists in three places** that must independently agree
  (`Generator::tag_class_rank`, `Backend::tag_class_index`, a RustBackend-local
  lambda that deliberately doesn't reuse `tag_class_index` because its order
  is wrong for that call site) — correctness risk, not just duplication.
- **`variant_name()` still recases** — see above.
- **`Generator` bakes a C++ naming convention into two `*Spec` fields**:
  `MemberTypeDescriptorSpec::tname` (`"asn_TYP_{parent}_{member}"`) and
  `SequenceMemberSpec::def_setter` (`"&_setdef_{parent}_{member}"`) are
  built by `Generator` itself, not by `CppBackend` — and `RustBackend`
  derives its own constant names from `tname` via `to_screaming_snake_case`,
  meaning **generated Rust code today contains the literal substring
  `ASN_TYP_...`**, a C++ codegen convention leaking into Rust output. Not an
  architectural necessity — these should carry raw `(parent, member)` and
  let each backend build its own convention, the same way every other
  `*Spec` field does. (Two struct fields that looked similar on paper —
  `SequenceMemberSpec::ops`/`offset_expr` — turned out on inspection to
  already be fully computed inside `CppBackend` itself, not pre-formatted at
  all; don't assume a struct's own doc comment is still accurate without
  checking the live call site.)
- **CHOICE's declaration/definition double-pass** — see the table above.
- **ENUMERATED's root-value sort is duplicated verbatim** in both backends
  (same comparator, same reason — X.691 §22 PER ordinal = sorted position) —
  trivial hoist into the `EnumeratedSpec`-building step.
- **A second, narrower naming-fold risk**, same shape as the `field-one`/
  `fieldOne` bug one layer up: `RustBackend` builds crate-wide constant names
  (`_SPEC`, `_MEMBERS`, `_ALTERNATIVES`, ...) via
  `to_screaming_snake_case(type_name())`, applied to a type's *own*
  already-deduped name. Two distinct top-level type names (`My_Type` vs
  `MY_TYPE`) aren't currently checked for collision at this third namespace
  layer.
- Two duplications that are real but belong **inside** `RustBackend.cpp`,
  not hoisted to `Generator` (Generator has no business knowing Rust's
  `PerValue`/`Unsupported`-stub concept): PER-coverage classification
  (`per_member_covered`/`per_alt_covered` vs `sequence_member_covered`/
  `choice_alternative_covered`), and the Rust-variant collision guard
  (`seen_variants` map + throw, copy-pasted three times).
- **#518** (`classify_typeref_for_per` duplicating part of
  `type_descriptor_ref_spec_for`'s resolve step) was re-checked against all
  18 `resolver_.resolve_ref(...)` call sites in `Generator.cpp` — still no
  third caller needing the same classification. Still correctly deferred.

## Adding a new backend: a tutorial (stress-tested against Java and .NET)

Every rule below was checked against two hypothetical third backends — a
JVM one (Java, one-public-class-per-file, package = directory) and a CLR one
(.NET/C#, namespace-qualified, usually one assembly) — specifically to catch
rules that quietly assume "it's either C++ or Rust."

1. **Start from the naming primitives, and get them right first.**
   Implement `type_name`, `member_name`, `value_name`, `escape`,
   `synthetic_name` (all pure virtual — you cannot skip these). Apply the
   project's naming philosophy from day one: minimal transliteration, not
   recasing, with the target language's own lint suppressed if your
   language has one. *Java check*: `type_name` still just needs to produce a
   valid Java class identifier — same transliteration formula works.
   *C# check*: same. Neither language's own style guide should change the
   formula; both support disabling style-analyzer lints per-type the same
   way Rust does (`@SuppressWarnings`, `#pragma warning disable`).

2. **Decide your `declaration_extension()`/`definition_extension()` pair.**
   Same string for both = everything in one `TypeOutputSession` buffer, in
   call order. Different strings = a real two-file split, like C++. *Java
   check*: Java's "one public top-level class per file, filename must match
   the class name" rule means you almost certainly want same-extension
   (single file), like Rust — but note your file*name* must come from
   `type_name()`'s output exactly, unlike Rust where the file is a module
   and the name mapping has one more layer (see point 6). *C# check*: C#
   has no filename constraint at all; one file per type is a convention, not
   a requirement — either model works, pick based on what's easiest for
   your emission code, not a language constraint.

3. **If your language has declare-before-use (most JVM/CLR targets do
   *not*, within one compilation unit — don't assume you need the C++-style
   workarounds).** Override `needs_seqof_wrapper_reference()` and
   `needs_forward_declare_for_cyclic_alias()` to `false`, and make
   `emit_forward_declaration` a no-op, *if* your language resolves names at
   whole-file/whole-assembly granularity like Rust, Java, and C# all do.
   Only override toward `true`/a real implementation if your target
   genuinely needs forward declarations (true of C++, true of essentially
   nothing else in modern use).

4. **Implement one construct at a time; let the throw-by-default behavior
   work for you.** Don't implement `emit_choice` before `emit_sequence`
   compiles — the interface is designed so a partial backend stays buildable.
   Pick an order; SEQUENCE and ENUMERATED are the simplest starting points on
   both existing backends.

5. **Never recompute something `Generator` already decided.** Before adding
   a loop over `spec.members`/`spec.alternatives`/`spec.values` inside your
   `emit_*`, check whether the `*Spec` already carries the answer you need.
   If it doesn't, and the missing fact is backend-agnostic (a sort order, a
   coverage classification that doesn't involve your language's own
   runtime-trait concepts), that's a sign it belongs as a new `*Spec` field
   computed once by `Generator`, not backend-local logic — see the tag-class
   ranking and ENUMERATED-sort gaps above for what *not* to repeat.

6. **Reuse the existing collision/dedup machinery; don't reinvent it.**
   `Generator::dedupe_styled_names`/`member_synth_name` exist because a
   backend's own naming transformation can fold two distinct ASN.1
   identifiers together (hyphen/case differences, abbreviation-run casing,
   ...) even when the raw ASN.1 names are guaranteed distinct. Any new
   backend doing real case transformation anywhere (which should be rare —
   see point 1) must run candidate names through this machinery, or it will
   reproduce the exact `field-one`/`fieldOne` bug class. `collision_types_`
   (cross-module same-name types) and `Backend::module_name()` (defaults to
   identity — don't override it to do your own casing without re-reading why
   that was tried and reverted for Rust, #597/#607/#623) are the other two
   buckets to reuse, not reinvent. *Java/C# check*: package/namespace-level
   collisions are exactly the #615 gap neither existing backend has solved
   yet — don't assume there's a working pattern to copy for module-level
   namespacing; this is open work, see #615.

7. **Resolver-dependent logic stays on `Generator`, never on `Backend`.**
   `Backend` has no access to `resolver_`/`collision_types_`/
   `effective_cpp_name` by design — if your backend's emission needs to
   resolve a `TypeRef` to its target type, that resolution must happen in
   `Generator` and be handed to you as an already-resolved `*Spec` field
   (see `type_descriptor_ref_spec_for`, `classify_typeref_for_per` for the
   existing examples). Don't add a `Backend`-side `resolver_` reference to
   work around this — it's a deliberate boundary (see #518's own discussion
   of why merging the two existing resolve-and-classify call sites isn't
   worth a bigger interface change for two callers).

8. **When you hit a case the interface doesn't have a `*Spec` field for
   yet**, check whether the gap is genuinely backend-agnostic data before
   adding backend-specific pre-formatted text to an existing struct — that's
   exactly how the `tname`/`def_setter` C++-text-leaking-into-Rust gap
   happened. Prefer adding a new, clearly-named raw-data field and
   formatting it yourself over reusing a field whose existing contents
   happen to look like what you need.
