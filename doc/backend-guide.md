# Backend Implementation Guide

How to add a new target language to the compiler: a codegen backend plus its runtime.

This guide is language-neutral. It is distilled from the history of the existing backends, mainly the second one, whose port went through several redesigns before reaching its current shape. Commit hashes in parentheses point at the change where a lesson was learned. `git show <hash>` gives the full reasoning.

The reference implementation is the C++ backend (`CppBackend`, `runtime/`). The second backend (`RustBackend`, `rust-runtime/wire/`) is the reference for a language without `offsetof` and without inheritance-based dispatch. Every rule below holds for both.

---

## 1. The one rule: tables, not code

A backend emits **descriptor tables** and **plain data types**. It never emits encode or decode logic.

- Every backend emits the same tables, row for row and value for value. Only the syntax differs.
- All codec logic lives in the runtime: one generic walker per codec (BER, XER, JER, PER).
- The walker reads the tables of the type it is handed.
- Adding a codec to a runtime must need **zero** codegen changes (`54f4639`).
- "The codec uses the type; the type does not have a codec" (`9b7b8c4`).

This rule exists for three reasons:

1. **Correctness is shared.** A table value is decided once, in `Generator`, and copied by every backend. If two runtimes disagree on the wire, either one runtime is wrong or a backend rendered a table wrong. The table diff (§10) tells you which.
2. **Code size.** Per-type codec code multiplies with the schema. The ETSI LI schema has about 1000 types. Codec closures stored in tables pull every codec into every binary, even a BER-only one (`9b7b8c4`).
3. **Tools can read the tables.** Constraints are data, never code (`2cca2bf`). Random fillers, validators and dumpers walk the same tables.

The first port started with straight-line generated code per SEQUENCE and was moved to tables on review (`88d9e94`). Start with tables.

---

## 2. The Backend contract

`compiler/src/codegen/Backend.hpp` defines the split:

- **`Generator` decides.** It resolves the AST and fills backend-agnostic `*Spec` structs (`TypeTagSpec`, `MemberTagSpec`, `IntegerSpec`, `EnumeratedSpec`, `BuiltinAliasSpec`, `SeqOfSpec`, `SequenceSpec`, `ChoiceSpec`, `DefaultValueSpec`, `TypeDescriptorRefSpec`, …).
- **A `Backend` formats.** It turns those decisions and the ASN.1 names into source text for its language.

The interface has two tiers:

| Tier | Methods | Default |
|------|---------|---------|
| Naming primitives | `type_name`, `member_name`, `value_name`, `escape`, `synthetic_name` | pure virtual: a backend cannot exist without them |
| Per-construct emission | `emit_integer`, `emit_enumerated`, `emit_builtin_alias`, `emit_seq_of`, `emit_sequence`, `emit_choice`, `format_*`, … | throws `std::logic_error` |

The throwing defaults are deliberate. A new backend is usable for everything it already supports and fails loudly the moment a schema needs a construct it doesn't support yet. You build the backend one construct at a time.

Rules for the boundary:

- **A decision belongs in `Generator` when every backend needs it.** Examples: tag resolution, storage width, DEFAULT values, cycle detection. Do not re-derive these in a backend.
- **Language-specific analysis stays inside its own backend.** It is never added to the shared `Generator`/`Backend` surface. Fields that only one backend needed were pulled back out of the shared interface (`3eacad4`, `2907a84`).
- **Never string-match generated type text** to make a decision. Ask for the decision as a typed field instead. `IntStorageKind` replaced matching on `"i64"` (`3aed389`).
- **File identity belongs to the backend.** It comes through `TypeOutputSession`, `declaration_extension()` and `definition_extension()`. A language without a header/body split returns the same extension for both, and both halves go to one file (`2c95318`).
- **Cross-type references go through the backend** (`emit_type_reference`, `emit_forward_declaration`, `232cc23`). Use the language's import or include form. `finalize_output` writes any per-output manifest the language needs, such as a module list.

How the first port moved the interface: it first extracted naming into `Backend` with C++ as the only implementation, and checked that by a byte-identical regeneration of the full test corpus (`eaec58f`). Then each construct moved in two steps, first into `CppBackend`, then implemented in the new backend: ENUMERATED, INTEGER, builtin alias, SEQUENCE OF, SEQUENCE/SET, CHOICE, top-level dispatch. If you need to move more C++ text out of `Generator`, follow the same two-step pattern and keep the C++ output byte-identical.

---

## 3. The table model

Each language renders the same rows in its own syntax. The canonical content is listed below; Appendix A gives the dump format used to compare tables across languages.

### TypeDescriptor (one per type)
- `name`: the ASN.1 type name, verbatim.
- `tag`: the type's own tag, resolved (class, number, constructed).
- `kind`: one of the builtin kinds, SEQUENCE, SET, CHOICE, SEQUENCE OF, SET OF, ENUMERATED or ANY.
- One spec, by kind: `SequenceSpec`, `ChoiceSpec`, `SeqOfSpec` or `EnumSpec`.
- `constraints`: see below.

### MemberDescriptor (one per SEQUENCE/SET member or CHOICE alternative)
- `name`: the ASN.1 identifier, verbatim.
- `tag`: the effective tag on the wire.
- `tagging`: IMPLICIT (replace the natural tag), EXPLICIT (wrap the inner TLV), or none (natural tag, or an untagged CHOICE that dispatches on its alternatives' tags).
  Tagging belongs to whoever wrote the tag. A member with its own `[n]` carries that framing in its row. A member that just references a type with its own tag (`TExp ::= [APPLICATION 13] EXPLICIT INTEGER`, then `w TExp`) gets *none*. Its row restates the type's tag, so OPTIONAL presence can be peeked, and the type's own descriptor does the framing (X.680 §31.2). That is also how a top-level PDU of that type frames itself. If your runtime unwraps an alias to its bare builtin before the walker sees it, the row must still point at the type's framing, for example through a reference to it. Never copy the type's EXPLICIT into the row.
- `optional`: true for OPTIONAL, DEFAULT and every extension member.
- `has_default`, plus a way to set the default and to test "equals default" (§6).
- A reference to the member type's descriptor (C++), or an accessor that yields a typed reference (§5).
- `constraints`, `xer_instruction` (BASE64/UTF8 per X.693 §21), and the contained-value marker (X.682 §11).

### SequenceSpec
- `members`, `ext_at` (index of the first extension member, -1 for none), `roms_count`, `is_set`.
- Extension units: the extension addition groups of X.691 §18.9.
- The indices of contained members.

### ChoiceSpec
- `alternatives` and `ext_at`.
- `range_bits`: the PER choice index width, precomputed (`aa0ebfa`).
- `ber_tags`: alternative tags **sorted**, for binary-search dispatch (`0e67d2b`). The tags of an untagged nested CHOICE are flattened in.

### SeqOfSpec
- The element descriptor, the SIZE constraint, and the declared element XER name (X.693 §12).

### EnumSpec
- Entries (value, name) sorted by value, `extensible`, `root_count`, and the root values in definition order (PER).

### Constraints
A flat record: `flags`, `range_bits`, `int_kind`, signed and unsigned bounds, SIZE bounds and `size_range_bits`, and the permitted-alphabet tables.

- C++ (`runtime/include/asn1cpp/codec/Constraints.hpp`) and Rust (`rust-runtime/wire/src/constraints.rs`) have the same fields. Keep it that way.
- **Precompute every schema-derived fact in the tables** (`b1319a3`): counts, bit widths, sorted tag lists, alphabet maps. A codec that recounts at runtime is a missing table field.

### How the existing backends render a member row

```
C++:   { "text", asn1::Tag{asn1::TagClass::Context, 0, false}, false, false,
         ASN1CPP_OFFSETOF(JeRec, text), &asn1::asn_DEF_Utf8String, ... }
Rust:  MemberMeta { name: "text", tag: Tag { class: Context, number: 0, constructed: false },
         optional: false, ber: BerTagging::Implicit(..), constraints: &UNCONSTRAINED, ... }
       + JeRec_GETTERS[0] = |v| MemberRef::Primitive(PrimitiveRef::Utf8String(&v.text))
```

The facts in the two rows are the same. The difference is how a field is reached: an `offsetof` in C++, an accessor function in Rust.

---

## 4. Runtime shape

A runtime has three layers. They depend on each other in one direction only.

1. **The I/O base:** a byte source and sink, a bit reader and writer for PER, and error types. It holds no codec knowledge. If several codecs need a shared concern and the I/O types live inside one codec, you get dependency cycles. Give I/O its own module or package.
2. **Spec:** the table types of §3, the member-reference sum type (below), and the PDU root marker. This layer is codec-neutral.
3. **Codecs:** one module per codec. Each has a reflective walker `object` plus the primitive content codecs.

**One package or crate for the whole runtime** (`9bf9819`). The shared spec layer has to know about every codec's needs. If codecs are split across packages that depend on each other, the language must support specialisation or cyclic dependencies. Unify early.

### The member-reference sum type

The walker never sees concrete generated types. It sees a **closed** set of shapes:

| Shape | Meaning |
|-------|---------|
| `Primitive(p)` | a builtin leaf. `p` is itself a closed sum over the builtin wrapper types. |
| `Composite(s)` | a SEQUENCE/SET: its spec plus indexed member access |
| `Choice(c)` | a CHOICE: its spec, the present index, and access to the alternative |
| `SeqOf(l)` | a SEQUENCE OF / SET OF: length, element access, append |
| `Enumerated(e)` | an ENUMERATED slot: value get/set plus its EnumSpec |
| `Absent` | a missing OPTIONAL member |
| `Unsupported(msg)` | a construct this backend cannot represent yet. Every walker turns it into an encode/decode error carrying `msg`. |

Generated types implement only the small reflective interface (spec plus indexed accessors) and a PDU marker. Top-level encode and decode are one generic function per codec, bound on the PDU marker: `encode_pdu`, `decode_pdu`, and the `_into` variants.

- **With sealed hierarchies and pattern matching:** the sum type is a sealed interface, and each walker is one exhaustive switch.
- **Without them:** use a visitor with one method per shape. Never use an open class hierarchy that the walker probes with type tests.

### Wrapper type for every builtin

Generate a builtin-typed member as the runtime's wrapper type, such as `Integer` or `Ia5String`, never as a bare host type like a 64-bit integer, a string or a byte array (`715146f`). A bare alias loses the type's identity: an alias of a list of integers can no longer carry its declared XER element name (`4a0f805`). Wrappers can still expose the host value directly.

### Errors, never aborts

Malformed input must give a decode error, never a crash, panic, uncaught exception or assertion (`6fa607f`, `6da3f85`, `48cc667`). This includes:
- lengths beyond the buffer;
- integers wider than their storage;
- nesting deeper than the depth limit (§6).

A fuzz smoke test is part of the validation ladder (§10).

---

## 5. Language mapping decisions

Make each decision once, document it in the backend's header, and test it.

| Concern | If the language has … | Do this |
|---------|-----------------------|---------|
| Field access | `offsetof` and raw pointers | an offset in the member row |
| | no `offsetof` | one accessor function or lambda per member, in a static table indexed like the member rows. **Never reflection**: it is slow, it breaks under ahead-of-time compilation, and it hides errors until runtime. |
| CHOICE | sealed hierarchies or tagged unions | one variant per alternative, plus a variant for an unknown extension (`4acc912`) |
| | neither | a present-index plus a value slot, with typed accessors |
| OPTIONAL | reference types with null | a nullable reference |
| | value types (structs) | an optional wrapper. For large members, box them: a struct of inline optionals measured 22× the C++ size (`4ef2183`). |
| Recursion | value types | box the members that close a real cycle, found by cycle detection in `Generator` (`8ca1ba0`, `a5aa19c`) |
| | reference types only | nothing extra for storage, but the decode depth limit still applies |
| INTEGER storage | 64-bit signed and unsigned types | `IntStorageKind::S64` / `U64` map to them |
| | no unsigned 64-bit type | map `U64` to the arbitrary-precision type, or to signed storage with unsigned compare and convert helpers. Decide in `native_int_type` and nowhere else. |
| Collections | reified generics | a typed list per SEQUENCE OF |
| | type erasure | a typed list for the API, but the walker reaches elements through the SeqOf accessor, never through runtime element-type tests |
| Decode target | — | decode **in place** into a default-constructed value. Grow collections in place and decode into the new slot; don't build a temporary and copy it in (`d167b3e`). |
| Type alias (`A ::= B`) | type aliases | `A` names `B`'s type, and every table is `B`'s |
| | no type aliases, but subclassing | an empty subclass of `B` named `A`; generated classes must not be sealed or final |
| Default construction | — | every type needs a default value. For ENUMERATED and CHOICE, make the default explicit (`e8d1d72`). |

Performance work comes after correctness, and it is driven by measurement:
- Profile allocations first. In the second port, the C++ vs. other-language gap was dominated by allocation, not by dispatch (`1a3e858`, `9a625b5`).
- Back-fill BER lengths in place in one output buffer, instead of building a buffer per node.
- An optimisation that is not measured on the real workload is not done. Small-string storage was tried twice and dropped (`023ed42`).

---

## 6. Semantics every backend must get right

Each item below was a real bug in an earlier port. Each needs a test in the new backend.

| Area | Rule | Bug class seen |
|------|------|----------------|
| SET | uses its own universal tag 17, not SEQUENCE's 16. Members are emitted in canonical tag order; decode accepts any order (X.690 §8.11). | `3874934` |
| IMPLICIT | the member's tag replaces the natural tag, even for strings, time types and aliases of aliases | `a26ed22`, `e0fb19e`, `38d00de`, `0a53c25` |
| EXPLICIT | wrap the inner TLV, don't substitute the tag. A tagged CHOICE is always EXPLICIT (X.680 §31.2.7). | `e224e80`, `544a60f`, `8aa6fcb` |
| AUTOMATIC TAGS | a member that already carries a tag keeps it. AUTOMATIC applies only when no member of the SEQUENCE/SET/CHOICE is tagged. | `e50747e` |
| Type-assignment tags | `T ::= [APPLICATION 3] INTEGER` puts the tag on the type itself, including for a top-level CHOICE | `30160ce`, `ba47763` |
| Wrong tag on decode | is an error, not a silent accept | `66a2347` |
| DEFAULT | fill the default when the member is absent on decode. Skip the member on DER encode when it equals the default. | `235f578`, `dd8bed5`, `8a9779d` |
| Extensibility | unknown extension members and alternatives decode and are skipped, or kept as raw bytes. An unknown ENUMERATED value in an extensible type is not an error. | `4acc912`, `60ec811`, `7d5707c`, `f9a1a85` |
| Storage width | values beyond the storage width give an error, never a wrap-around | `655ac96`, `f5514a9` |
| Depth | limit decode nesting to 256 levels | `7c6b551`, `f4046b7` |

---

## 7. Naming fidelity

Generated names are API. Two distinct ASN.1 names must never map to one generated name, and an API name should match the ASN.1 name wherever the language allows.

- **Transliterate only.** Replace `-` with `_` and change nothing else. Never recase: `field-one` and `fieldOne` would both become `fieldOne`. Recasing was added in the second port and reverted (`9f8fd75` → `f87fe41`, `2b3a864`). Suppress the style lint instead.
- **Escape keywords with a trailing `_`.** This covers reserved words, contextual keywords and the language's literal names. It cannot collide with another schema name: an ASN.1 identifier never ends in a hyphen and never contains `--` (X.680 §11.2, §11.3). So a name ending in `_` cannot come from the schema.
  - Use a raw-identifier syntax only where it accepts every word. The second port hit words its raw syntax refuses (`e3a45cc`), and raw prefixes leaked into compound names (`e7e72cc`).
- **Generated code fully qualifies every host standard-library name.** A schema type may be named `Option`, `Integer`, `String`, `Object` or `Error`, and it will shadow the host name inside the generated package (`b445ab7`, `cf8d2a3`, `86b2872`).
- **Generated local variables use a prefix that ASN.1 cannot produce,** such as `__`. A local named like an enum item can capture or shadow it (`e3a45cc`).
- **The file or module name is the type name, verbatim** (`7480c42`). This removes a whole namespace where collisions could happen.
- Synthetic names for anonymous inner types come from `Generator` (`synthetic_name`, depth-scoped for nested levels). Do not invent another scheme in a backend.

---

## 8. Anti-patterns (tried, then reverted)

| Tried | Why it failed | Do instead |
|-------|---------------|------------|
| Multi-pass emission with a fixed-point loop over "can this type be covered yet?" | order-sensitive and fragile (`426cffc`, `37b5cd4`) | one pass. Every type always gets a real implementation; a row that can't be covered becomes an `Unsupported` stub. |
| Codegen-time "supported?" gates that guess what the runtime can handle | guesses went stale and were wrong (`5a7207b`, `0689f0f`, `0fc5cf7`) | emit the table. The runtime rejects an unsupported value when it meets one. |
| Per-codec closures stored in the tables | every codec linked into every binary (`986010f` → `9b7b8c4`) | the reflective sum type, matched in each codec's walker |
| A per-type value trait implemented by generated code | per-type code again (`5b42c88`, `183a96e`) | spec plus indexed accessors only |
| Recasing identifiers to satisfy a style lint | lossy (`f87fe41`) | transliterate and suppress the lint |
| Box only on cycles, everywhere | struct size blow-up for large optional members (`4ef2183`) | the per-language decision of §5 |
| Small-string optimisation for every string | no measured gain (`023ed42`) | measure first |
| Codec packages split from the start | dependency cycles; shim packages left behind (`9bf9819`, `cbd9948`) | one runtime package, with codec modules inside it |

---

## 9. Construct order and milestones

Build BER first, then XER, JER and PER. Each later codec is a new walker over the same tables, with no codegen change.

### BER primitives, in order

| Step | Construct | Why at this point |
|------|-----------|-------------------|
| 1 | BOOLEAN | smallest content codec; exercises tag and length end to end |
| 2 | NULL | zero-length content |
| 3 | INTEGER, 64-bit storage | two's-complement minimal encoding, sign extension |
| 4 | ENUMERATED | reuses INTEGER content; adds the EnumSpec table |
| 5 | OCTET STRING | raw content; constructed (segmented) form on decode |
| 6 | BIT STRING | unused-bits byte; named bits |
| 7 | 8-bit restricted strings: UTF8, IA5, Printable, Numeric, Visible, Teletex, Videotex, Graphic, General, ObjectDescriptor | one codec, one wrapper type per tag |
| 8 | Wide strings: BMPString, UniversalString | 2- and 4-byte code units |
| 9 | OBJECT IDENTIFIER | base-128 arcs, with the first two arcs combined |
| 10 | RELATIVE-OID | reuses the arc codec |
| 11 | UTCTime, GeneralizedTime | string content with a time-type tag |
| 12 | REAL | X.690 §8.5 binary, decimal and special values. Share vectors with the existing runtimes. |
| 13 | INTEGER with unsigned or arbitrary storage | the storage decision of §5 |
| 14 | ANY / open type | raw TLV kept as bytes |

Each step has four parts:
- a runtime unit test with shared vectors;
- codegen for the type assignment (`emit_builtin_alias`, `emit_integer`, `emit_enumerated`);
- a table-diff target;
- a test leg mirroring the C++ test.

### Constructed types, in order
1. CHOICE: alternative dispatch through the sorted `ber_tags`.
2. SEQUENCE: member walk, OPTIONAL.
3. SEQUENCE OF / SET OF.
4. SET: its own tag, canonical order, any-order decode.
5. The tagging matrix: IMPLICIT / EXPLICIT / AUTOMATIC, at type and member level.
6. DEFAULT.
7. Extensibility: extension members, groups, unknown alternatives.
8. Recursive types.
9. Contained values (X.682 §11).

### Milestone gates
1. **First roundtrip:** a SEQUENCE of plain INTEGERs encodes and decodes (`3d86c2d`).
2. **Table diff clean** against C++ on every target in `validation-tools/xval_sweep/targets.txt`.
3. **xval leg:** the language joins `xval_sweep.py`. Random records cross-encode byte-identically against C++, the second backend, and asn1c.
4. **Real-schema build probe:** the full ETSI LI PS-PDU schema compiles and round-trips. The second port's first probe showed 232 compile errors (`a4ed52c`). Expect the same kind of number and run the probe early.
5. XER byte-identical to asn1c, including whitespace; then JER; then PER.

---

## 10. Validation ladder

From cheapest to most thorough. All of it runs under `ctest`.

1. **Runtime unit tests** in the language's own test framework, using vectors shared with the C++ and second-backend tests. Reference bytes come from asn1c-generated encoders, never from hand-crafted bytes. `tests/vectors/make_ber_vectors.py SCHEMA VALUES.xer OUT.vectors` makes such vectors: asn1c encodes each listed XER value to DER, and the committed `.vectors` file (`Type<TAB>XER<TAB>hex` per line) needs no asn1c to use.
2. **Naming test:** `test_backend_naming` covers each backend's naming primitives (keywords, hyphens, collisions).
3. **Generated-code test legs:** `tests/<lang>/<case>`, one per C++ test (`tests/<codec>/test_<case>.cpp`). They use the same schema under `tests/asn1/` and the same vectors, and print the same PASS/FAIL lines. The build compiles the generated code with warnings as errors.
4. **Table diff:** `validation-tools/table_diff/table_diff.py` dumps every generated type's tables in each runtime (Appendix A) and diffs them against C++.
5. **Cross-validation:** `validation-tools/xval_sweep/xval_sweep.py` runs random records, all codecs, every backend, plus asn1c ground truth.
6. **Fuzz smoke test:** corrupted BER must give errors, never aborts.

A divergence between asn1c and the compiler is presumed to be a compiler bug. A divergence between two backends with identical tables is a runtime bug. A table diff is a backend or `Generator` bug.

---

## Appendix A — canonical table dump

Every runtime provides a dumper that serialises its own static tables (C++ `asn1::dump_tables`, `runtime/include/asn1cpp/TableDump.hpp`; Rust `asn1cpp_wire::spec::dump::dump_tables`; Java `TableDump.dump`, `java-runtime/.../spec/TableDump.java`). `validation-tools/table_diff/table_diff.py` builds a harness per language that dumps every generated type, then compares the dumps field by field, C++ being the reference. The dumper reads tables only; it never encodes or decodes.

The dump is JSON Lines: one object per type, one line each.

```json
{"name":"JeRec","kind":"SEQUENCE","tag":{"class":"UNIVERSAL","number":16,"constructed":true},
 "constraints":{"flags":0,"range_bits":0,"lower":0,"upper":0,"lower_u64":0,"upper_u64":0,
                "size_range_bits":0,"size_lower":0,"size_upper":null,"alphabet_bits":0,"alphabet":""},
 "ext_at":-1,"roms_count":0,
 "members":[{"name":"text","tag":{"class":"CONTEXT","number":0,"constructed":false},"tagging":"IMPLICIT",
             "optional":false,"has_default":false,"constraints":{...},"xer_instruction":"DEFAULT","contained":false}],
 "ext_units":[],"contained_members":[]}
```

Fields per `kind`, beyond `name`, `kind`, `tag` and `constraints`:

| kind | fields |
|------|--------|
| `SEQUENCE`, `SET` | `ext_at`, `roms_count`, `members`, `ext_units` [{`end`, `group`}], `contained_members` |
| `CHOICE` | `ext_at`, `range_bits`, `alternatives` (member rows), `ber_tags` [{`tag`, `alt`}] sorted by (class, number) |
| `SEQUENCE_OF`, `SET_OF` | `size`, `element_xer_tag`, `element` {`kind`, `constraints`} |
| `ENUMERATED` | `extensible`, `root_count`, `entries` [{`value`, `name`}] sorted by value, `per_value_order` |
| builtin kinds (`BOOLEAN`, `INTEGER`, `OCTET_STRING`, `UTF8String`, …, `ANY`) | none |

Value sets and normalisation:

- `kind` of a builtin is its X.693 element name (`OCTET_STRING`, `OBJECT_IDENTIFIER`, `UTF8String`, …); the open type is `ANY`.
- `tag.class`: `UNIVERSAL`, `APPLICATION`, `CONTEXT`, `PRIVATE`. A CHOICE with no tag of its own has `"tag": null`.
- `tagging`: `IMPLICIT` (the tag replaces the natural tag), `EXPLICIT` (outer TLV), `NONE` (the row restates the referenced type's own tag and frames nothing), `UNTAGGED_CHOICE` (the member is an untagged CHOICE; `"tag": null`), `UNSUPPORTED` (the runtime has no representation for the row yet). `NONE` and `IMPLICIT` with the same tag frame the row identically and compare equal.
- `xer_instruction`: `DEFAULT`, `BASE64`, `UTF8`.
- `size_upper` is `null` unless the SIZE constraint is a finite range (`SIZE_CONSTRAINED` flag); the bound has no meaning otherwise.
- Integers are plain decimal JSON numbers, any width. `alphabet` is hex.
- The type name is the ASN.1 name; where a runtime's tables carry no name (builtin type assignments, SEQUENCE OF) the harness passes the generated identifier, and the diff matches names with `-` and `_` treated alike.

A field a runtime's tables do not carry is left out of its dump and reported as "not carried" (`--not-carried` lists them), never as a mismatch. An already-filed divergence is listed in `validation-tools/table_diff/known_diffs.txt` (`<lang> <field-path glob> <issue>`) and reported as known.

Usage: `table_diff.py [--lang cpp,rust|cpp,java|cpp,rust,java] [--full] [--target SUBSTR] [--targets-file F] [-j N] [-v] [--not-carried] [--rebuild]`.

- The default target list, `validation-tools/table_diff/targets.txt`, holds the schemas every compared backend covers today, so a run takes minutes; ctest `table_diff_cpp_rust` runs it. While a backend is being built, keep this list at the few schemas it already covers and move schemas into it from `validation-tools/xval_sweep/targets.txt` as coverage grows. `--full` runs that whole list, including the large real-world schemas.
- A run that includes a backend still being built uses that backend's own list instead (Java: `java_targets.txt`, ctest `table_diff_cpp_java`), whose `-pdu` roots leave out the types it cannot emit yet.
- A dump is reused when its inputs (schema files, flags, compiler binary, runtime sources) are unchanged; `--rebuild` forces fresh builds.
- The C++ harness is a unity build (one translation unit per core), since each generated file is a few lines of tables behind the same runtime headers.
