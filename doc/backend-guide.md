# Backend Implementation Guide

How to add a new target language to the compiler: a codegen backend plus its runtime.

This guide is language-neutral. It is distilled from the history of the existing backends: the second one, whose port went through several redesigns before reaching its current shape, and the third, which followed this guide and fed back how to slice the work (§11). Commit hashes in parentheses point at the change where a lesson was learned. `git show <hash>` gives the full reasoning; `#N` is a pull request or issue of the project.

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

## 9. Porting checklist

Build BER first, then XER, JER and PER. Each later codec is a new walker over the same tables, with no codegen change.

Work the list top to bottom. Every `- [ ]` item is one issue and one pull request of about 200–500 changed lines. Its bold title is the issue title; its sub-items are the issue body. An item marked **⚠** exists because an earlier port missed it; the note says what went wrong. §11 has the evidence behind the order.

**Every BER primitive and constructed item** delivers four parts, so they are not repeated below:
- runtime codec plus a unit test using the shared vectors;
- codegen for the construct (`emit_builtin_alias`, `emit_integer`, `emit_enumerated`, `emit_sequence`, …);
- a table-diff target whose schema carries every `Constraints` field the construct can have;
- a test leg mirroring the C++ test.

**Every text-codec item** (XER, JER) delivers the runtime walker code, unit tests, and a leg against the asn1c column of the shared vectors.

**Standing items**, filed whenever they come up and not tied to a step:
- [ ] **Fix in the reference runtime: <bug>.** A C++ or second-backend bug found while porting gets its own issue and is fixed on the main branch first. The port follows the reference behaviour until then. Expect several of these (§11).
- [ ] **Report asn1c deviation: <shape>.** Upstream, low priority. asn1c is not patched; tests get an explicit allowance.

### Foundations

- [ ] **F1 Ground-truth vectors for every planned codec**
  - Every shared `.vectors` file has the DER column plus asn1c's text for every codec the port will cover (§10). Add any missing column in this one mechanical change.
  - Done when: the regenerated files differ only in the new columns.
  - ⚠ The third port added the XER and JER columns inside the first XER and JER code steps: about 100 regenerated lines mixed into each code diff.
- [ ] **F2 Runtime skeleton: I/O base, tags, primitive tables, member-reference type, table dump**
  - Byte sink/source, decode and encode errors (§4); `Tag`/`Tagging`; `TypeDescriptor`, `MemberDescriptor`, `Constraints`; the member-reference sum type; the PDU marker; the dumper (Appendix A).
  - Done when: the runtime's unit tests run under ctest and the dumper prints a hand-written table.
  - ⚠ Leave `SequenceSpec`, `ChoiceSpec`, `SeqOfSpec` and `EnumSpec` to the items that use them. The third port's skeleton carried every spec record and came to ~1,980 lines.
- [ ] **F3 Backend skeleton: target flag, naming, one file per type**
  - Target and package flags, naming primitives (§7), cases added to `test_backend_naming`. `emit_*` keep the throwing default.
- [ ] **F4 Test plumbing: legs, table diff, CI**
  - Leg harness under `tests/<lang>/`, the language in `table_diff.py` with its own target list, a CI job with the language toolchain.
  - Done when: an empty leg and an empty table-diff run pass in CI.

### BER primitives

- [ ] **B1 BOOLEAN and NULL.** Smallest content codec; zero-length content. The first leg and the first table-diff target.
- [ ] **B2 INTEGER (64-bit storage) and ENUMERATED.** Minimal two's-complement content; `EnumSpec` arrives here.
- [ ] **B3 OCTET STRING and BIT STRING.** Unused-bits byte, named bits. SIZE constraints in the table-diff target.
- [ ] **B4 Restricted character strings: 8-bit and wide.** One codec and one wrapper per tag; 2- and 4-byte code units for BMPString/UniversalString. Alphabet constraints in the table-diff target.
- [ ] **B5 OBJECT IDENTIFIER and RELATIVE-OID.** Base-128 arcs; RELATIVE-OID reuses the arc codec.
- [ ] **B6 UTCTime and GeneralizedTime.** String content under a time-type tag.
- [ ] **B7 REAL.** X.690 §8.5 binary, decimal and special values; vectors shared with the existing runtimes.
- [ ] **B8 REAL constraints in the tables**
  - Range, open bounds and base-10-only (`WITH COMPONENTS { ..., base (10) }`) on type assignments and members; table-diff targets for REAL range, base and DEFAULT schemas.
  - Done when: the table diff is clean on those targets.
  - ⚠ BER and XER do not read these fields, so every BER and XER leg passed without them. The third backend emitted none, and the gap showed only in JER, where base-10-only picks the text form. A table field no codec reads yet is checked only by the table diff.
- [ ] **B9 INTEGER with unsigned or arbitrary storage, and ANY.** The storage decision of §5; raw TLV kept as bytes.

### BER constructed types

- [ ] **C1 CHOICE.** `ChoiceSpec`; alternative dispatch through the sorted `ber_tags`.
- [ ] **C2 SEQUENCE.** `SequenceSpec`; member walk; OPTIONAL. First round trip of a SEQUENCE of INTEGERs (`3d86c2d`).
- [ ] **C3 Real-schema compile probe**
  - Generate and compile the full ETSI LI PS-PDU schema; constructs not done yet become `Unsupported` stubs. File each compile gap as its own issue.
  - ⚠ The second port's first probe showed 232 compile errors (`a4ed52c`). The third ran it only after all BER constructs and still found three gaps: empty SEQUENCE, tagged contained types, over-long names (#991).
- [ ] **C4 SEQUENCE OF / SET OF.** `SeqOfSpec`; element constraints.
- [ ] **C5 Inline member constraints.** Constraints written on a member or an element rather than on a named type, in the tables and the table diff.
- [ ] **C6 SET.** Its own tag, canonical order on encode, any order on decode.
- [ ] **C7 Tagging matrix.** IMPLICIT / EXPLICIT / AUTOMATIC at type and member level (§6).
- [ ] **C8 DEFAULT.** Fill on decode, skip on DER encode.
- [ ] **C9 Extensibility.** Extension members, groups, unknown alternatives and enumerations.
- [ ] **C10 Recursive types.** Cycle handling (§5) and the 256-level decode limit.
- [ ] **C11 Contained values: status model, registry and decoders**
  - Against hand-written tables. Unit-test every status transition of the reference runtime: setting raw bytes drops the inner value and resets the status; a field already decoded from its inline text form is kept by the post-decode pass.
  - ⚠ The third runtime copied only what BER showed. The JER `raw` form then decoded such a value a second time from its bytes and lost it.
- [ ] **C12 Contained values: container-config codegen.** The rows from `--container-config` and their leg.
- [ ] **C13 Contained values: per-call options.** Decode off, registry override.
- [ ] **C14 BER cross-validation leg.** The language joins `xval_sweep.py`: random records round-trip byte for byte against C++, the second backend and asn1c.
- [ ] **C15 BER fuzz smoke test.** Corrupted BER gives errors, never aborts.
- [ ] **C16 Real-schema round trip.** The full ETSI LI PS-PDU schema compiles with no stubs and round-trips.

### XER (the template for every text codec)

- [ ] **X1 I/O layer + BOOLEAN, NULL, INTEGER, ENUMERATED + first leg**
  - Settle the comparison rules here: byte-for-byte against asn1c's XER, and an explicit allowance for each known asn1c deviation. Later items only add rows.
  - ⚠ An I/O layer has nothing to test on its own, so it pulls in every primitive unless the item stops at these four. The third port's XER and JER primitive steps came to ~1,150 and ~1,360 lines.
- [ ] **X2 Strings and escaping,** wide strings included.
- [ ] **X3 Hex kinds:** OCTET STRING, ANY, the BIT STRING forms.
- [ ] **X4 OBJECT IDENTIFIER, RELATIVE-OID, time types.**
- [ ] **X5 REAL text.**
- [ ] **X6 Constructed walker:** SEQUENCE/SET, CHOICE, SEQUENCE OF. One switch; its legs exercise every primitive already done.
- [ ] **X7 Encoding instructions on rows** (X.693 §21 BASE64/UTF8, value lists).
- [ ] **X8 Contained values, row form.** Hex, inline, inline-raw.
- [ ] **X9 Contained values, per-call override.**
  - ⚠ The third port had to split X8 and X9 after the fact (#1003, #1004).
- [ ] **X10 XER cross-validation leg.** Rows against C++ and asn1c, plus the round-trip and cross-decode matrix.

### JER

Same items as XER, J1–J10, with these differences:
- [ ] **J1** compares as parsed JSON, because asn1c indents its JER. Known asn1c deviations to allow for: extension-group members nested in an `extN` object (X.697 §27.3.1 keeps them flat); some absent DEFAULT members left out; wide strings not escaped.
- [ ] **J5 REAL text** needs the shortest round-trip number format. The third port checked it against the reference runtime on 200,000 doubles; the host language's own float-to-text was not shortest.
- [ ] **J7** is the REAL base-10 forms (bare number under base-10-only, `{"base10Value":…}` otherwise, X.697 §23), which rely on B8. No runtime implements JER encoding instructions yet.

### PER (unaligned)

The second port did PER after BER and XER, construct by construct (`6172168` … `0064728`). Most of its X.691 conformance came later, as fixes in both runtimes. The list below puts each of those clauses into the item that owns it. Clause numbers are those of X.691 (02/2021), `asn1-docs/T-REC-X.680-X.693-202102-I!!ZIP-E/X6911.doc`. Ground truth is asn1c's `-ouper` output; trace PER problems on the RRC schema, which is PER-native, and use ETSI LI only as a smoke test.

- [ ] **P1 Bit-level reader/writer + BOOLEAN and NULL + first leg**
  - Bit fields, octet-aligned fields, and the whole-number encodings of §11.3–§11.8, each unit-tested on its own before any type uses them.
- [ ] **P2 Length determinants (§11.9)**
  - Constrained, normally small, unconstrained, and fragments of 16K items or more (§11.9.3.8).
  - ⚠ Fragmentation was added a month after the rest, in both runtimes (`b90bb84`).
- [ ] **P3 INTEGER (§13)**
  - Single value, constrained, semi-constrained (§13.2.3, a non-negative-binary-integer), unconstrained, extensible range; constrained ranges as wide as the 64-bit and unsigned storage (§11.5.6).
  - ⚠ Semi-constrained values were encoded as unconstrained (`571dcbe`), and full 64-bit ranges overflowed (`f5514a9`); both fixed late in both runtimes.
- [ ] **P4 ENUMERATED (§14).** Root index, extension bit, extension values.
- [ ] **P5 BIT STRING and OCTET STRING (§16, §17)**
  - SIZE; the extension bit of an extensible SIZE (§16.6, §17.3); trailing 0 bits dropped for a NamedBitList BIT STRING (§16.2, §16.3); a length outside a non-extensible SIZE rejected on decode.
  - ⚠ All three came as late fixes (`3604074`, `d2f3150`, `45503f4`).
- [ ] **P6 Restricted character strings (§30)**
  - Known-multiplier strings: effective permitted alphabet and FROM remapping (§30.5), extensible types (§30.4). The other string types as a length plus octets.
  - ⚠ FROM remapping (`3a44e3b`) and extensible strings (`7d5707c`) came late.
- [ ] **P7 OBJECT IDENTIFIER, RELATIVE-OID, REAL, ANY/open type** (§24, §25, §15). Open-type fields as in §11.2.
- [ ] **P8 SEQUENCE and SET walker (§19, §21)**
  - Preamble bitmap sized by the precomputed `roms_count`, extension bit, extension additions as open-type fields, an extension addition group as one addition (§19.9).
  - ⚠ Groups were encoded member by member until `f9a1a85`; the optional count was recounted per value until `b1319a3`.
- [ ] **P9 CHOICE (§23)**
  - Index in the precomputed `range_bits`; canonical order with an untagged CHOICE alternative (§23.3); unknown extension alternatives (§23.8).
  - ⚠ An untagged CHOICE alternative was ordered last instead of by its smallest tag in both runtimes (#952). The third port's tests found it.
- [ ] **P10 SEQUENCE OF and SET OF (§20, §22)**
  - SIZE, the extension bit of an extensible SIZE (§20.4), SET OF components sorted (§22.1).
  - ⚠ SET OF sorting came late (`b86a134`).
- [ ] **P11 Contained values in PER.** Inner decode through the registry, as for BER.
- [ ] **P12 PER cross-validation leg.**
  - PER has no record boundary of its own, so the harness frames each record with a 4-byte length. Rows against C++ and asn1c, plus the round-trip matrix.
- [ ] **P13 PER fuzz smoke test.** Corrupted PER gives errors, never aborts.

---

## 10. Validation ladder

From cheapest to most thorough. All of it runs under `ctest`.

1. **Runtime unit tests** in the language's own test framework, using vectors shared with the C++ and second-backend tests. Reference bytes come from asn1c-generated encoders, never from hand-crafted bytes. `tests/vectors/make_ber_vectors.py SCHEMA VALUES.xer OUT.vectors` makes such vectors: asn1c encodes each listed XER value to DER and writes its own text encodings of that DER. The committed `.vectors` file (`Type<TAB>XER<TAB>DER-hex<TAB>asn1c-XER<TAB>asn1c-JER` per line) needs no asn1c to use, and gives every codec leg its ground truth from the same line.
2. **Naming test:** `test_backend_naming` covers each backend's naming primitives (keywords, hyphens, collisions).
3. **Generated-code test legs:** `tests/<lang>/<case>`, one per C++ test (`tests/<codec>/test_<case>.cpp`). They use the same schema under `tests/asn1/` and the same vectors, and print the same PASS/FAIL lines. The build compiles the generated code with warnings as errors.
4. **Table diff:** `validation-tools/table_diff/table_diff.py` dumps every generated type's tables in each runtime (Appendix A) and diffs them against C++.
5. **Cross-validation:** `validation-tools/xval_sweep/xval_sweep.py` runs random records, all codecs, every backend, plus asn1c ground truth.
6. **Fuzz smoke test:** corrupted BER must give errors, never aborts.

A divergence between asn1c and the compiler is presumed to be a compiler bug. A divergence between two backends with identical tables is a runtime bug. A table diff is a backend or `Generator` bug.

---

## 11. Why the checklist looks like this (lessons from the third port)

The third port took 35 pull requests into its integration branch, about 90 commits, against about 346 commits for the second port. The table-only design held: no codec after BER needed a codegen change, except where a table field had never been emitted (below). What still went wrong was step size and order.

### Which steps were too big

Most steps were 200–500 changed lines and passed review and CI on the first push. The outliers:

| Step | Own diff | What made it big |
|------|----------|------------------|
| Runtime skeleton (I/O, spec tables, BER reader/writer, table dump) | ~1,980 lines, 47 files | spec records for every construct, before any construct used them |
| JER I/O layer + all primitives | ~1,360 | I/O layer, every primitive, and a vectors column regenerated in every file |
| XER I/O layer + all primitives | ~1,150 | the same shape |
| BER contained values | ~1,000 | registry, decoders, container-config codegen and options in one step |
| BER REAL | ~870 | binary, decimal and special forms plus their vectors |

These produced the step boundaries of §9 (F1, F2, X1, B7/B8, C11–C13, X8/X9). Two patterns. **The first step of a new layer** carries the I/O layer and every primitive, because an I/O layer has nothing to test until a value goes through it. **A feature with several switches** (contained values: per-row form, per-call override, decoder registry) lands all switches at once. The XER contained step had to be split after the fact (#1003, #1004).

### A table field that no codec reads yet is untested (B8)

The third backend never emitted REAL constraints (range, open bounds, base-10-only). BER and XER do not read them, so every BER and XER leg passed. The gap showed only in the JER step, where base-10-only picks the text form, and table_diff had no REAL-constrained target. When a construct's table rows land, add a table_diff target that carries every `Constraints` field the construct can have, even fields no codec of the new runtime reads yet. The table diff is the only check that sees them.

### Port shared state transitions, not observed behaviour (C11)

A contained field keeps a status (not decoded, decoded, skipped, failed). The third runtime copied what BER showed: setting the raw bytes did not reset the status, and the post-decode pass did not skip a field already decoded from its inline text form. BER never takes that path. JER's `raw` member did: a value whose raw bytes differed from its own encoding was decoded again from those bytes and lost. For state that several codecs share, port each setter of the reference runtime with what it resets, and test each transition in the runtime's unit tests, not through one codec.

### The new backend tests the existing ones

The port found bugs in the reference runtimes, each fixed on the main branch first, in its own change:
- an EXPLICIT tag around a tagged CHOICE (#951);
- untagged CHOICE alternative order in PER (#952);
- CHOICE and inline-type cycles that did not compile (#975, #979);
- a CHOICE alternative ignoring its BASE64/UTF8 instruction (#1001);
- wide strings in JER carrying XML escapes (#1010);
- JER `null` for an absent member not accepted (#1013).

The second port's PER showed the same from the other side: most X.691 corner clauses (fragmentation, semi-constrained INTEGER, extensible SIZE, extension groups, SET OF order) arrived as late fixes in both runtimes, each a month or more after the construct itself. §9 lists them inside the item that owns them.

asn1c deviations were reported upstream, not patched. These are the standing items of §9: budget for them, and keep each fix out of the port's own step.

### Check clause numbers against the text

First drafts cited wrong X.697 clauses for strings, bit strings and constructed types, and commit messages of the second port mix X.691 editions (1997 and 2021 numbering differ by one clause for most types). Cite one edition, preferably the 2021 set in `asn1-docs/T-REC-X.680-X.693-202102-I!!ZIP-E/`, and search its text before writing a clause number into a comment. Those are Word 97 files; `strings -n 4 X6911.doc` gives searchable text with each clause number at the start of its line.

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
