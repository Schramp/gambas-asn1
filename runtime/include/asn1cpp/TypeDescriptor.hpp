#pragma once
#include <cstddef>
#include <memory>
#include "Tag.hpp"
#include "SeqOfBase.hpp"
#include "codec/Constraints.hpp"

// C++ equivalents of asn1c's descriptor table types.
// Generated code fills these static tables; the runtime codec uses them.

namespace asn1 {

// Sentinel for MemberDescriptor::offset when the field is not used
// (optional members use get_ptr; CHOICE alternatives use get_const_fn).
// High bit of size_t — maps to kernel address space, causing an immediate
// fault on any architecture if accidentally used in pointer arithmetic.
inline constexpr std::size_t kInvalidMemberOffset =
    std::size_t{1} << (sizeof(std::size_t) * 8 - 1);

// One row in an ENUMERATED value<->name map (mirrors asn_INTEGER_enum_map_t).
struct EnumEntry {
    long        value;
    const char* name;
};

// Per-type ENUMERATED metadata (mirrors asn_INTEGER_specifics_t).
struct EnumSpec {
    const EnumEntry* entries;          // sorted by value (BER/XER binary search)
    int              count;            // total count (root + extension)
    bool             extensible;

    // PER: root values in ASN.1 definition order (ordinal → value mapping).
    // Root ordinal 0 = first enumeration value in the ASN.1 source, etc.
    // Nullptr for non-extensible types where count == root_count == entries count.
    int              root_count;       // number of root enumeration values
    const long*      per_value_order;  // [root_count] values in definition order

    // Returns 0 if `v` is a known enumeration value (root or extension),
    // otherwise 1 (no meaningful distance for ENUMERATED).
    int64_t validate(long v) const {
        for (int i = 0; i < count; ++i)
            if (entries[i].value == v) return 0;
        return 1;
    }
};

// Safe offsetof for non-standard-layout types (SequenceBase<T> has virtual methods).
#if defined(__GNUC__) || defined(__clang__)
#  define ASN1CPP_OFFSETOF(T, m) __builtin_offsetof(T, m)
#else
#  define ASN1CPP_OFFSETOF(T, m) offsetof(T, m)
#endif

// Template that generates the three OptionalOps callbacks for a unique_ptr<T> member.
// Usage in generated code:
//   using _Ops_Type_member = asn1::UniquePtrOps<Type, MemberType, &Type::member>;
//   ... OptionalOps{ &_Ops_Type_member::check, &_Ops_Type_member::set, &_Ops_Type_member::get } ...
template<typename Owner, typename T, std::unique_ptr<T> Owner::* Mbr>
struct UniquePtrOps {
    static bool        check(const Asn1Object* p) {
        return (bool)(static_cast<const Owner*>(p)->*Mbr);
    }
    static void        set(Asn1Object* p, bool v) {
        auto& o = static_cast<Owner*>(p)->*Mbr;
        if (v) { if (!o) o = std::make_unique<T>(); } else o.reset();
    }
    static Asn1Object* get(Asn1Object* p) {
        return (static_cast<Owner*>(p)->*Mbr).get();
    }
};

// Encapsulates optional-member callbacks so codecs don't carry naked function
// pointers or repeat null checks.  get_ptr(struct*) returns T* from the
// unique_ptr<T> that stores the optional value; needed by table-driven codecs
// that must write into the allocated object, not the unique_ptr itself.
struct OptionalOps {
    bool        (*check)(const Asn1Object*)  = nullptr;
    void        (*set)(Asn1Object*, bool)    = nullptr;
    Asn1Object* (*get_ptr)(Asn1Object*)      = nullptr; // null for required members; UniquePtrOps::get for optional
    bool is_present(const Asn1Object* p)  const { return check && check(p); }
    bool is_present(const void* p)         const { return is_present(static_cast<const Asn1Object*>(p)); }
    void set_present(Asn1Object* p, bool v) const { if (set) set(p, v); }
    void set_present(void* p, bool v)       const { set_present(static_cast<Asn1Object*>(p), v); }
    // Returns a typed pointer to the member within the owner struct.
    //
    // Two cases:
    //
    //   get_ptr != null  (optional members, UniquePtrOps):
    //     Calls get_ptr(p), which dereferences the unique_ptr<T> stored at the
    //     member's location and returns the T* inside it. The T is heap-allocated;
    //     the unique_ptr itself is at a fixed offset but the member value is one
    //     level of indirection deeper.
    //
    //   get_ptr == null  (required members):
    //     The member is stored directly inside the struct (not behind a pointer).
    //     We compute its address as: (char*)p + offset, where offset =
    //     ASN1CPP_OFFSETOF(StructType, member_name), emitted by codegen.
    //     This is a single ADD instruction — the cheapest possible access.
    //
    // Why the void* round-trip in the offset path:
    //   C++ forbids static_cast<char*> from a pointer-to-class (Asn1Object*).
    //   The standard-legal route for byte arithmetic is through void*:
    //     Asn1Object* → void* → char* → +offset → void* → Asn1Object*
    //   The object at (p + offset) really is an Asn1Object (all member types
    //   inherit from it), so the final static_cast is well-defined.
    //   reinterpret_cast<char*>(p) is technically UB without the void* hop.
    //
    // Why NOT use a stored function pointer for required members too:
    //   Commit 053f795 tried DirectMemberOps<Owner,T,Mbr>::get stored as get_ptr
    //   for required members, removing the offset field entirely. Measured result:
    //   +1.015B Ir (+4.86% total), confirmed by interleaved A/B perfdiff (winner
    //   every round, P=0.1%). LTO cannot devirtualize a function pointer loaded
    //   from a descriptor table in a runtime loop — it sees only the call through
    //   the pointer, not the callee. The offset ADD compiles to one instruction;
    //   the function pointer call costs a load + indirect branch + return.
    //   Reverted in 00b4942. Do not revisit without a profiler trace showing
    //   something has changed in how LTO handles this pattern.
    Asn1Object* member_ptr(Asn1Object* p, std::size_t offset) const {
        return get_ptr ? get_ptr(p)
                       : static_cast<Asn1Object*>(static_cast<void*>(
                             static_cast<char*>(static_cast<void*>(p)) + offset));
    }
    const Asn1Object* member_ptr(const Asn1Object* p, std::size_t offset) const {
        return get_ptr ? get_ptr(const_cast<Asn1Object*>(p))
                       : static_cast<const Asn1Object*>(static_cast<const void*>(
                             static_cast<const char*>(static_cast<const void*>(p)) + offset));
    }
    explicit operator bool() const { return check != nullptr; }
};

// Forward declaration — MemberDescriptor references TypeDescriptor.
struct TypeDescriptor;

// Per-member SEQUENCE/SET/CHOICE descriptor (mirrors asn_TYPE_member_t).
struct MemberDescriptor {
    const char*           name;
    Tag                   tag;            // effective wire tag (context tag when tagged, natural otherwise)
    bool                  optional;
    bool                  has_default;
    std::size_t           offset;         // offsetof(Struct, member); 0 for CHOICE alternatives
    const TypeDescriptor* type_descriptor;
    OptionalOps           optional_ops;   // non-null only for optional/extension members (UniquePtrOps)
    bool                  is_explicit = false; // true → EXPLICIT tagging; false → IMPLICIT

    // BER/XER: when set, called after decode if the member was absent on the wire.
    // Allocates the optional and writes the DEFAULT value from the ASN.1 schema.
    // Null when no DEFAULT applies.
    void (*set_default)(Asn1Object* owner) = nullptr;

    // BER encode: when set and returns true, the member is suppressed (X.690
    // §11.5: DEFAULT-equal values must not be encoded). True only when the
    // member is present AND its value equals the schema default.
    bool (*is_default_equal)(const Asn1Object* owner) = nullptr;

    // CHOICE variant accessors — non-null only for CHOICE alternatives in
    // std::variant-based generated structs.  Codecs use these instead of
    // offset arithmetic.
    //   emplace_fn  — in-place constructs this alternative in the CHOICE struct
    //   get_mut_fn  — returns mutable pointer to the active alternative
    //   get_const_fn — returns const pointer to the active alternative
    void              (*emplace_fn)(Asn1Object* choice_ptr)          = nullptr;
    Asn1Object*       (*get_mut_fn)(Asn1Object* choice_ptr)          = nullptr;
    const Asn1Object* (*get_const_fn)(const Asn1Object* choice_ptr)  = nullptr;
};

// SEQUENCE OF / SET OF specifics.
// Collection operations are now virtual methods on SeqOfBase — no function pointers.
struct SeqOfSpec {
    const TypeDescriptor* element;         // element type descriptor
    Constraints        size_constraints; // SIZE constraint on collection length

    // Returns 0 when the collection satisfies SIZE(...), otherwise
    // signed delta (elements) such that (count + delta) lands at the nearest
    // valid bound: positive = too few, negative = too many.
    int64_t validate(const SeqOfBase& seq) const {
        if (!(size_constraints.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (size_constraints.flags & Constraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(seq.count());
        if (n < size_constraints.size_lower) return size_constraints.size_lower - n;
        if (n > size_constraints.size_upper) return size_constraints.size_upper - n;
        return 0;
    }
};

// SEQUENCE / SET specifics (mirrors asn_SEQUENCE_specifics_t).
struct SequenceSpec {
    const MemberDescriptor* members;
    int                     count;
    int                     ext_at;      // index of first extension member; -1 = none

    // PER: optional-member bitmap bookkeeping.
    // roms_count = number of root OPTIONAL/DEFAULT members (preamble bitmap width).
    // oms = indices (into members[]) of optional members, root ones first.
    // Zeros/nullptr until PER codegen is active.
    int        roms_count;
    int        aoms_count;
    const int* oms;
};

// CHOICE specifics.
// BER dispatch entry: maps one BER tag to the 0-based alternative index.
// Pre-computed for CHOICEs that have untagged CHOICE alternatives (nested flattening).
struct ChoiceTagEntry {
    Tag tag;
    int alt_index; // 0-based index into ChoiceSpec::alternatives
};

struct ChoiceSpec {
    const MemberDescriptor* alternatives;
    int                     count;
    int                     ext_at;

    // PER: default-constructed (flags==0) means unconstrained.
    Constraints constraints;

    // BER: flattened tag → alternative dispatch (X.690 §8.13, X.680 §24.6).
    // Non-null only when at least one alternative is itself an untagged CHOICE.
    // Existing initializers leave these zero/nullptr (valid: means use alternatives[].tag).
    const ChoiceTagEntry* ber_tags      = nullptr;
    int                   ber_tag_count = 0;

    // O(1) context-tag dispatch: tag_index[tag.number - tag_index_base] → alt index (0-based),
    // or -1 if not present. Non-null only when ALL alternatives carry a context tag and tags
    // are dense enough to fit in a small array. Generated by codegen; null = fall back to scan.
    const int16_t* tag_index      = nullptr;
    int            tag_index_base = 0;
    int            tag_index_size = 0;
};

// Codec dispatch discriminant — set once at descriptor definition time.
// Primitive: tag-number indexed table. Composites: spec-pointer indexed table.
enum class TypeKind : uint8_t {
    Primitive  = 0,  // dispatch via prim_dispatch_[tag.number]
    Any        = 1,
    Enumerated = 2,
    Sequence   = 3,  // also SET
    Choice     = 4,
    SeqOf      = 5,  // also SET OF
};

// Forward declaration — avoids circular dependency (PerCodec.hpp includes TypeDescriptor.hpp).
struct IPerTypeHandler;

// Top-level per-type descriptor (mirrors asn_TYPE_descriptor_t).
// Generated as `asn_DEF_<TypeName>` in the type's .cpp.
struct TypeDescriptor {
    const char*          name;
    Tag                  tag;
    const EnumSpec*      enum_spec;      // non-null for ENUMERATED
    const SequenceSpec*  sequence_spec;  // non-null for SEQUENCE/SET
    const ChoiceSpec*    choice_spec;    // non-null for CHOICE
    const SeqOfSpec*     seq_of_spec     = nullptr; // non-null for SEQUENCE OF / SET OF
    Constraints          constraints     = {};      // flags==0 means unconstrained
    bool     is_any = false;             // true for ANY — raw BER bytes, open-type in PER
    TypeKind kind   = TypeKind::Primitive;
    // Direct PER handler; null means fall back to PerCodec's LUT.
    const IPerTypeHandler* per_handler = nullptr;
};

// Built-in type descriptors — defined in runtime/src/BuiltinTypes.cpp (per_handler wired there).
// Used by generated SEQUENCE/CHOICE member tables for plain primitive members.
extern const TypeDescriptor asn_DEF_Any;
extern const TypeDescriptor asn_DEF_Integer;
extern const TypeDescriptor asn_DEF_Boolean;
extern const TypeDescriptor asn_DEF_Null;
extern const TypeDescriptor asn_DEF_Real;
extern const TypeDescriptor asn_DEF_BitString;
extern const TypeDescriptor asn_DEF_Oid;
extern const TypeDescriptor asn_DEF_RelativeOid;
extern const TypeDescriptor asn_DEF_UtcTime;
extern const TypeDescriptor asn_DEF_GeneralizedTime;
extern const TypeDescriptor asn_DEF_OctetString;
extern const TypeDescriptor asn_DEF_Utf8String;
extern const TypeDescriptor asn_DEF_Ia5String;
extern const TypeDescriptor asn_DEF_NumericString;
extern const TypeDescriptor asn_DEF_PrintableString;
extern const TypeDescriptor asn_DEF_T61String;
extern const TypeDescriptor asn_DEF_VisibleString;
extern const TypeDescriptor asn_DEF_GeneralString;
extern const TypeDescriptor asn_DEF_GraphicString;
extern const TypeDescriptor asn_DEF_UniversalString;
extern const TypeDescriptor asn_DEF_BmpString;
extern const TypeDescriptor asn_DEF_VideotexString;
extern const TypeDescriptor asn_DEF_ObjectDescriptor;

} // namespace asn1
