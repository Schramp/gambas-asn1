#pragma once
#include <cstddef>
#include <memory>
#include "Tag.hpp"
#include "codec/Constraints.hpp"

// C++ equivalents of asn1c's descriptor table types.
// Generated code fills these static tables; the runtime codec uses them.

namespace asn1 {

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

// Template that generates the three OptionalOps callbacks for a unique_ptr<T> member.
// Usage in generated code:
//   using _Ops_Type_member = asn1::UniquePtrOps<Type, MemberType, &Type::member>;
//   ... OptionalOps{ &_Ops_Type_member::check, &_Ops_Type_member::set, &_Ops_Type_member::get } ...
template<typename Owner, typename T, std::unique_ptr<T> Owner::* Mbr>
struct UniquePtrOps {
    static bool  check(const void* p) {
        return (bool)(static_cast<const Owner*>(p)->*Mbr);
    }
    static void  set(void* p, bool v) {
        auto& o = static_cast<Owner*>(p)->*Mbr;
        if (v) { if (!o) o = std::make_unique<T>(); } else o.reset();
    }
    static void* get(void* p) {
        return (static_cast<Owner*>(p)->*Mbr).get();
    }
};

// Encapsulates optional-member callbacks so codecs don't carry naked function
// pointers or repeat null checks.  get_ptr(struct*) returns T* from the
// unique_ptr<T> that stores the optional value; needed by table-driven codecs
// that must write into the allocated object, not the unique_ptr itself.
struct OptionalOps {
    bool  (*check)(const void*)  = nullptr;
    void  (*set)(void*, bool)    = nullptr;
    void* (*get_ptr)(void*)      = nullptr; // struct* → T* (dereferences unique_ptr)
    bool is_present(const void* p)  const { return check && check(p); }
    void set_present(void* p, bool v) const { if (set) set(p, v); }
    // Returns pointer to the actual member object (T*) given the parent struct.
    // Falls back to dest+offset path when get_ptr is null (required members).
    void* member_ptr(void* struct_ptr, std::size_t offset) const {
        return get_ptr ? get_ptr(struct_ptr)
                       : static_cast<char*>(struct_ptr) + offset;
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
    std::size_t           offset;         // offsetof(Struct, member) — for unique_ptr members,
                                          // points to the unique_ptr, not the contained value
    const TypeDescriptor* type_descriptor;
    OptionalOps           optional_ops;   // non-null only for optional/extension members
    bool                  is_explicit = false; // true → EXPLICIT tagging; false → IMPLICIT

    // BER/XER: when set, called after decode if the member was absent on the wire.
    // Allocates the optional and writes the DEFAULT value from the ASN.1 schema.
    // Null when no DEFAULT applies.
    void (*set_default)(void* owner) = nullptr;

    // BER encode: when set and returns true, the member is suppressed (X.690
    // §11.5: DEFAULT-equal values must not be encoded). True only when the
    // member is present AND its value equals the schema default.
    bool (*is_default_equal)(const void* owner) = nullptr;
};

// Template that generates the four SeqOfSpec callbacks for a std::vector-based SEQUENCE OF.
// Usage in generated code:
//   using _VecOps = asn1::VectorOps<CollectionType>;
//   ... SeqOfSpec{ ..., &_VecOps::count, &_VecOps::get_const, &_VecOps::get_mut, &_VecOps::resize } ...
template<typename Container>
struct VectorOps {
    static std::size_t count(const void* v) {
        return static_cast<const Container*>(v)->size();
    }
    static const void* get_const(const void* v, std::size_t i) {
        return static_cast<const Container*>(v)->data() + i;
    }
    static void* get_mut(void* v, std::size_t i) {
        return static_cast<Container*>(v)->data() + i;
    }
    static void resize(void* v, std::size_t n) {
        static_cast<Container*>(v)->resize(n);
    }
};

// SEQUENCE OF / SET OF specifics.
struct SeqOfSpec {
    const TypeDescriptor* element;         // element type descriptor
    Constraints        size_constraints; // SIZE constraint on collection length

    // Type-erased collection operations (generated per concrete vector type).
    std::size_t (*count_fn)(const void* vec);
    const void* (*get_const_fn)(const void* vec, std::size_t i);
    void*       (*get_fn)(void* vec, std::size_t i);
    void        (*resize_fn)(void* vec, std::size_t n);

    // Returns 0 when the collection at `vec` satisfies SIZE(...), otherwise
    // signed delta (elements) such that (count + delta) lands at the nearest
    // valid bound: positive = too few, negative = too many.
    int64_t validate(const void* vec) const {
        if (!(size_constraints.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (size_constraints.flags & Constraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(count_fn(vec));
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
};

// Top-level per-type descriptor (mirrors asn_TYPE_descriptor_t).
// Generated as `asn_DEF_<TypeName>` in the type's .cpp.
struct TypeDescriptor {
    const char*          name;
    Tag                  tag;
    const EnumSpec*      enum_spec;      // non-null for ENUMERATED
    const SequenceSpec*  sequence_spec;  // non-null for SEQUENCE/SET
    const ChoiceSpec*    choice_spec;    // non-null for CHOICE
    const SeqOfSpec*     seq_of_spec;    // non-null for SEQUENCE OF / SET OF
    Constraints constraints; // flags==0 means unconstrained
    bool is_any = false;            // true for ANY — raw BER bytes, open-type in PER
};

// Built-in type descriptors — used by generated SEQUENCE/CHOICE member tables
// to fill type_descriptor pointers for plain primitive members.
inline const TypeDescriptor asn_DEF_Any          = { "ANY",          Tag::universal( 4, false), nullptr, nullptr, nullptr, nullptr, {}, true };
inline const TypeDescriptor asn_DEF_Integer      = { "INTEGER",      Tag::universal( 2, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Boolean      = { "BOOLEAN",      Tag::universal( 1, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Null         = { "NULL",         Tag::universal( 5, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Real         = { "REAL",         Tag::universal( 9, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_BitString    = { "BIT_STRING",        Tag::universal( 3, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Oid          = { "OBJECT_IDENTIFIER", Tag::universal( 6, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_RelativeOid  = { "RELATIVE_OID",      Tag::universal(13, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_UtcTime      = { "UTCTime",       Tag::universal(23, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_GeneralizedTime = { "GeneralizedTime", Tag::universal(24, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_OctetString    = { "OCTET_STRING",   Tag::universal( 4, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Utf8String     = { "UTF8String",     Tag::universal(12, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_Ia5String      = { "IA5String",      Tag::universal(22, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_NumericString  = { "NumericString",  Tag::universal(18, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_PrintableString= { "PrintableString",Tag::universal(19, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_T61String      = { "T61String",      Tag::universal(20, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_VisibleString  = { "VisibleString",  Tag::universal(26, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_GeneralString  = { "GeneralString",  Tag::universal(27, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_GraphicString  = { "GraphicString",  Tag::universal(25, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_UniversalString= { "UniversalString",Tag::universal(28, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_BmpString      = { "BMPString",      Tag::universal(30, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_VideotexString = { "VideotexString", Tag::universal(21, false), nullptr, nullptr, nullptr };
inline const TypeDescriptor asn_DEF_ObjectDescriptor={ "ObjectDescriptor",Tag::universal(7, false), nullptr, nullptr, nullptr };

} // namespace asn1
