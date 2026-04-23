#pragma once
#include <cstddef>
#include "Tag.hpp"

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
};

// Per-member SEQUENCE/SET/CHOICE descriptor (mirrors asn_TYPE_member_t).
struct MemberDescriptor {
    const char*  name;
    Tag          tag;             // effective tag (after implicit/explicit)
    bool         optional;
    bool         has_default;
    std::size_t  offset;          // offsetof into the containing struct
    const void*  type_descriptor; // cast to TypeDescriptor* in codec
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
struct ChoiceSpec {
    const MemberDescriptor* alternatives;
    int                     count;
    int                     ext_at;

    // PER: nullptr until PER codegen is active.
    const void* per_constraints; // cast to PerConstraints* in PerCodec
};

// Top-level per-type descriptor (mirrors asn_TYPE_descriptor_t).
// Generated as `asn_DEF_<TypeName>` in the type's .cpp.
struct TypeDescriptor {
    const char*          name;
    Tag                  tag;
    const EnumSpec*      enum_spec;     // non-null for ENUMERATED
    const SequenceSpec*  sequence_spec; // non-null for SEQUENCE/SET
    const ChoiceSpec*    choice_spec;   // non-null for CHOICE
};

} // namespace asn1
