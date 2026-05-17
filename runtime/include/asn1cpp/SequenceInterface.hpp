#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"

namespace asn1 {

// Non-virtual CRTP base for all generated SEQUENCE / SET types.
//
// Provides typed member access via the static s_members[] descriptor table.
// Codecs iterate spec.members[] directly and call optional_ops.member_ptr for
// pointer resolution — these helpers are for non-codec callers (tests,
// introspection) where the concrete type is known.
//
// No virtual methods → no vtable overhead on generated struct instances.
template<typename Derived>
class SequenceBase : public Asn1Object {
public:
    int member_count() const {
        return Derived::s_member_count;
    }

    // Pointer to member i. Returns null if optional and absent.
    Asn1Object* get_member(int i) {
        const auto& desc = Derived::s_members[i];
        return static_cast<Asn1Object*>(
            desc.optional_ops.member_ptr(static_cast<Derived*>(this), desc.offset));
    }

    const Asn1Object* get_member(int i) const {
        const auto& desc = Derived::s_members[i];
        return static_cast<const Asn1Object*>(
            desc.optional_ops.member_ptr(static_cast<const Derived*>(this), desc.offset));
    }

    // Pointer to member i, allocating the unique_ptr if optional and absent.
    Asn1Object* get_or_create_member(int i) {
        const auto& desc = Derived::s_members[i];
        desc.optional_ops.set_present(static_cast<Derived*>(this), true);
        return static_cast<Asn1Object*>(
            desc.optional_ops.member_ptr(static_cast<Derived*>(this), desc.offset));
    }

    const MemberDescriptor& member_desc(int i) const {
        return Derived::s_members[i];
    }
};

} // namespace asn1
