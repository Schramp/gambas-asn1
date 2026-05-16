#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"

namespace asn1 {

// Abstract interface for SEQUENCE / SET types.
// Lets codec handlers call virtual methods on a typed interface instead of
// doing raw offset arithmetic on void*.
//
// Generated structs inherit SequenceBase<Derived> which implements this via
// Derived::s_members[] and Derived::s_member_count.
class SequenceInterface : public Asn1Object {
public:
    virtual ~SequenceInterface() = default;
    virtual int                     seq_member_count()              const = 0;
    virtual void*                   seq_member_ptr(int i)                 = 0;
    virtual const void*             seq_member_ptr(int i)           const = 0;
    virtual bool                    seq_member_present(int i)       const = 0;
    virtual bool                    seq_is_default_equal(int i)     const = 0;
    virtual void                    seq_set_present(int i, bool v)        = 0;
    virtual void                    seq_set_default(int i)                = 0;
    virtual const MemberDescriptor& seq_member_desc(int i)         const = 0;
};

template<typename Derived>
class SequenceBase : public SequenceInterface {
public:
    int seq_member_count() const override {
        return Derived::s_member_count;
    }

    void* seq_member_ptr(int i) override {
        const auto& desc = Derived::s_members[i];
        return desc.optional_ops.member_ptr(static_cast<Derived*>(this), desc.offset);
    }

    const void* seq_member_ptr(int i) const override {
        const auto& desc = Derived::s_members[i];
        return desc.optional_ops.member_ptr(static_cast<const Derived*>(this), desc.offset);
    }

    bool seq_member_present(int i) const override {
        const auto& desc = Derived::s_members[i];
        if (!desc.optional_ops.check) return true;
        return desc.optional_ops.check(static_cast<const Derived*>(this));
    }

    bool seq_is_default_equal(int i) const override {
        const auto& desc = Derived::s_members[i];
        if (!desc.is_default_equal) return false;
        return desc.is_default_equal(static_cast<const Derived*>(this));
    }

    void seq_set_present(int i, bool v) override {
        const auto& desc = Derived::s_members[i];
        desc.optional_ops.set_present(static_cast<Derived*>(this), v);
    }

    void seq_set_default(int i) override {
        const auto& desc = Derived::s_members[i];
        if (desc.set_default) desc.set_default(static_cast<Derived*>(this));
    }

    const MemberDescriptor& seq_member_desc(int i) const override {
        return Derived::s_members[i];
    }
};

} // namespace asn1
