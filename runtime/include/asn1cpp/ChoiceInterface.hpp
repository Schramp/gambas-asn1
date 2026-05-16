#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"

namespace asn1 {

// Abstract interface for CHOICE types.
// Lets codec handlers call virtual methods instead of reading _present via
// raw int* cast and calling emplace/get function pointers.
//
// Generated structs inherit ChoiceBase<Derived> which implements this via
// Derived::s_alternatives[], Derived::s_alternative_count, and Derived::_present.
class ChoiceInterface : public Asn1Object {
public:
    virtual ~ChoiceInterface() = default;
    virtual int         choice_present()                        const = 0;  // 0 = NOTHING
    virtual void        choice_set_present(int idx)                   = 0;  // does NOT emplace
    virtual void        choice_emplace(int idx)                       = 0;  // emplace variant only
    virtual void*       choice_member_ptr(int idx)                    = 0;  // 1-based idx
    virtual const void* choice_member_const_ptr(int idx)        const = 0;
    virtual int         choice_alt_count()                      const = 0;
    virtual const MemberDescriptor& choice_alt_desc(int i)     const = 0;  // 0-based
};

template<typename Derived>
class ChoiceBase : public ChoiceInterface {
public:
    int choice_present() const override {
        return static_cast<const Derived*>(this)->_present;
    }

    void choice_set_present(int idx) override {
        static_cast<Derived*>(this)->_present = idx;
    }

    void choice_emplace(int idx) override {
        if (idx <= 0 || idx > Derived::s_alternative_count) return;
        const auto& alt = Derived::s_alternatives[idx - 1];
        if (alt.emplace_fn) alt.emplace_fn(static_cast<Derived*>(this));
    }

    void* choice_member_ptr(int idx) override {
        if (idx <= 0 || idx > Derived::s_alternative_count) return nullptr;
        const auto& alt = Derived::s_alternatives[idx - 1];
        Derived* self = static_cast<Derived*>(this);
        return alt.get_mut_fn ? alt.get_mut_fn(self)
                              : reinterpret_cast<char*>(self) + alt.offset;
    }

    const void* choice_member_const_ptr(int idx) const override {
        if (idx <= 0 || idx > Derived::s_alternative_count) return nullptr;
        const auto& alt = Derived::s_alternatives[idx - 1];
        const Derived* self = static_cast<const Derived*>(this);
        return alt.get_const_fn ? alt.get_const_fn(self)
                                : reinterpret_cast<const char*>(self) + alt.offset;
    }

    int choice_alt_count() const override {
        return Derived::s_alternative_count;
    }

    const MemberDescriptor& choice_alt_desc(int i) const override {
        return Derived::s_alternatives[i];
    }
};

} // namespace asn1
