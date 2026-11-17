#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"
#include <memory>

namespace asn1 {

// Non-virtual base for all generated CHOICE types.
// Holds the active-alternative pointer, destroy/move fn-ptrs, and _present index.
// Codecs use spec.alternatives[] get_mut_fn/get_const_fn for access; emplace_alt
// uses TypeDescriptor::lifecycle for construction — no virtual dispatch needed.
class ChoiceInterface : public Asn1Object {
public:
    // Noop lifecycle used for the NOTHING state: destroy/move are no-ops so
    // destructors and move operations never need a null check on active_lifecycle.
    static const TypeLifecycleOps k_noop_lifecycle;

    int                      _present         = 0;
    char*                    val_             = nullptr;           // set to val_storage_ in derived ctor
    const TypeLifecycleOps*  active_lifecycle = &k_noop_lifecycle; // ptr into TypeDescriptor::lifecycle

    int  choice_present() const      { return _present; }

    /// @brief Select a CHOICE alternative: destroy the current occupant,
    ///        placement-new a default \p alt in the shared storage, and record
    ///        it as \c _present in the same step.
    ///
    /// \c _present, \c active_lifecycle and the storage always name the same
    /// alternative: encode, deep_copy, the accessors and a later decode that
    /// skips re-emplacing all read the storage as the type \c _present names.
    /// A decoder that fails inside the alternative leaves it selected with a
    /// partial value, never the previous index over the new storage.
    /// \p alt's lifecycle comes from its TypeDescriptor, or from
    /// \c alt.boxed_lifecycle for a self-referential (unique_ptr-boxed)
    /// alternative, whose storage isn't a plain T (see MemberDescriptor's doc).
    /// @param alt      The alternative's member descriptor (ChoiceSpec::alternatives).
    /// @param present  Its 1-based index, stored as \c _present.
    void emplace_alt(const MemberDescriptor& alt, int present) noexcept {
        const TypeLifecycleOps& ops = alt.boxed_lifecycle ? *alt.boxed_lifecycle : alt.type_descriptor->lifecycle;
        active_lifecycle->destroy(val_);
        active_lifecycle = &k_noop_lifecycle;
        _present = 0;
        ops.construct(val_);
        active_lifecycle = &ops;
        _present = present;
    }
};

// Single-type-param accessor template: replaces per-alternative _get_mut_T_alt /
// _get_const_T_alt named free functions.  Instantiated in generated .cpp files
// where AltT is fully defined.  No ChoiceT param needed — val_ is in the base.
template<typename AltT>
struct ChoiceOps {
    static Asn1Object* get_mut(Asn1Object* p) {
        return std::launder(
            reinterpret_cast<AltT*>(static_cast<ChoiceInterface*>(p)->val_));
    }
    static const Asn1Object* get_const(const Asn1Object* p) {
        return std::launder(
            reinterpret_cast<const AltT*>(static_cast<const ChoiceInterface*>(p)->val_));
    }
};

// Accessor for a self-referential CHOICE alternative boxed as
// std::unique_ptr<AltT> (see TypeLifecycleOps's BoxedTypeTag constructor) —
// val_ holds the unique_ptr itself, not an AltT, so an extra ->get() applies.
template<typename AltT>
struct BoxedChoiceOps {
    static Asn1Object* get_mut(Asn1Object* p) {
        return std::launder(reinterpret_cast<std::unique_ptr<AltT>*>(
            static_cast<ChoiceInterface*>(p)->val_))->get();
    }
    static const Asn1Object* get_const(const Asn1Object* p) {
        return std::launder(reinterpret_cast<const std::unique_ptr<AltT>*>(
            static_cast<const ChoiceInterface*>(p)->val_))->get();
    }
};

} // namespace asn1
