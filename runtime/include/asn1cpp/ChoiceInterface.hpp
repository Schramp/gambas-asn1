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
    void choice_set_present(int idx) { _present = idx; }

    // Generic emplace: destroy current occupant then placement-new the new alternative.
    // Single pointer assignment replaces old separate destroy_fn_ / move_fn_ writes.
    // alt.type_descriptor->lifecycle must be fully populated (guaranteed for all
    // TypeDescriptors referenced from ChoiceSpec::alternatives).
    void emplace_alt(const MemberDescriptor& alt) noexcept {
        active_lifecycle->destroy(val_);
        alt.type_descriptor->lifecycle.construct(val_);
        active_lifecycle = &alt.type_descriptor->lifecycle;
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

} // namespace asn1
