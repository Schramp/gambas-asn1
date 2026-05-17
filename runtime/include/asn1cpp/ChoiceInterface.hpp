#pragma once
#include "Asn1Object.hpp"

namespace asn1 {

// Non-virtual base for all generated CHOICE types.
// Provides a type-safe cast target from void* and direct access to _present.
// Codecs use spec.alternatives[] function pointers for emplace/get operations —
// no virtual dispatch needed because the codec already has the MemberDescriptor.
class ChoiceInterface : public Asn1Object {
public:
    int _present = 0;
    int  choice_present() const      { return _present; }
    void choice_set_present(int idx) { _present = idx; }
};

} // namespace asn1
