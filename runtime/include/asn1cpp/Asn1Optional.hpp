#pragma once
#include <asn1cpp/Asn1Object.hpp>
#include <asn1cpp/TypeDescriptor.hpp>

namespace asn1 {

/// @brief Non-template base for Asn1Optional<T>.
///
/// Holds the three fields the projection engine needs without knowing T.
/// Asn1OptionalBase is always the first base in Asn1Optional<T> so that
/// Asn1Optional<T>* → Asn1OptionalBase* is a free conversion (same address).
///
/// The field is named `found` (not `present`) to avoid collision with the
/// `present()` method generated on ENUMERATED and CHOICE types.
struct Asn1OptionalBase {
    bool                  found     = false;   ///< True after apply() populates this field.
    Asn1Object*           value_ptr = nullptr; ///< Points to the T sub-object within Asn1Optional<T>.
    const TypeDescriptor* desc      = nullptr; ///< &T::asn_DEF; set at construction.
};

/// @brief Optional-semantics wrapper for a generated ASN.1 type T.
///
/// Inherits Asn1OptionalBase first (offset 0) then T. The projection engine
/// works entirely through Asn1OptionalBase* — template-free. Callers access
/// the value by casting: `static_cast<T&>(opt)`.
///
/// Usage:
/// @code
/// Asn1Optional<VisibleString> liid;
/// res.bind(h_liid, liid);
/// res.apply(frame);
/// if (liid.found)
///     use(static_cast<VisibleString&>(liid));
/// @endcode
///
/// @tparam T Any generated ASN.1 type that inherits Asn1Object and carries asn_DEF.
template<typename T>
struct Asn1Optional : Asn1OptionalBase, T {
    static_assert(std::is_base_of_v<Asn1Object, T>,
                  "Asn1Optional<T>: T must inherit Asn1Object");

    Asn1Optional() {
        value_ptr = static_cast<Asn1Object*>(static_cast<T*>(this));
        desc      = &T::asn_DEF;
        found     = false;
    }
};

} // namespace asn1
