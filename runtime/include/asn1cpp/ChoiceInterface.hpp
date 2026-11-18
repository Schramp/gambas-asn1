#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace asn1 {

/// @brief An alternative of an extensible CHOICE that this schema version
///        does not define, kept as the codec carried it so it can be
///        relayed (X.680 §52.1: extension additions are not a decoding
///        error).
///
/// BER carries the alternative's TLV: \c tag (constructed bit included) and
/// \c bytes, its contents octets. PER carries the extension index past the
/// known alternatives (X.691 §23) and the open-type octets (§11.2).
struct ChoiceUnknownExtension {
    enum class Origin : uint8_t { Ber, Per };
    Origin               origin = Origin::Ber;  ///< Codec it was read from.
    Tag                  tag{};                  ///< BER: the TLV's tag.
    long                 index = 0;              ///< PER: extension index past the known ones.
    std::vector<uint8_t> bytes;                  ///< BER contents octets / PER open-type octets.
};

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

    /// Unknown extension alternative, set only while \c _present is 0.
    std::unique_ptr<ChoiceUnknownExtension> unknown_ext_;

    int  choice_present() const      { return _present; }

    /// @brief The unknown extension alternative held, or nullptr.
    const ChoiceUnknownExtension* unknown_extension() const { return unknown_ext_.get(); }

    /// @brief Select nothing and keep \p ext, an alternative of a newer
    ///        schema version read by a decoder (X.680 §52.1).
    /// @param ext  The alternative as its codec carried it.
    void set_unknown_extension(ChoiceUnknownExtension ext) {
        active_lifecycle->destroy(val_);
        active_lifecycle = &k_noop_lifecycle;
        _present = 0;
        unknown_ext_ = std::make_unique<ChoiceUnknownExtension>(std::move(ext));
    }

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
        unknown_ext_.reset();
        ops.construct(val_);
        active_lifecycle = &ops;
        _present = present;
    }
};

/// @brief Encode error for an unknown CHOICE extension alternative that
///        \p codec cannot write back, e.g. "CHOICE Msg: extension
///        alternative of a newer schema version, read from PER, has no BER
///        encoding".
inline std::string choice_unknown_encode_error(const char* type_name, const ChoiceUnknownExtension& ext,
                                               const char* codec) {
    return std::string("CHOICE ") + type_name + ": extension alternative of a newer schema version, read from " +
           (ext.origin == ChoiceUnknownExtension::Origin::Ber ? "BER" : "PER") + ", has no " + codec + " encoding";
}

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
