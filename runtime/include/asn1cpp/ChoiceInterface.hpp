#pragma once
#include "Asn1Object.hpp"
#include "TypeDescriptor.hpp"
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace asn1 {

/// @brief View of an alternative of an extensible CHOICE that this schema
///        version does not define, kept as the codec carried it so it can
///        be relayed (X.680 §52.1: extension additions are not a decoding
///        error). Valid until the CHOICE changes.
///
/// BER carries the alternative's TLV: \c tag (constructed bit included) and
/// \c bytes, its contents octets. PER carries the extension index past the
/// known alternatives (X.691 §23) and the open-type octets (§11.2).
struct ChoiceUnknownExtension {
    enum class Origin : uint8_t { Ber, Per };
    Origin                   origin = Origin::Ber;  ///< Codec it was read from.
    Tag                      tag{};                  ///< BER: the TLV's tag.
    long                     index = 0;              ///< PER: extension index past the known ones.
    std::span<const uint8_t> bytes;                  ///< BER contents octets / PER open-type octets.
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
    /// Lifecycles of an unknown extension alternative held in the storage as
    /// a \c std::string; which one is active records the codec it came from.
    static const TypeLifecycleOps k_unknown_ber_lifecycle;
    static const TypeLifecycleOps k_unknown_per_lifecycle;

    int                      _present         = 0;
    char*                    val_             = nullptr;           // set to val_storage_ in derived ctor
    const TypeLifecycleOps*  active_lifecycle = &k_noop_lifecycle; // ptr into TypeDescriptor::lifecycle

    int  choice_present() const      { return _present; }

    /// @brief The unknown extension alternative held (\c _present is 0), or
    ///        nothing. The view points into this CHOICE's storage.
    std::optional<ChoiceUnknownExtension> unknown_extension() const {
        const bool ber = active_lifecycle == &k_unknown_ber_lifecycle;
        if (!ber && active_lifecycle != &k_unknown_per_lifecycle) return std::nullopt;
        const std::string& s = *std::launder(reinterpret_cast<const std::string*>(val_));
        const auto* p = reinterpret_cast<const uint8_t*>(s.data());
        ChoiceUnknownExtension ext;
        if (ber) {
            ext.origin = ChoiceUnknownExtension::Origin::Ber;
            ext.tag.cls = static_cast<TagClass>(p[0]);
            ext.tag.constructed = p[1] != 0;
            std::memcpy(&ext.tag.number, p + 2, sizeof ext.tag.number);
            ext.bytes = {p + kBerHeader, s.size() - kBerHeader};
        } else {
            ext.origin = ChoiceUnknownExtension::Origin::Per;
            std::memcpy(&ext.index, p, sizeof ext.index);
            ext.bytes = {p + kPerHeader, s.size() - kPerHeader};
        }
        return ext;
    }

    /// @brief Select nothing and keep a BER alternative of a newer schema
    ///        version: its tag and contents octets (X.680 §52.1, X.690 §8.1).
    ///        Only an extensible CHOICE's storage is sized for it.
    /// @param tag       The TLV's tag.
    /// @param contents  The TLV's contents octets.
    void set_unknown_ber(Tag tag, std::span<const uint8_t> contents) {
        std::string& s = hold_unknown(k_unknown_ber_lifecycle);
        s.resize(kBerHeader + contents.size());
        s[0] = static_cast<char>(tag.cls);
        s[1] = tag.constructed ? 1 : 0;
        std::memcpy(s.data() + 2, &tag.number, sizeof tag.number);
        if (!contents.empty()) std::memcpy(s.data() + kBerHeader, contents.data(), contents.size());
    }

    /// @brief Select nothing and keep a PER alternative of a newer schema
    ///        version: its extension index and open-type octets (X.691 §23.8).
    ///        Only an extensible CHOICE's storage is sized for it.
    /// @param index   Extension index past the known alternatives.
    /// @param octets  The open-type field's octets (§11.2).
    void set_unknown_per(long index, std::span<const uint8_t> octets) {
        std::string& s = hold_unknown(k_unknown_per_lifecycle);
        s.resize(kPerHeader + octets.size());
        std::memcpy(s.data(), &index, sizeof index);
        if (!octets.empty()) std::memcpy(s.data() + kPerHeader, octets.data(), octets.size());
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
        ops.construct(val_);
        active_lifecycle = &ops;
        _present = present;
    }

private:
    static constexpr std::size_t kBerHeader = 2 + sizeof(uint32_t);  // class, constructed, number
    static constexpr std::size_t kPerHeader = sizeof(long);           // extension index

    /// @brief Replace the current occupant with an empty \c std::string
    ///        under \p ops, with nothing selected.
    std::string& hold_unknown(const TypeLifecycleOps& ops) {
        active_lifecycle->destroy(val_);
        active_lifecycle = &k_noop_lifecycle;
        _present = 0;
        ops.construct(val_);
        active_lifecycle = &ops;
        return *std::launder(reinterpret_cast<std::string*>(val_));
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
