#pragma once
#include <cstddef>
#include <memory>
#include "Tag.hpp"
#include "SeqOfBase.hpp"
#include "codec/Constraints.hpp"

/// C++ equivalents of asn1c's descriptor table types.
/// Generated code fills these static tables; the runtime codec uses them.

namespace asn1 {

/// @brief Sentinel offset used in \c MemberDescriptor::offset when direct byte
/// access is not applicable (optional members with \c UniquePtrOps, CHOICE alternatives).
/// Set to the high bit of \c size_t — any accidental use in pointer arithmetic
/// maps to kernel address space and faults immediately on any architecture.
inline constexpr std::size_t kInvalidMemberOffset =
    std::size_t{1} << (sizeof(std::size_t) * 8 - 1);

/// @brief One row in an ENUMERATED value↔name map.
/// The table is sorted by \c value to allow binary search during BER/XER encode/decode.
/// @see X.680 §19 — ENUMERATED type.
struct EnumEntry {
    long        value;  ///< Numeric enumeration value (from ASN.1 definition).
    const char* name;   ///< ASN.1 identifier name (used in XER output and error messages).
};

/// @brief Per-type ENUMERATED metadata table.
/// Mirrors \c asn_INTEGER_specifics_t from asn1c.
/// @see X.680 §19 — ENUMERATED type; X.690 §8.4 — BER ENUMERATED encoding.
struct EnumSpec {
    const EnumEntry* entries;       ///< Value↔name table, sorted by value (BER/XER binary search).
    int              count;         ///< Total entry count (root + extension).
    bool             extensible;    ///< True if the ENUMERATED has an extension marker.

    /// PER: root values in ASN.1 definition order (ordinal → value mapping).
    /// Root ordinal 0 = first enumeration value in the ASN.1 source.
    /// Nullptr for non-extensible types where count == root_count.
    int              root_count;       ///< Number of root (non-extension) enumeration values.
    const long*      per_value_order;  ///< [root_count] values in definition order (PER).

    /// @brief Return 0 if \p v is a known enumeration value (root or extension), else 1.
    int64_t validate(long v) const {
        for (int i = 0; i < count; ++i)
            if (entries[i].value == v) return 0;
        return 1;
    }
};

/// @brief Portable offsetof for non-standard-layout types (SequenceBase<T> has virtual methods).
#if defined(__GNUC__) || defined(__clang__)
#  define ASN1CPP_OFFSETOF(T, m) __builtin_offsetof(T, m)
#else
#  define ASN1CPP_OFFSETOF(T, m) offsetof(T, m)
#endif

/// @brief Generates the three \c OptionalOps callbacks for a \c unique_ptr<T> member.
///
/// Emitted by codegen for every optional/extension SEQUENCE member that is stored as
/// \c std::unique_ptr<MemberType>.
///
/// Usage in generated code:
/// @code
/// using _Ops_Type_member = asn1::UniquePtrOps<Type, MemberType, &Type::member>;
/// // then in MemberDescriptor:
/// OptionalOps{ &_Ops_Type_member::check, &_Ops_Type_member::set, &_Ops_Type_member::get }
/// @endcode
///
/// @tparam Owner  The containing generated struct type.
/// @tparam T      The pointed-to member type.
/// @tparam Mbr    Pointer-to-member selecting the \c unique_ptr field.
template<typename Owner, typename T, std::unique_ptr<T> Owner::* Mbr>
struct UniquePtrOps {
    /// @brief Return true if the unique_ptr is non-null (member is present).
    static bool        check(const Asn1Object* p) {
        return (bool)(static_cast<const Owner*>(p)->*Mbr);
    }
    /// @brief Set or clear the unique_ptr (allocating a default-constructed T on set).
    static void        set(Asn1Object* p, bool v) {
        auto& o = static_cast<Owner*>(p)->*Mbr;
        if (v) { if (!o) o = std::make_unique<T>(); } else o.reset();
    }
    /// @brief Return the T* held inside the unique_ptr (null if not present).
    static Asn1Object* get(Asn1Object* p) {
        return (static_cast<Owner*>(p)->*Mbr).get();
    }
};

/// @brief Encapsulates optional-member lifecycle callbacks for table-driven codecs.
///
/// One \c OptionalOps is embedded in every \c MemberDescriptor.  For required members
/// all three pointers are null; for optional/extension members they are set via
/// \c UniquePtrOps.
///
/// \c member_ptr() is the primary access path — it hides the two-case logic
/// (direct offset ADD vs. unique_ptr dereference) behind a single call.
struct OptionalOps {
    bool        (*check)(const Asn1Object*)  = nullptr; ///< True if member is present (unique_ptr non-null).
    void        (*set)(Asn1Object*, bool)    = nullptr; ///< Allocate or reset the unique_ptr.
    Asn1Object* (*get_ptr)(Asn1Object*)      = nullptr; ///< Return T* from inside the unique_ptr (null for required members).

    /// @brief Return true if this optional member is present in \p p.
    bool is_present(const Asn1Object* p)  const { return check && check(p); }
    /// @brief Return true if this optional member is present in \p p (void* overload).
    bool is_present(const void* p)         const { return is_present(static_cast<const Asn1Object*>(p)); }
    /// @brief Set or clear presence of this member in \p p.
    void set_present(Asn1Object* p, bool v) const { if (set) set(p, v); }
    /// @brief Set or clear presence of this member in \p p (void* overload).
    void set_present(void* p, bool v)       const { set_present(static_cast<Asn1Object*>(p), v); }

    /// @brief Return a pointer to the member value within owner \p p.
    ///
    /// Two cases:
    /// - \c get_ptr != null (optional members): dereferences the unique_ptr at the
    ///   member's location and returns the T* inside it.
    /// - \c get_ptr == null (required members): computes address as
    ///   \c (char*)p + offset (one ADD instruction, no indirection).
    ///
    /// The void* round-trip in the offset path is standard-required: C++ forbids
    /// \c static_cast<char*> from a pointer-to-class.
    ///
    /// @see OptionalOps — UniquePtrOps design rationale in TypeDescriptor.hpp.
    Asn1Object* member_ptr(Asn1Object* p, std::size_t offset) const {
        return get_ptr ? get_ptr(p)
                       : static_cast<Asn1Object*>(static_cast<void*>(
                             static_cast<char*>(static_cast<void*>(p)) + offset));
    }
    /// @brief Const overload of \c member_ptr.
    const Asn1Object* member_ptr(const Asn1Object* p, std::size_t offset) const {
        return get_ptr ? get_ptr(const_cast<Asn1Object*>(p))
                       : static_cast<const Asn1Object*>(static_cast<const void*>(
                             static_cast<const char*>(static_cast<const void*>(p)) + offset));
    }

    /// @brief True if this \c OptionalOps is wired (member is optional/extension).
    explicit operator bool() const { return check != nullptr; }
};

/// Forward declaration — MemberDescriptor references TypeDescriptor.
struct TypeDescriptor;

/// @brief Per-member descriptor for SEQUENCE, SET, and CHOICE types.
/// Mirrors \c asn_TYPE_member_t from asn1c.  One entry per member in the
/// generated \c asn_MBR_<Type>[] table.
/// @see X.680 §24 — SEQUENCE type; X.680 §28 — CHOICE type.
struct MemberDescriptor {
    const char*           name;             ///< ASN.1 member name (used in XER tags and diagnostics).
    Tag                   tag;              ///< Effective wire tag (context tag when tagged, natural otherwise).
    bool                  optional;         ///< True for OPTIONAL and DEFAULT members, all extension members.
    bool                  has_default;      ///< True when a DEFAULT value is defined.
    std::size_t           offset;           ///< \c offsetof(Struct, member); \c kInvalidMemberOffset for CHOICE alternatives.
    const TypeDescriptor* type_descriptor;  ///< TypeDescriptor of this member's type.
    OptionalOps           optional_ops;     ///< Non-null only for optional/extension members (UniquePtrOps).
    bool                  is_explicit = false; ///< True → EXPLICIT tagging; false → IMPLICIT.
    /// True when this member/alternative names its own `[n]` tag override
    /// (X.680 §30.1/30.3 TaggedType construction). False when `tag` merely
    /// restates the referenced type's own tag for dispatch/presence
    /// purposes (a bare `x SomeType` reference, no `[n]` written on the
    /// member) — in that case the wire encoding is exactly SomeType's own
    /// standalone encoding; the codec must not wrap/unwrap an extra layer.
    bool                  tag_is_override = true;

    /// @brief Called after BER/XER decode when the member was absent on the wire.
    /// Allocates the optional and writes the DEFAULT value from the ASN.1 schema.
    /// Null when no DEFAULT applies.
    /// @see X.690 §11.5 — DEFAULT values.
    void (*set_default)(Asn1Object* owner) = nullptr;

    /// @brief BER encode gate: return true to suppress this member.
    /// Per X.690 §11.5, a member whose value equals the schema DEFAULT must not
    /// be encoded.  Null for non-DEFAULT members.
    bool (*is_default_equal)(const Asn1Object* owner) = nullptr;

    /// @brief Return mutable pointer to the active CHOICE alternative (null for non-CHOICE members).
    Asn1Object*       (*get_mut_fn)(Asn1Object* choice_ptr)          = nullptr;
    /// @brief Return const pointer to the active CHOICE alternative (null for non-CHOICE members).
    const Asn1Object* (*get_const_fn)(const Asn1Object* choice_ptr)  = nullptr;
};

/// @brief SEQUENCE OF / SET OF element and constraint metadata.
struct SeqOfSpec {
    const TypeDescriptor* element;                    ///< TypeDescriptor of the element type.
    Constraints           size_constraints;           ///< SIZE constraint on collection length.
    const char*           element_xer_tag = nullptr;  ///< X.693 §12: declared element tag name; nullptr = use element->name.

    /// @brief Return 0 if the collection satisfies SIZE(…), else signed delta to nearest valid bound.
    /// Positive = too few elements; negative = too many.
    int64_t validate(const SeqOfBase& seq) const {
        if (!(size_constraints.flags & Constraints::SIZE_CONSTRAINED)) return 0;
        if (size_constraints.flags & Constraints::EXTENSIBLE) return 0;
        auto n = static_cast<int64_t>(seq.count());
        if (n < size_constraints.size_lower) return size_constraints.size_lower - n;
        if (n > size_constraints.size_upper) return size_constraints.size_upper - n;
        return 0;
    }
};

/// @brief SEQUENCE / SET member list and PER optional-bitmap bookkeeping.
/// Mirrors \c asn_SEQUENCE_specifics_t from asn1c.
/// @see X.680 §24 — SEQUENCE type.
struct SequenceSpec {
    const MemberDescriptor* members;    ///< Array of member descriptors (length = \c count).
    int                     count;      ///< Total member count (root + extension).
    int                     ext_at;     ///< Index of first extension member; -1 = no extension marker.

    /// PER: root optional-member bitmap width (preamble bit count before any values).
    int        roms_count; ///< Number of root OPTIONAL/DEFAULT members. Zero until PER codegen active.
    int        aoms_count; ///< Number of extension optional members. Zero until PER codegen active.
    const int* oms;        ///< Indices into \c members[] of optional members, root first. Nullptr until PER codegen active.
};

/// @brief One BER dispatch entry: maps one BER tag to a CHOICE alternative index.
/// Pre-computed for CHOICEs that contain untagged CHOICE alternatives (nested flattening).
/// @see X.690 §8.13 — CHOICE encoding; X.680 §24.6 — tagging alternatives.
struct ChoiceTagEntry {
    Tag tag;       ///< BER tag of the alternative (or its flattened inner alternative).
    int alt_index; ///< 0-based index into \c ChoiceSpec::alternatives.
};

/// @brief CHOICE alternative list and BER dispatch tables.
/// @see X.680 §28 — CHOICE type; X.690 §8.13 — BER CHOICE encoding.
struct ChoiceSpec {
    const MemberDescriptor* alternatives; ///< Array of alternative descriptors (length = \c count).
    int                     count;        ///< Total alternative count (root + extension).
    int                     ext_at;       ///< Index of first extension alternative; -1 = none.

    /// PER: constraint on the CHOICE index encoding. Default-constructed (flags==0) = unconstrained.
    Constraints constraints;

    /// @brief BER flattened tag → alternative dispatch table.
    /// Non-null only when at least one alternative is itself an untagged CHOICE.
    /// Null = use \c alternatives[].tag directly (the common case).
    const ChoiceTagEntry* ber_tags      = nullptr;
    int                   ber_tag_count = 0;

    /// @brief O(1) context-tag dispatch: \c tag_index[tag.number - tag_index_base] → alt index (0-based), or -1.
    /// Non-null only when ALL alternatives carry a context tag and tags are dense enough for a small array.
    /// Null = fall back to linear scan.
    const int16_t* tag_index      = nullptr;
    int            tag_index_base = 0;
    int            tag_index_size = 0;
};

/// @brief Codec dispatch discriminant — set once at descriptor definition time.
/// Determines which entry in the codec's handler lookup table is used.
enum class TypeKind : uint8_t {
    Primitive  = 0,  ///< Dispatch via \c prim_dispatch_[tag.number].
    Any        = 1,  ///< Open type (raw BER bytes; open-type wrapper in PER).
    Enumerated = 2,
    Sequence   = 3,  ///< Also SET.
    Choice     = 4,
    SeqOf      = 5,  ///< Also SET OF.
};

/// Forward declarations — avoid circular dependency (codec headers include TypeDescriptor.hpp).
struct IPerTypeHandler;
struct IBerTypeHandler;

/// @brief Type-tag knob for selecting \c T in \c TypeLifecycleOps template constructor.
template<typename T> struct TypeTag {};

/// @brief Per-type lifecycle operations used by \c ChoiceInterface::emplace_alt().
///
/// Embedded by value in \c TypeDescriptor (same 3×ptr cost as three separate fields).
/// Must be set for all types referenced from \c ChoiceSpec::alternatives.
/// Non-CHOICE types and built-in primitives may leave this default-constructed (all nullptrs).
struct TypeLifecycleOps {
    void (*construct)(void*)          = nullptr; ///< Placement new T{} into pre-allocated storage.
    void (*destroy)(void*)            = nullptr; ///< Call ~T in-place.
    void (*move)(void*, void*)        = nullptr; ///< Move-construct T into dst, then destroy src.
    void (*clone)(void*, const void*) = nullptr; ///< Copy-construct T into uninitialised dst. Null for move-only types.

    TypeLifecycleOps() = default;

    /// @brief Direct fn-ptr constructor — used for the \c k_noop_lifecycle sentinel.
    constexpr TypeLifecycleOps(void (*c)(void*), void (*d)(void*),
                               void (*m)(void*, void*)) noexcept
        : construct(c), destroy(d), move(m) {}

    /// @brief Return a clone fn-ptr only when T is copy-constructible (nullptr otherwise).
    /// SEQUENCE-with-optionals and CHOICE types are move-only until deep_copy copy ctors
    /// are generated — this avoids a compile error at instantiation time.
    template<typename T>
    static constexpr auto make_clone_fn() noexcept -> void(*)(void*, const void*) {
        if constexpr (std::is_copy_constructible_v<T>)
            return [](void* d, const void* s){ new(d) T(*static_cast<const T*>(s)); };
        else
            return nullptr;
    }

    /// @brief Template constructor — infers all four ops from type T.
    template<typename T>
    explicit constexpr TypeLifecycleOps(TypeTag<T>) noexcept
        : construct([](void* p){ new(p) T{}; })
        , destroy  ([](void* p){ std::destroy_at(static_cast<T*>(p)); })
        , move     ([](void* d, void* s){
              new(d) T(std::move(*static_cast<T*>(s)));
              std::destroy_at(static_cast<T*>(s)); })
        , clone    (make_clone_fn<T>())
    {}
};

/// @brief XER encoding instruction for OCTET STRING (X.693 §21).
enum class XerEncoding : uint8_t {
    Default = 0, ///< Hexadecimal uppercase pairs (X.693 §17.4 first alternative).
    Base64  = 1, ///< RFC 2045 §6.8 base64 (X.693 §21 "BASE64" instruction).
};

/// @brief Top-level per-type descriptor — the primary runtime metadata table.
///
/// Each generated type \c T has a static instance \c T::asn_DEF (declared in its
/// generated \c .hpp, defined in \c .cpp).  Pass \c T::asn_DEF by const-reference
/// to codec calls.
///
/// At most one of \c enum_spec, \c sequence_spec, \c choice_spec, \c seq_of_spec
/// is non-null; which one is indicated by \c kind.
///
/// Mirrors \c asn_TYPE_descriptor_t from asn1c.
struct TypeDescriptor {
    const char*          name;                         ///< ASN.1 type name (used in XER tags and diagnostics).
    Tag                  tag;                          ///< Universal or application tag (IMPLICIT/EXPLICIT resolved in member table).
    const EnumSpec*      enum_spec      = nullptr;     ///< Non-null for ENUMERATED.
    const SequenceSpec*  sequence_spec  = nullptr;     ///< Non-null for SEQUENCE / SET.
    const ChoiceSpec*    choice_spec    = nullptr;     ///< Non-null for CHOICE.
    const SeqOfSpec*     seq_of_spec    = nullptr;     ///< Non-null for SEQUENCE OF / SET OF.
    Constraints          constraints    = {};           ///< Value/size constraints (flags==0 = unconstrained).
    bool     is_any  = false;                          ///< True for ANY — raw BER bytes; open-type wrapper in PER.
    TypeKind kind    = TypeKind::Primitive;            ///< Codec dispatch discriminant.
    const IPerTypeHandler* per_handler  = nullptr;     ///< Direct PER handler; null = fall back to PerCodec's LUT.
    const IBerTypeHandler* ber_handler  = nullptr;     ///< Direct BER handler; null = fall back to BerCodec's LUT.
    TypeLifecycleOps lifecycle;                        ///< Lifecycle ops for CHOICE emplace; default (all nullptrs) for non-CHOICE types.
    XerEncoding xer_encoding = XerEncoding::Default;  ///< XER serialisation mode (meaningful for OCTET STRING only).
    /// X.690 §8.14.3 — true when \c tag is an EXPLICIT override on this
    /// type's own top-level `[n]` declaration: the wire encoding must wrap
    /// a nested TLV using \c natural_tag, not substitute \c tag directly
    /// for it the way IMPLICIT does. False for every type with no declared
    /// tag of its own, or one using IMPLICIT.
    bool is_explicit = false;
    Tag  natural_tag = {};  ///< This type's own natural tag, ignoring `[n]`; meaningful only when is_explicit.
};

/// @name Built-in type descriptors
/// Defined in \c runtime/src/BuiltinTypes.cpp (PER handler wired there).
/// Used by generated SEQUENCE/CHOICE member tables for plain primitive members.
///@{
extern const TypeDescriptor asn_DEF_Any;
extern const TypeDescriptor asn_DEF_Integer;
extern const TypeDescriptor asn_DEF_UInteger;
extern const TypeDescriptor asn_DEF_Boolean;
extern const TypeDescriptor asn_DEF_Null;
extern const TypeDescriptor asn_DEF_Real;
extern const TypeDescriptor asn_DEF_BitString;
extern const TypeDescriptor asn_DEF_Oid;
extern const TypeDescriptor asn_DEF_RelativeOid;
extern const TypeDescriptor asn_DEF_UtcTime;
extern const TypeDescriptor asn_DEF_GeneralizedTime;
extern const TypeDescriptor asn_DEF_OctetString;
extern const TypeDescriptor asn_DEF_Utf8String;
extern const TypeDescriptor asn_DEF_Ia5String;
extern const TypeDescriptor asn_DEF_NumericString;
extern const TypeDescriptor asn_DEF_PrintableString;
extern const TypeDescriptor asn_DEF_T61String;
extern const TypeDescriptor asn_DEF_VisibleString;
extern const TypeDescriptor asn_DEF_GeneralString;
extern const TypeDescriptor asn_DEF_GraphicString;
extern const TypeDescriptor asn_DEF_UniversalString;
extern const TypeDescriptor asn_DEF_BmpString;
extern const TypeDescriptor asn_DEF_VideotexString;
extern const TypeDescriptor asn_DEF_ObjectDescriptor;
///@}

} // namespace asn1
