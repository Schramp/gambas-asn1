#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include "OctetString.hpp"

namespace asn1 {

struct TypeDescriptor;

/// @brief State of a contained value after the outer decode.
enum class ContainedStatus : uint8_t {
    NotDecoded, ///< No inner decode attempted (fresh value, or raw bytes set directly).
    Decoded,    ///< The inner value is available.
    Skipped,    ///< Not decoded on purpose: `decode: off`, a `when` mismatch, or a decoder declined.
    Failed,     ///< The inner decode failed; error() has the reason, the raw bytes are kept.
};

/// @brief Encoding rules of the contained bytes (X.682 §11.4/§11.6).
/// `Outer` means the encoding rules of the enclosing OCTET STRING.
enum class ContainedEncoding : uint8_t { Outer, Ber, Cer, Der, PerAligned, PerUnaligned };

/// @brief XER/JER form of a contained value: hex only, the inner value in
/// place of the hex (X.680 §22.4, X.697 §25.4), or the inner value plus the
/// raw hex (an extension, not standard-conformant).
enum class ContainedText : uint8_t { Hex, Inline, InlineRaw };

/// @brief Typed heap operations on a contained value, which the runtime
/// cannot do through the type-erased Asn1Object (it has no virtual
/// destructor). Generated tables point at \c ContainedOpsFor<T>::ops.
struct ContainedOps {
    Asn1Object* (*make)();                      ///< `new T{}`
    void        (*destroy)(Asn1Object*);        ///< `delete static_cast<T*>(p)`
    Asn1Object* (*clone)(const Asn1Object*);    ///< `new T(*static_cast<const T*>(p))`
};

/// @brief \c ContainedOps for the inner type \p T.
template<typename T>
struct ContainedOpsFor {
    static constexpr ContainedOps ops{
        []() -> Asn1Object* { return new T{}; },
        [](Asn1Object* p) { delete static_cast<T*>(p); },
        [](const Asn1Object* p) -> Asn1Object* { return new T(*static_cast<const T*>(p)); },
    };
};

/// @brief Per-field table row for a contained value: what the inner type is
/// and how the eager decode handles it. Reached through the field's own
/// per-member \c TypeDescriptor::contained.
/// @see X.682 §11 — contents constraints.
struct ContainedSpec {
    /// Type of a `when` sibling, which decides how its value is read.
    enum class WhenKind : uint8_t { None, Enumerated, Integer, UInteger, Boolean };

    const TypeDescriptor* inner_def;        ///< Descriptor of the inner type.
    const ContainedOps*   ops;              ///< Heap operations for the inner type.
    ContainedEncoding     encoding = ContainedEncoding::Outer;
    bool                  eager = true;     ///< false: `decode: off`, never decoded.
    const char*           decoder = "plain"; ///< Name looked up in \c ContainedDecoders.
    int                   when_member = -1; ///< Index in the enclosing SequenceSpec::members, -1 = always.
    WhenKind              when_kind = WhenKind::None;
    int64_t               when_value = 0;   ///< Sibling value that enables the decode.
    bool                  fail_on_error = false; ///< `on_error: fail`: a failed inner decode fails the outer decode.
    ContainedText         xer = ContainedText::Hex;
    ContainedText         jer = ContainedText::Hex;
};

/// @brief Non-template part of a contained value: the raw OCTET STRING bytes
/// (the base class, which every OCTET STRING codec path reads and writes),
/// plus the type-erased inner value and its decode status.
///
/// The raw bytes stay authoritative for encoding, so a value that was
/// decoded and not modified re-encodes byte-exact (an HMAC over it stays
/// valid). Modifying the inner value marks it dirty; encode then re-encodes
/// the inner value instead.
class ContainedBase : public OctetString {
public:
    ContainedBase() = default;
    ContainedBase(const ContainedBase& o)
        : OctetString(o), ops_(o.ops_), status_(o.status_), error_(o.error_), dirty_(o.dirty_) {
        if (o.inner_) inner_ = ops_->clone(o.inner_);
    }
    ContainedBase(ContainedBase&& o) noexcept
        : OctetString(std::move(o)), inner_(std::exchange(o.inner_, nullptr)), ops_(o.ops_),
          status_(o.status_), error_(std::move(o.error_)), dirty_(o.dirty_) {}
    ContainedBase& operator=(const ContainedBase& o) {
        if (this != &o) { ContainedBase tmp(o); swap(tmp); }
        return *this;
    }
    ContainedBase& operator=(ContainedBase&& o) noexcept {
        if (this != &o) { ContainedBase tmp(std::move(o)); swap(tmp); }
        return *this;
    }
    ~ContainedBase() { reset_value(); }

    /// @brief Equality of the raw bytes; the inner value is derived from them.
    bool operator==(const ContainedBase& o) const {
        return static_cast<const OctetString&>(*this) == static_cast<const OctetString&>(o);
    }

    /// @brief Replace the raw bytes. Drops the inner value: it no longer
    ///        matches them.
    template<typename B> void set(B&& b) {
        OctetString::set(std::forward<B>(b));
        reset_value();
        status_ = ContainedStatus::NotDecoded;
        error_.clear();
        dirty_ = false;
    }
    /// @brief Replace the raw bytes with \p n bytes from \p p.
    void set(const uint8_t* p, std::size_t n) {
        OctetString::set(p, n);
        reset_value();
        status_ = ContainedStatus::NotDecoded;
        error_.clear();
        dirty_ = false;
    }

    ContainedStatus status() const { return status_; }
    /// @brief Reason of a Failed or Skipped status (empty otherwise).
    const std::string& error() const { return error_; }
    bool has_value() const { return inner_ != nullptr; }
    /// @brief True after the inner value was modified; encode then derives
    ///        the bytes from it.
    bool dirty() const { return dirty_; }

    /// @brief Type-erased inner value, or nullptr.
    const Asn1Object* value_object() const { return inner_; }
    Asn1Object*       value_object() { return inner_; }

    /// @brief Runtime access for codecs: replace the inner value by a fresh
    ///        default one of the inner type.
    Asn1Object* emplace_value_object(const ContainedOps& ops) {
        reset_value();
        ops_ = &ops;
        inner_ = ops.make();
        return inner_;
    }
    /// @brief Runtime access for codecs: record a decode outcome. Drops the
    ///        inner value unless \p s is Decoded.
    void set_status(ContainedStatus s, std::string error = {}) {
        if (s != ContainedStatus::Decoded) reset_value();
        status_ = s;
        error_ = std::move(error);
        dirty_ = false;
    }
    /// @brief Runtime access for codecs: raw bytes from the wire, before any
    ///        inner decode.
    void set_raw_from_wire(std::span<const uint8_t> b) {
        OctetString::set(b);
        reset_value();
        status_ = ContainedStatus::NotDecoded;
        error_.clear();
        dirty_ = false;
    }

    /// @brief Runtime access for codecs: raw bytes derived for an inner value
    ///        that was just decoded from its inline XER/JER form; keeps the
    ///        value and marks it Decoded.
    void set_raw_for_value(std::span<const uint8_t> b) {
        OctetString::set(b);
        status_ = ContainedStatus::Decoded;
        error_.clear();
        dirty_ = false;
    }

protected:
    void reset_value() {
        if (inner_) ops_->destroy(inner_);
        inner_ = nullptr;
    }
    void mark_dirty() { dirty_ = true; status_ = ContainedStatus::Decoded; error_.clear(); }
    void swap(ContainedBase& o) noexcept {
        std::swap(static_cast<OctetString&>(*this), static_cast<OctetString&>(o));
        std::swap(inner_, o.inner_);
        std::swap(ops_, o.ops_);
        std::swap(status_, o.status_);
        std::swap(error_, o.error_);
        std::swap(dirty_, o.dirty_);
    }

    Asn1Object*          inner_ = nullptr;
    const ContainedOps*  ops_ = nullptr;
    ContainedStatus      status_ = ContainedStatus::NotDecoded;
    std::string          error_;
    bool                 dirty_ = false;
};

/// @brief An OCTET STRING whose bytes are the encoding of a \p T value
///        (X.682 §11 contents constraint, or a --container-config entry).
///
/// Keeps the OctetString surface (\c bytes(), \c set(), \c size()) for the
/// raw bytes, and adds the inner value decoded during the outer decode.
/// The inner value is heap-held, so \p T may be the enclosing type itself.
template<typename T>
class Containing : public ContainedBase {
public:
    Containing() = default;

    /// @brief The decoded inner value, or nullptr (see status()).
    const T* value() const { return static_cast<const T*>(inner_); }
    /// @brief Mutable inner value, or nullptr. Marks the value dirty: encode
    ///        derives the bytes from it from now on.
    T* value_mut() {
        if (inner_) mark_dirty();
        return static_cast<T*>(inner_);
    }
    /// @brief Replace the inner value. Encode derives the bytes from it.
    void set_value(T v) {
        reset_value();
        ops_ = &ContainedOpsFor<T>::ops;
        inner_ = new T(std::move(v));
        mark_dirty();
    }
};

} // namespace asn1
