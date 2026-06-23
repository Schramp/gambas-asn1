#pragma once
#include <variant>
#include <stdexcept>
#include <string>

namespace asn1 {

/// @brief Minimal \c std::expected-like result type for C++20.
///
/// Holds either a success value of type \c T or an error value of type \c E —
/// never both.  Use \c .has_value() / \c bool conversion to check; access the
/// success value with \c * or \c ->; access the error with \c .error().
///
/// Construct via normal \c T copy/move for success, or \c make_unexpected<T,E>()
/// for failure.  The \c DecodeResult alias (\c Expected<std::monostate,DecodeError>)
/// is the standard return type of all codec decode operations.
///
/// @tparam T  Success value type.
/// @tparam E  Error value type.
template<typename T, typename E>
class Expected {
    std::variant<T, E> storage_;

public:
    /// @brief Construct a successful \c Expected holding \p v.
    Expected(T v) : storage_(std::move(v)) {}

    /// @brief Internal factory for failure — prefer \c make_unexpected<T,E>().
    static Expected unexpected(E e) {
        Expected r;
        r.storage_ = std::move(e);
        return r;
    }

    /// @brief Return true if this holds a success value.
    bool has_value() const { return std::holds_alternative<T>(storage_); }
    /// @brief Return true if this holds a success value (same as \c has_value()).
    explicit operator bool() const { return has_value(); }

    /// @brief Return a reference to the success value (UB if \c !has_value()).
    T& value() { return std::get<T>(storage_); }
    /// @brief Return a const reference to the success value (UB if \c !has_value()).
    const T& value() const { return std::get<T>(storage_); }
    /// @brief Dereference to the success value.
    T& operator*() { return value(); }
    /// @brief Dereference to the success value (const).
    const T& operator*() const { return value(); }
    /// @brief Arrow access into the success value.
    T* operator->() { return &value(); }
    /// @brief Arrow access into the success value (const).
    const T* operator->() const { return &value(); }

    /// @brief Return a reference to the error value (UB if \c has_value()).
    E& error() { return std::get<E>(storage_); }
    /// @brief Return a const reference to the error value (UB if \c has_value()).
    const E& error() const { return std::get<E>(storage_); }

private:
    Expected() = default;
};

/// @brief Helper tag for constructing failure values — not used directly.
template<typename E>
struct Unexpected {
    E value;
    explicit Unexpected(E v) : value(std::move(v)) {}
};

/// @brief Construct a failed \c Expected<T,E> carrying error \p e.
/// @param e  Error value to store.
/// @return   \c Expected<T,E> in the error state.
///
/// Usage:
/// @code
/// return asn1::make_unexpected<MyType, DecodeError>(DecodeError{"bad tag", pos});
/// @endcode
template<typename T, typename E>
Expected<T, E> make_unexpected(E e) {
    return Expected<T, E>::unexpected(std::move(e));
}

} // namespace asn1
