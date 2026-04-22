#pragma once
#include <variant>
#include <stdexcept>
#include <string>

namespace asn1 {

// Minimal std::expected-like type for C++20.
template<typename T, typename E>
class Expected {
    std::variant<T, E> storage_;

public:
    Expected(T v) : storage_(std::move(v)) {}

    static Expected unexpected(E e) {
        Expected r;
        r.storage_ = std::move(e);
        return r;
    }

    bool has_value() const { return std::holds_alternative<T>(storage_); }
    explicit operator bool() const { return has_value(); }

    T& value() { return std::get<T>(storage_); }
    const T& value() const { return std::get<T>(storage_); }
    T& operator*() { return value(); }
    const T& operator*() const { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    E& error() { return std::get<E>(storage_); }
    const E& error() const { return std::get<E>(storage_); }

private:
    Expected() = default;
};

template<typename E>
struct Unexpected {
    E value;
    explicit Unexpected(E v) : value(std::move(v)) {}
};

template<typename T, typename E>
Expected<T, E> make_unexpected(E e) {
    return Expected<T, E>::unexpected(std::move(e));
}

} // namespace asn1
