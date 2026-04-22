#pragma once
#include <string>
#include <cstddef>

namespace asn1 {

struct DecodeError {
    std::string message;
    std::size_t offset{0};   // byte offset in the input where the error occurred

    explicit DecodeError(std::string msg, std::size_t off = 0)
        : message(std::move(msg)), offset(off) {}
};

} // namespace asn1
