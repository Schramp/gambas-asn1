#pragma once
#include <cstdint>
#include <optional>

namespace asn1::ast {

enum class TagClass { Implicit, Universal, Application, Context, Private };
enum class TagMode  { Default, Implicit, Explicit };

struct Tag {
    TagClass        cls{TagClass::Context};
    int64_t         number{-1};   // -1 = absent
    TagMode         mode{TagMode::Default};

    bool present() const { return number >= 0; }
};

} // namespace asn1::ast
