#pragma once
// Portability shim: use std::format (GCC 13+) or libfmt fallback (GCC 11, Ubuntu 22.04).
// Install fallback: sudo apt install libfmt-dev
#include <version>
#if defined(__cpp_lib_format)
#  include <format>
#else
#  include <fmt/format.h>
namespace std { using fmt::format; }
#endif
