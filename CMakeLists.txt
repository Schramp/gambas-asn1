cmake_minimum_required(VERSION 3.20)
project(asn1cpp VERSION 0.1.0 LANGUAGES CXX)

# Must be called here (top-level scope), not just in tests/CMakeLists.txt —
# CMake only emits build/CTestTestfile.cmake (what `ctest --test-dir build`
# needs) when enable_testing() runs at the scope ctest is invoked from.
# Calling it only inside tests/ produces build/tests/CTestTestfile.cmake,
# which is why `ctest --test-dir build/tests` has always worked while
# `ctest --test-dir build` (used by .github/workflows/ci.yml) silently found
# zero tests — masked because ctest with no tests still exits 0.
enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(BISON 3.8 REQUIRED)
find_package(fmt QUIET)  # optional: fallback for std::format on GCC < 13 (Ubuntu 22.04)
find_program(REFLEX_EXECUTABLE reflex
    PATHS /usr/local/bin
    NO_DEFAULT_PATH
    REQUIRED)

# ---------------------------------------------------------------------------
# Optional: asn1c cross-validation
#   Set ASN1C_BIN_DIR (env or cmake -D) to the directory containing the asn1c
#   binary when it is not on PATH or at /usr/local/bin.
#   Example: cmake -DASN1C_BIN_DIR=/path/to/asn1c/build -B build
# ---------------------------------------------------------------------------
if(NOT DEFINED ASN1C_BIN_DIR AND DEFINED ENV{ASN1C_BIN_DIR})
    set(ASN1C_BIN_DIR "$ENV{ASN1C_BIN_DIR}")
endif()
find_program(ASN1C_EXECUTABLE asn1c
    HINTS "${ASN1C_BIN_DIR}" /usr/local/bin
    DOC "asn1c reference compiler (optional — enables cross-validation tests)")

include(CMakeDependentOption)
cmake_dependent_option(WITH_ASN1C_XVAL
    "Cross-validate parser tests against the asn1c reference compiler"
    ON "ASN1C_EXECUTABLE" OFF)

if(WITH_ASN1C_XVAL)
    message(STATUS "asn1c cross-validation: ON  (${ASN1C_EXECUTABLE})")
else()
    message(STATUS "asn1c cross-validation: OFF (asn1c not found; set ASN1C_BIN_DIR to enable)")
endif()

option(WITH_SMOKE_MATRIX
    "Run type × flag smoke test matrix (17 types × 4 flag combos; requires g++)"
    OFF)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# ---------------------------------------------------------------------------
# Validation hooks (compile-time toggleable)
#   ASN1CPP_VALIDATE         — enable per-primitive validate() calls in codec
#                              (bool result, warns via DBG_BER_WRITE).
#   ASN1CPP_VALIDATE_ON_SET  — validate() in generated set_<member>() helpers.
#   ASN1CPP_VALIDATE_REPORT  — path-tracking ValidationReport.
# Default: ON for Debug (alpha-stage), OFF for Release.
# ---------------------------------------------------------------------------
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    option(ASN1CPP_VALIDATE           "Master switch — enable validate() infrastructure" ON)
    option(ASN1CPP_VALIDATE_ON_ENCODE "Run validate() inside BerCodec::encode"            OFF)
    option(ASN1CPP_VALIDATE_ON_DECODE "Run validate() inside BerCodec::decode"            ON)
    option(ASN1CPP_VALIDATE_ON_SET    "Run validate() in generated set_<member> helpers" ON)
    option(ASN1CPP_VALIDATE_REPORT    "Detailed ValidationReport with paths"             OFF)
else()
    option(ASN1CPP_VALIDATE           "Master switch — enable validate() infrastructure" ON)
    option(ASN1CPP_VALIDATE_ON_ENCODE "Run validate() inside BerCodec::encode"            ON)
    option(ASN1CPP_VALIDATE_ON_DECODE "Run validate() inside BerCodec::decode"            ON)
    option(ASN1CPP_VALIDATE_ON_SET    "Run validate() in generated set_<member> helpers" ON)
    option(ASN1CPP_VALIDATE_REPORT    "Detailed ValidationReport with paths"             ON)
endif()
message(STATUS "ASN1CPP_VALIDATE           = ${ASN1CPP_VALIDATE}")
message(STATUS "ASN1CPP_VALIDATE_ON_ENCODE = ${ASN1CPP_VALIDATE_ON_ENCODE}")
message(STATUS "ASN1CPP_VALIDATE_ON_DECODE = ${ASN1CPP_VALIDATE_ON_DECODE}")
message(STATUS "ASN1CPP_VALIDATE_ON_SET    = ${ASN1CPP_VALIDATE_ON_SET}")
message(STATUS "ASN1CPP_VALIDATE_REPORT    = ${ASN1CPP_VALIDATE_REPORT}")

add_subdirectory(runtime)
add_subdirectory(compiler)
add_subdirectory(tests)

# ---------------------------------------------------------------------------
# Optional: Doxygen documentation
#   cmake -DBUILD_DOCS=ON -B build && cmake --build build --target doxygen
# ---------------------------------------------------------------------------
option(BUILD_DOCS "Build Doxygen HTML documentation" OFF)
if(BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    set(DOXYGEN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    configure_file(Doxyfile.in "${CMAKE_BINARY_DIR}/Doxyfile" @ONLY)
    add_custom_target(doxygen
        COMMAND "${DOXYGEN_EXECUTABLE}" "${CMAKE_BINARY_DIR}/Doxyfile"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Generating Doxygen documentation -> ${DOXYGEN_OUTPUT_DIR}/html/index.html"
        VERBATIM)
    message(STATUS "BUILD_DOCS: ON  — run: cmake --build build --target doxygen")
else()
    message(STATUS "BUILD_DOCS: OFF — enable with -DBUILD_DOCS=ON")
endif()
