cmake_minimum_required(VERSION 3.20)
project(asn1cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(BISON 3.8 REQUIRED)
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

find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_subdirectory(runtime)
add_subdirectory(compiler)
add_subdirectory(tests)
