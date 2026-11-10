cmake_minimum_required(VERSION 3.20)

# ---- Bison (parser) --------------------------------------------------------
BISON_TARGET(asn1_parser
    grammar/asn1.y
    ${CMAKE_CURRENT_BINARY_DIR}/asn1.tab.cc
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/asn1.tab.hh
    COMPILE_FLAGS "--defines --warnings=none"
)

# ---- RE/flex (lexer) -------------------------------------------------------
set(REFLEX_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(REFLEX_LEXER_SRC  ${REFLEX_OUTPUT_DIR}/lex.yy.cpp)
set(REFLEX_LEXER_HDR  ${REFLEX_OUTPUT_DIR}/Lexer.l.hh)

add_custom_command(
    OUTPUT  ${REFLEX_LEXER_SRC} ${REFLEX_LEXER_HDR}
    COMMAND ${REFLEX_EXECUTABLE}
            --outfile=${REFLEX_LEXER_SRC}
            --header-file=${REFLEX_LEXER_HDR}
            --bison-complete
            --bison-locations
            --noyywrap
            --stack
            ${CMAKE_CURRENT_SOURCE_DIR}/grammar/asn1.l
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/grammar/asn1.l
            ${CMAKE_CURRENT_BINARY_DIR}/asn1.tab.hh
    COMMENT "Running RE/flex on asn1.l"
)

# ---- Compiler executable ---------------------------------------------------
add_executable(asn1cpp
    ${BISON_asn1_parser_OUTPUTS}
    ${REFLEX_LEXER_SRC}
    src/codegen/Generator.cpp
    src/codegen/CppBackend.cpp
    src/codegen/RustBackend.cpp
    src/codegen/JavaBackend.cpp
    src/config/Json.cpp
    src/sema/ContainedFields.cpp
    src/sema/PerNkmSize.cpp
    src/main.cpp
)

target_include_directories(asn1cpp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/grammar  # for Lexer.hpp (wrapper)
    ${CMAKE_CURRENT_BINARY_DIR}          # for generated asn1.tab.hh and Lexer.l.hh
    ${CMAKE_CURRENT_SOURCE_DIR}          # for src/ast etc. relative includes from grammar/
)

target_include_directories(asn1cpp PRIVATE
    ${CMAKE_SOURCE_DIR}/runtime/include)  # Tag.hpp, TypeDescriptor.hpp, Constraints.hpp

# RE/flex runtime library (installed under /usr/local). The static archive
# comes first, so the compiler never depends on a libreflex.so at run time.
find_library(REFLEX_LIB NAMES libreflex.a reflex
    HINTS /usr/local/lib
    REQUIRED)
target_link_libraries(asn1cpp PRIVATE ${REFLEX_LIB})

# A fully static compiler (libc and libstdc++ included) runs on any x86_64
# Linux, whatever its glibc: the release ships one. The compiler only reads
# and writes files, so it uses none of the glibc parts that need shared
# libraries at run time (NSS, dlopen, iconv, locales).
option(ASN1CPP_STATIC_COMPILER "Link the asn1cpp compiler fully static (Linux)" OFF)
if(ASN1CPP_STATIC_COMPILER)
    if(APPLE)
        message(FATAL_ERROR "ASN1CPP_STATIC_COMPILER: macOS has no static libc")
    endif()
    target_link_options(asn1cpp PRIVATE -static)
endif()
if(fmt_FOUND)
    target_link_libraries(asn1cpp PRIVATE fmt::fmt)
endif()
target_include_directories(asn1cpp PRIVATE /usr/local/include)

target_compile_options(asn1cpp PRIVATE -Wall -Wextra -Wno-unused-parameter)

# Default location of the X.681/X.208 predefined-classes module
# (TYPE-IDENTIFIER, ABSTRACT-SYNTAX, EXTERNAL) — overridable at runtime
# via --stdlib-dir.
target_compile_definitions(asn1cpp PRIVATE
    ASN1CPP_STDLIB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/predefined"
    ASN1CPP_VERSION="${PROJECT_VERSION}"
    ASN1CPP_HOMEPAGE_URL="${PROJECT_HOMEPAGE_URL}")

# ---- install: the compiler, and the predefined-classes module where an
# installed compiler looks for it (relative to its own directory).
set(_asn1cpp_stdlib_dest ${CMAKE_INSTALL_DATADIR}/asn1cpp/predefined)
file(RELATIVE_PATH _asn1cpp_stdlib_rel ${CMAKE_INSTALL_FULL_BINDIR}
     ${CMAKE_INSTALL_PREFIX}/${_asn1cpp_stdlib_dest})
target_compile_definitions(asn1cpp PRIVATE
    ASN1CPP_INSTALLED_STDLIB_REL="${_asn1cpp_stdlib_rel}")
install(TARGETS asn1cpp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY predefined/ DESTINATION ${_asn1cpp_stdlib_dest})
