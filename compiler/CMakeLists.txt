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

# RE/flex runtime library (installed under /usr/local)
find_library(REFLEX_LIB reflex
    HINTS /usr/local/lib /home/ruud/RE-flex/lib
    REQUIRED)
target_link_libraries(asn1cpp PRIVATE ${REFLEX_LIB})
if(fmt_FOUND)
    target_link_libraries(asn1cpp PRIVATE fmt::fmt)
endif()
target_include_directories(asn1cpp PRIVATE /usr/local/include)

target_compile_options(asn1cpp PRIVATE -Wall -Wextra -Wno-unused-parameter)
