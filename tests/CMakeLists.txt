enable_testing()

# ---- BER primitive unit tests ----------------------------------------------
add_executable(test_ber_primitives ber/test_primitives.cpp)
target_link_libraries(test_ber_primitives PRIVATE asn1cpp_runtime)
add_test(NAME ber_primitives COMMAND test_ber_primitives)

# ---- BER SEQUENCE / CHOICE tests ------------------------------------------
add_executable(test_ber_sequence ber/test_sequence.cpp)
target_link_libraries(test_ber_sequence PRIVATE asn1cpp_runtime)
add_test(NAME ber_sequence COMMAND test_ber_sequence)

# ---- SEQUENCE BER / XER / PER tests (no tagging, no OPTIONAL) -------------
# Generated C++ from simple_seq.asn1 using the asn1cpp compiler.
set(SIMPLE_SEQ_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_simple_seq)
add_custom_command(
    OUTPUT  ${SIMPLE_SEQ_GEN_DIR}/Point.hpp         ${SIMPLE_SEQ_GEN_DIR}/Point.cpp
            ${SIMPLE_SEQ_GEN_DIR}/ColoredPoint.hpp  ${SIMPLE_SEQ_GEN_DIR}/ColoredPoint.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SIMPLE_SEQ_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/simple_seq.asn1
                                   -o ${SIMPLE_SEQ_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/simple_seq.asn1
    COMMENT "Generating C++ from simple_seq.asn1"
)
add_executable(test_seq_simple
    seq/test_seq_simple.cpp
    ${SIMPLE_SEQ_GEN_DIR}/Point.cpp
    ${SIMPLE_SEQ_GEN_DIR}/ColoredPoint.cpp
)
target_include_directories(test_seq_simple PRIVATE ${SIMPLE_SEQ_GEN_DIR})
target_link_libraries(test_seq_simple PRIVATE asn1cpp_runtime)
add_test(NAME seq_simple COMMAND test_seq_simple)

# ---- PER integer encoding tests --------------------------------------------
# Validates constrained INTEGER UPER encoding.
# ASN.1 schemas under tests/asn1/ document the intent; TypeDescriptors are
# constructed manually in the test source to avoid build-time code generation.
add_executable(test_per_integer per/test_per_integer.cpp)
target_link_libraries(test_per_integer PRIVATE asn1cpp_runtime)
add_test(NAME per_integer COMMAND test_per_integer)
