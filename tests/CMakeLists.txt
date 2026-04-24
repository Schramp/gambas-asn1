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

# ---- NULL member BER tests -------------------------------------------------
set(NULL_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_null_test)
add_custom_command(
    OUTPUT  ${NULL_TEST_GEN_DIR}/HasNull.hpp ${NULL_TEST_GEN_DIR}/HasNull.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NULL_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/null_test.asn1
                                   -o ${NULL_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/null_test.asn1
    COMMENT "Generating C++ from null_test.asn1"
)
add_executable(test_null
    seq/test_null.cpp
    ${NULL_TEST_GEN_DIR}/HasNull.cpp
)
target_include_directories(test_null PRIVATE ${NULL_TEST_GEN_DIR})
target_link_libraries(test_null PRIVATE asn1cpp_runtime)
add_test(NAME null_member COMMAND test_null)

# ---- REAL member BER tests -------------------------------------------------
set(REAL_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_real_test)
add_custom_command(
    OUTPUT  ${REAL_TEST_GEN_DIR}/HasReal.hpp ${REAL_TEST_GEN_DIR}/HasReal.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${REAL_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/real_test.asn1
                                   -o ${REAL_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/real_test.asn1
    COMMENT "Generating C++ from real_test.asn1"
)
add_executable(test_real
    seq/test_real.cpp
    ${REAL_TEST_GEN_DIR}/HasReal.cpp
)
target_include_directories(test_real PRIVATE ${REAL_TEST_GEN_DIR})
target_link_libraries(test_real PRIVATE asn1cpp_runtime)
add_test(NAME real_member COMMAND test_real)

# ---- BIT STRING member BER tests -------------------------------------------
set(BITSTRING_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_bitstring_test)
add_custom_command(
    OUTPUT  ${BITSTRING_TEST_GEN_DIR}/HasBitString.hpp ${BITSTRING_TEST_GEN_DIR}/HasBitString.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${BITSTRING_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/bitstring_test.asn1
                                   -o ${BITSTRING_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/bitstring_test.asn1
    COMMENT "Generating C++ from bitstring_test.asn1"
)
add_executable(test_bitstring
    seq/test_bitstring.cpp
    ${BITSTRING_TEST_GEN_DIR}/HasBitString.cpp
)
target_include_directories(test_bitstring PRIVATE ${BITSTRING_TEST_GEN_DIR})
target_link_libraries(test_bitstring PRIVATE asn1cpp_runtime)
add_test(NAME bitstring_member COMMAND test_bitstring)

# ---- OID / RELATIVE-OID member BER tests -----------------------------------
set(OID_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_oid_test)
add_custom_command(
    OUTPUT  ${OID_TEST_GEN_DIR}/HasOid.hpp    ${OID_TEST_GEN_DIR}/HasOid.cpp
            ${OID_TEST_GEN_DIR}/HasRelOid.hpp ${OID_TEST_GEN_DIR}/HasRelOid.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${OID_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oid_test.asn1
                                   -o ${OID_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oid_test.asn1
    COMMENT "Generating C++ from oid_test.asn1"
)
add_executable(test_oid
    seq/test_oid.cpp
    ${OID_TEST_GEN_DIR}/HasOid.cpp
    ${OID_TEST_GEN_DIR}/HasRelOid.cpp
)
target_include_directories(test_oid PRIVATE ${OID_TEST_GEN_DIR})
target_link_libraries(test_oid PRIVATE asn1cpp_runtime)
add_test(NAME oid_member COMMAND test_oid)

# ---- UTCTime / GeneralizedTime member BER tests ----------------------------
set(TIME_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_time_test)
add_custom_command(
    OUTPUT  ${TIME_TEST_GEN_DIR}/HasUtcTime.hpp         ${TIME_TEST_GEN_DIR}/HasUtcTime.cpp
            ${TIME_TEST_GEN_DIR}/HasGeneralizedTime.hpp ${TIME_TEST_GEN_DIR}/HasGeneralizedTime.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${TIME_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/time_test.asn1
                                   -o ${TIME_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/time_test.asn1
    COMMENT "Generating C++ from time_test.asn1"
)
add_executable(test_time
    seq/test_time.cpp
    ${TIME_TEST_GEN_DIR}/HasUtcTime.cpp
    ${TIME_TEST_GEN_DIR}/HasGeneralizedTime.cpp
)
target_include_directories(test_time PRIVATE ${TIME_TEST_GEN_DIR})
target_link_libraries(test_time PRIVATE asn1cpp_runtime)
add_test(NAME time_member COMMAND test_time)

# ---- String type member BER tests ------------------------------------------
set(STRINGS_TEST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_strings_test)
add_custom_command(
    OUTPUT  ${STRINGS_TEST_GEN_DIR}/HasNumericString.hpp   ${STRINGS_TEST_GEN_DIR}/HasNumericString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasPrintableString.hpp ${STRINGS_TEST_GEN_DIR}/HasPrintableString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasT61String.hpp        ${STRINGS_TEST_GEN_DIR}/HasT61String.cpp
            ${STRINGS_TEST_GEN_DIR}/HasVisibleString.hpp   ${STRINGS_TEST_GEN_DIR}/HasVisibleString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasGeneralString.hpp   ${STRINGS_TEST_GEN_DIR}/HasGeneralString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasGraphicString.hpp   ${STRINGS_TEST_GEN_DIR}/HasGraphicString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasUniversalString.hpp ${STRINGS_TEST_GEN_DIR}/HasUniversalString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasBmpString.hpp       ${STRINGS_TEST_GEN_DIR}/HasBmpString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasVideotexString.hpp  ${STRINGS_TEST_GEN_DIR}/HasVideotexString.cpp
            ${STRINGS_TEST_GEN_DIR}/HasObjectDescriptor.hpp ${STRINGS_TEST_GEN_DIR}/HasObjectDescriptor.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${STRINGS_TEST_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/strings_test.asn1
                                   -o ${STRINGS_TEST_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/strings_test.asn1
    COMMENT "Generating C++ from strings_test.asn1"
)
add_executable(test_strings
    seq/test_strings.cpp
    ${STRINGS_TEST_GEN_DIR}/HasNumericString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasPrintableString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasT61String.cpp
    ${STRINGS_TEST_GEN_DIR}/HasVisibleString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasGeneralString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasGraphicString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasUniversalString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasBmpString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasVideotexString.cpp
    ${STRINGS_TEST_GEN_DIR}/HasObjectDescriptor.cpp
)
target_include_directories(test_strings PRIVATE ${STRINGS_TEST_GEN_DIR})
target_link_libraries(test_strings PRIVATE asn1cpp_runtime)
add_test(NAME strings_member COMMAND test_strings)

# ---- PER integer encoding tests --------------------------------------------
# Validates constrained INTEGER UPER encoding.
# ASN.1 schemas under tests/asn1/ document the intent; TypeDescriptors are
# constructed manually in the test source to avoid build-time code generation.
add_executable(test_per_integer per/test_per_integer.cpp)
target_link_libraries(test_per_integer PRIVATE asn1cpp_runtime)
add_test(NAME per_integer COMMAND test_per_integer)
