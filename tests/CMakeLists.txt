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

# ---- Rec3: plain 3-field SEQUENCE ------------------------------------------
set(SEQ3_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_seq3_test)
add_custom_command(
    OUTPUT  ${SEQ3_GEN_DIR}/Rec3.hpp    ${SEQ3_GEN_DIR}/Rec3.cpp
            ${SEQ3_GEN_DIR}/MyByte.hpp  ${SEQ3_GEN_DIR}/MyByte.cpp
            ${SEQ3_GEN_DIR}/MyStr.hpp   ${SEQ3_GEN_DIR}/MyStr.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SEQ3_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq3_test.asn1
                                   -o ${SEQ3_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq3_test.asn1
    COMMENT "Generating C++ from seq3_test.asn1"
)
add_executable(test_seq3
    seq/test_seq3.cpp
    ${SEQ3_GEN_DIR}/Rec3.cpp
    ${SEQ3_GEN_DIR}/MyByte.cpp
    ${SEQ3_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_seq3 PRIVATE ${SEQ3_GEN_DIR})
target_link_libraries(test_seq3 PRIVATE asn1cpp_runtime)
add_test(NAME seq3 COMMAND test_seq3)

# ---- Rec5: SEQUENCE with OPTIONAL members -----------------------------------
set(SEQ_OPT_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_seq_opt_test)
add_custom_command(
    OUTPUT  ${SEQ_OPT_GEN_DIR}/Rec5.hpp   ${SEQ_OPT_GEN_DIR}/Rec5.cpp
            ${SEQ_OPT_GEN_DIR}/MyByte.hpp ${SEQ_OPT_GEN_DIR}/MyByte.cpp
            ${SEQ_OPT_GEN_DIR}/MyStr.hpp  ${SEQ_OPT_GEN_DIR}/MyStr.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SEQ_OPT_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq_opt_test.asn1
                                   -o ${SEQ_OPT_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq_opt_test.asn1
    COMMENT "Generating C++ from seq_opt_test.asn1"
)
add_executable(test_seq_opt
    seq/test_seq_opt.cpp
    ${SEQ_OPT_GEN_DIR}/Rec5.cpp
    ${SEQ_OPT_GEN_DIR}/MyByte.cpp
    ${SEQ_OPT_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_seq_opt PRIVATE ${SEQ_OPT_GEN_DIR})
target_link_libraries(test_seq_opt PRIVATE asn1cpp_runtime)
add_test(NAME seq_opt COMMAND test_seq_opt)

# ---- SEQUENCE OF types ------------------------------------------------------
set(SEQ_OF_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_seq_of_test)
add_custom_command(
    OUTPUT  ${SEQ_OF_GEN_DIR}/ByteList.hpp ${SEQ_OF_GEN_DIR}/ByteList.cpp
            ${SEQ_OF_GEN_DIR}/StrList.hpp  ${SEQ_OF_GEN_DIR}/StrList.cpp
            ${SEQ_OF_GEN_DIR}/MyByte.hpp   ${SEQ_OF_GEN_DIR}/MyByte.cpp
            ${SEQ_OF_GEN_DIR}/MyStr.hpp    ${SEQ_OF_GEN_DIR}/MyStr.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SEQ_OF_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq_of_test.asn1
                                   -o ${SEQ_OF_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/seq_of_test.asn1
    COMMENT "Generating C++ from seq_of_test.asn1"
)
add_executable(test_seq_of
    seq/test_seq_of.cpp
    ${SEQ_OF_GEN_DIR}/ByteList.cpp
    ${SEQ_OF_GEN_DIR}/StrList.cpp
    ${SEQ_OF_GEN_DIR}/MyByte.cpp
    ${SEQ_OF_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_seq_of PRIVATE ${SEQ_OF_GEN_DIR})
target_link_libraries(test_seq_of PRIVATE asn1cpp_runtime)
add_test(NAME seq_of COMMAND test_seq_of)

# ---- CHOICE types -----------------------------------------------------------
set(CHOICE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_choice_test)
add_custom_command(
    OUTPUT  ${CHOICE_GEN_DIR}/HasAlt2.hpp ${CHOICE_GEN_DIR}/HasAlt2.cpp
            ${CHOICE_GEN_DIR}/HasAlt4.hpp ${CHOICE_GEN_DIR}/HasAlt4.cpp
            ${CHOICE_GEN_DIR}/Alt2.hpp    ${CHOICE_GEN_DIR}/Alt2.cpp
            ${CHOICE_GEN_DIR}/Alt4.hpp    ${CHOICE_GEN_DIR}/Alt4.cpp
            ${CHOICE_GEN_DIR}/MyByte.hpp  ${CHOICE_GEN_DIR}/MyByte.cpp
            ${CHOICE_GEN_DIR}/MyStr.hpp   ${CHOICE_GEN_DIR}/MyStr.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CHOICE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/choice_test.asn1
                                   -o ${CHOICE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/choice_test.asn1
    COMMENT "Generating C++ from choice_test.asn1"
)
add_executable(test_choice
    seq/test_choice.cpp
    ${CHOICE_GEN_DIR}/HasAlt2.cpp
    ${CHOICE_GEN_DIR}/HasAlt4.cpp
    ${CHOICE_GEN_DIR}/Alt2.cpp
    ${CHOICE_GEN_DIR}/Alt4.cpp
    ${CHOICE_GEN_DIR}/MyByte.cpp
    ${CHOICE_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_choice PRIVATE ${CHOICE_GEN_DIR})
target_link_libraries(test_choice PRIVATE asn1cpp_runtime)
add_test(NAME choice COMMAND test_choice)

# ---- Constrained INTEGER types ----------------------------------------------
set(INT_RANGE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_int_range_test)
add_custom_command(
    OUTPUT  ${INT_RANGE_GEN_DIR}/HasBit1.hpp   ${INT_RANGE_GEN_DIR}/HasBit1.cpp
            ${INT_RANGE_GEN_DIR}/HasByte.hpp   ${INT_RANGE_GEN_DIR}/HasByte.cpp
            ${INT_RANGE_GEN_DIR}/HasSigned.hpp ${INT_RANGE_GEN_DIR}/HasSigned.cpp
            ${INT_RANGE_GEN_DIR}/HasNarrow.hpp ${INT_RANGE_GEN_DIR}/HasNarrow.cpp
            ${INT_RANGE_GEN_DIR}/HasWord.hpp   ${INT_RANGE_GEN_DIR}/HasWord.cpp
            ${INT_RANGE_GEN_DIR}/MyBit1.hpp    ${INT_RANGE_GEN_DIR}/MyBit1.cpp
            ${INT_RANGE_GEN_DIR}/MyByte.hpp    ${INT_RANGE_GEN_DIR}/MyByte.cpp
            ${INT_RANGE_GEN_DIR}/MySigned.hpp  ${INT_RANGE_GEN_DIR}/MySigned.cpp
            ${INT_RANGE_GEN_DIR}/MyNarrow.hpp  ${INT_RANGE_GEN_DIR}/MyNarrow.cpp
            ${INT_RANGE_GEN_DIR}/MyWord.hpp    ${INT_RANGE_GEN_DIR}/MyWord.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${INT_RANGE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/int_range_test.asn1
                                   -o ${INT_RANGE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/int_range_test.asn1
    COMMENT "Generating C++ from int_range_test.asn1"
)
add_executable(test_int_range
    seq/test_int_range.cpp
    ${INT_RANGE_GEN_DIR}/HasBit1.cpp
    ${INT_RANGE_GEN_DIR}/HasByte.cpp
    ${INT_RANGE_GEN_DIR}/HasSigned.cpp
    ${INT_RANGE_GEN_DIR}/HasNarrow.cpp
    ${INT_RANGE_GEN_DIR}/HasWord.cpp
    ${INT_RANGE_GEN_DIR}/MyBit1.cpp
    ${INT_RANGE_GEN_DIR}/MyByte.cpp
    ${INT_RANGE_GEN_DIR}/MySigned.cpp
    ${INT_RANGE_GEN_DIR}/MyNarrow.cpp
    ${INT_RANGE_GEN_DIR}/MyWord.cpp
)
target_include_directories(test_int_range PRIVATE ${INT_RANGE_GEN_DIR})
target_link_libraries(test_int_range PRIVATE asn1cpp_runtime)
add_test(NAME int_range COMMAND test_int_range)

# ---- Name collision: two modules define same type name ----------------------
set(COLLISION_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_collision_test)
add_custom_command(
    OUTPUT  ${COLLISION_GEN_DIR}/CollisionModAStatus.hpp  ${COLLISION_GEN_DIR}/CollisionModAStatus.cpp
            ${COLLISION_GEN_DIR}/CollisionModAWrapper.hpp ${COLLISION_GEN_DIR}/CollisionModAWrapper.cpp
            ${COLLISION_GEN_DIR}/CollisionModBStatus.hpp  ${COLLISION_GEN_DIR}/CollisionModBStatus.cpp
            ${COLLISION_GEN_DIR}/CollisionModBWrapper.hpp ${COLLISION_GEN_DIR}/CollisionModBWrapper.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${COLLISION_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/collision_test.asn1
                                   -o ${COLLISION_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/collision_test.asn1
    COMMENT "Generating C++ from collision_test.asn1"
)
add_executable(test_collision
    seq/test_collision.cpp
    ${COLLISION_GEN_DIR}/CollisionModAStatus.cpp
    ${COLLISION_GEN_DIR}/CollisionModAWrapper.cpp
    ${COLLISION_GEN_DIR}/CollisionModBStatus.cpp
    ${COLLISION_GEN_DIR}/CollisionModBWrapper.cpp
)
target_include_directories(test_collision PRIVATE ${COLLISION_GEN_DIR})
target_link_libraries(test_collision PRIVATE asn1cpp_runtime)
add_test(NAME collision COMMAND test_collision)

# ---- Cross-module IMPORTS ---------------------------------------------------
set(IMPORTS_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_imports_test)
add_custom_command(
    OUTPUT  ${IMPORTS_GEN_DIR}/ZipCode.hpp ${IMPORTS_GEN_DIR}/ZipCode.cpp
            ${IMPORTS_GEN_DIR}/Address.hpp ${IMPORTS_GEN_DIR}/Address.cpp
            ${IMPORTS_GEN_DIR}/Person.hpp  ${IMPORTS_GEN_DIR}/Person.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${IMPORTS_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/imports_test.asn1
                                   -o ${IMPORTS_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/imports_test.asn1
    COMMENT "Generating C++ from imports_test.asn1"
)
add_executable(test_imports
    seq/test_imports.cpp
    ${IMPORTS_GEN_DIR}/ZipCode.cpp
    ${IMPORTS_GEN_DIR}/Address.cpp
    ${IMPORTS_GEN_DIR}/Person.cpp
)
target_include_directories(test_imports PRIVATE ${IMPORTS_GEN_DIR})
target_link_libraries(test_imports PRIVATE asn1cpp_runtime)
add_test(NAME imports COMMAND test_imports)

# ---- Parser conformance: asn1c test suite -----------------------------------
# Runs run_parser_tests.py against all *-OK/-NP/-SE.asn1 files imported from
# the asn1c compiler test suite. Pass --asn1c when WITH_ASN1C_XVAL is ON.
set(_parser_test_args
    ${CMAKE_CURRENT_SOURCE_DIR}/run_parser_tests.py
    --asn1cpp $<TARGET_FILE:asn1cpp>
    --test-dir ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler
    --known-failures 59-choice-extended-OK.asn1
)
if(WITH_ASN1C_XVAL)
    list(APPEND _parser_test_args --asn1c ${ASN1C_EXECUTABLE})
endif()
add_test(
    NAME parser_conformance
    COMMAND ${Python3_EXECUTABLE} ${_parser_test_args}
)
set_tests_properties(parser_conformance PROPERTIES
    TIMEOUT 120
)
