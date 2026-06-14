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

# ---- EXPLICIT tagging on non-CHOICE ----------------------------------------
set(EXPLICIT_TAG_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_explicit_tag_test)
add_custom_command(
    OUTPUT  ${EXPLICIT_TAG_GEN_DIR}/WithExplicitInt.hpp ${EXPLICIT_TAG_GEN_DIR}/WithExplicitInt.cpp
            ${EXPLICIT_TAG_GEN_DIR}/WithExplicitSeq.hpp ${EXPLICIT_TAG_GEN_DIR}/WithExplicitSeq.cpp
            ${EXPLICIT_TAG_GEN_DIR}/Mixed.hpp           ${EXPLICIT_TAG_GEN_DIR}/Mixed.cpp
            ${EXPLICIT_TAG_GEN_DIR}/Inner.hpp           ${EXPLICIT_TAG_GEN_DIR}/Inner.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${EXPLICIT_TAG_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/explicit_tag_test.asn1
                                   -o ${EXPLICIT_TAG_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/explicit_tag_test.asn1
    COMMENT "Generating C++ from explicit_tag_test.asn1"
)
add_executable(test_explicit_tag
    seq/test_explicit_tag.cpp
    ${EXPLICIT_TAG_GEN_DIR}/WithExplicitInt.cpp
    ${EXPLICIT_TAG_GEN_DIR}/WithExplicitSeq.cpp
    ${EXPLICIT_TAG_GEN_DIR}/Mixed.cpp
    ${EXPLICIT_TAG_GEN_DIR}/Inner.cpp
)
target_include_directories(test_explicit_tag PRIVATE ${EXPLICIT_TAG_GEN_DIR})
target_link_libraries(test_explicit_tag PRIVATE asn1cpp_runtime)
add_test(NAME explicit_tag COMMAND test_explicit_tag)

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

# ---- Deep-copy (SEQUENCE-with-optionals + CHOICE) ---------------------------
add_executable(test_deep_copy
    seq/test_deep_copy.cpp
    ${SEQ_OPT_GEN_DIR}/Rec5.cpp
    ${CHOICE_GEN_DIR}/HasAlt4.cpp
    ${CHOICE_GEN_DIR}/Alt4.cpp
    ${CHOICE_GEN_DIR}/MyByte.cpp
    ${CHOICE_GEN_DIR}/MyStr.cpp
)
# Both gen dirs define MyByte/MyStr — include only one set (.cpp) to avoid ODR.
# SEQ_OPT_GEN_DIR listed second so its headers are found after CHOICE_GEN_DIR.
target_include_directories(test_deep_copy PRIVATE ${CHOICE_GEN_DIR} ${SEQ_OPT_GEN_DIR})
target_link_libraries(test_deep_copy PRIVATE asn1cpp_runtime)
add_test(NAME deep_copy COMMAND test_deep_copy)

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
    # Known gaps: OID-based import alias resolution not yet implemented (issue #63).
    # asn1c resolves these by OID; asn1cpp currently resolves imports by name only.
    --known-failures 13-resolver-OK.asn1 14-resolver-OK.asn1
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

# ---- Validation hook coverage ---------------------------------------------
# Built only when validation infrastructure is enabled at compile time.
if(ASN1CPP_VALIDATE AND ASN1CPP_VALIDATE_ON_ENCODE)
    set(VALIDATE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_validate_test)
    set(VALIDATE_TYPES
        ByteCount Code Color FixedBlob FlagsByte FlagsRange
        HexDigit MidBlob MidList Name NegRange
        PercentInt PositiveInt ShortList SignedSmall Tariff
        TinyBlob Token Visi Vowels WideUnsigned YesNo
        HasByteCount HasCode HasColor HasFixed HasFlagsByte HasFlagsRange
        HasHex HasMid HasMidList HasName HasNeg
        HasPct HasPos HasShortList HasSigned HasTariff
        HasTiny HasToken HasVisi HasVowels HasWide HasYesNo
    )
    set(_validate_outputs)
    foreach(t IN LISTS VALIDATE_TYPES)
        list(APPEND _validate_outputs
            ${VALIDATE_GEN_DIR}/${t}.hpp
            ${VALIDATE_GEN_DIR}/${t}.cpp)
    endforeach()
    add_custom_command(
        OUTPUT  ${_validate_outputs}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${VALIDATE_GEN_DIR}
        COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/validate_test.asn1
                                       -o ${VALIDATE_GEN_DIR}
        DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/validate_test.asn1
        COMMENT "Generating C++ from validate_test.asn1"
    )
    set(_validate_cpps)
    foreach(t IN LISTS VALIDATE_TYPES)
        list(APPEND _validate_cpps ${VALIDATE_GEN_DIR}/${t}.cpp)
    endforeach()
    add_executable(test_validate
        seq/test_validate.cpp
        ${_validate_cpps}
    )
    target_include_directories(test_validate PRIVATE ${VALIDATE_GEN_DIR})
    target_link_libraries(test_validate PRIVATE asn1cpp_runtime)
    add_test(NAME validate_hooks COMMAND test_validate)
endif()

# ---- XER codec coverage: ENUMERATED + ANY ----------------------------------
set(XER_CODEC_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_codec_test)
add_custom_command(
    OUTPUT  ${XER_CODEC_GEN_DIR}/Direction.hpp    ${XER_CODEC_GEN_DIR}/Direction.cpp
            ${XER_CODEC_GEN_DIR}/HasDirection.hpp ${XER_CODEC_GEN_DIR}/HasDirection.cpp
            ${XER_CODEC_GEN_DIR}/HasAny.hpp       ${XER_CODEC_GEN_DIR}/HasAny.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_CODEC_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/xer_codec_test.asn1
                                   -o ${XER_CODEC_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/xer_codec_test.asn1
    COMMENT "Generating C++ from xer_codec_test.asn1"
)
add_executable(test_xer_codec
    seq/test_xer_codec.cpp
    ${XER_CODEC_GEN_DIR}/Direction.cpp
    ${XER_CODEC_GEN_DIR}/HasDirection.cpp
    ${XER_CODEC_GEN_DIR}/HasAny.cpp
)
target_include_directories(test_xer_codec PRIVATE ${XER_CODEC_GEN_DIR})
target_link_libraries(test_xer_codec PRIVATE asn1cpp_runtime)
add_test(NAME xer_codec COMMAND test_xer_codec)

# ---- asn1c BER vector suite: data-62 (62-any-OK.asn1) ----------------------
# Mirrors asn1c check-62.c: decode 32 BER files, re-encode, compare.
# Covers: CHOICE of SEQUENCE/tagged-SEQUENCE/tagged-CHOICE, ANY member,
# optional members, indefinite-length, IMPLICIT outer tags, extension marker.
# 5 -B files are skipped (ANY inner-TLV leniency — see test source).
set(BER_VEC_62_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_ber_vectors_62)
set(BER_VEC_62_TYPES T T1_ext T2 T2M3 T3 T4)
set(_bv62_outputs)
foreach(t IN LISTS BER_VEC_62_TYPES)
    list(APPEND _bv62_outputs ${BER_VEC_62_GEN_DIR}/${t}.hpp ${BER_VEC_62_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_bv62_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${BER_VEC_62_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/62-any-OK.asn1
            -o ${BER_VEC_62_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/62-any-OK.asn1
    COMMENT "Generating C++ from 62-any-OK.asn1"
)
set(_bv62_cpps)
foreach(t IN LISTS BER_VEC_62_TYPES)
    list(APPEND _bv62_cpps ${BER_VEC_62_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_ber_vectors_62
    seq/test_ber_vectors_62.cpp
    ${_bv62_cpps}
)
target_include_directories(test_ber_vectors_62 PRIVATE ${BER_VEC_62_GEN_DIR})
target_link_libraries(test_ber_vectors_62 PRIVATE asn1cpp_runtime)
add_test(NAME ber_vectors_62 COMMAND test_ber_vectors_62
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-62)
set_tests_properties(ber_vectors_62 PROPERTIES TIMEOUT 30)

# ---- asn1c XER vector suite: data-70 (70-xer-test-OK.asn1) -----------------
# Mirrors asn1c check-70.c: XER decode → BER encode → BER decode → XER encode.
# (none)/-E: round-trip output must equal input (whitespace-stripped).
# -B: XER decode must fail (broken input).
# -D/-X: round-trip succeeds; output may differ from input.
set(XER_VEC_70_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_vectors_70)
set(XER_VEC_70_TYPES
    PDU Sequence Set ExtensibleSet ExtensibleSetEnum
    ExtensibleSequence ExtensibleSequence2
    SetOfNULL SetOfREAL SetOfEnums SetOfEnumsEnum
    NamedSetOfNULL NamedSetOfREAL NamedSetOfEnums NamedSetOfEnumsName
    SequenceOf SeqOfZuka
    SetOfChoice NamedSetOfChoice SimpleChoice
)
set(_xv70_outputs)
foreach(t IN LISTS XER_VEC_70_TYPES)
    list(APPEND _xv70_outputs ${XER_VEC_70_GEN_DIR}/${t}.hpp ${XER_VEC_70_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_xv70_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_VEC_70_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/70-xer-test-OK.asn1
            -o ${XER_VEC_70_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/70-xer-test-OK.asn1
    COMMENT "Generating C++ from 70-xer-test-OK.asn1"
)
set(_xv70_cpps)
foreach(t IN LISTS XER_VEC_70_TYPES)
    list(APPEND _xv70_cpps ${XER_VEC_70_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_xer_vectors_70
    seq/test_xer_vectors_70.cpp
    ${_xv70_cpps}
)
target_include_directories(test_xer_vectors_70 PRIVATE ${XER_VEC_70_GEN_DIR})
target_link_libraries(test_xer_vectors_70 PRIVATE asn1cpp_runtime)
add_test(NAME xer_vectors_70 COMMAND test_xer_vectors_70
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-70)
set_tests_properties(xer_vectors_70 PROPERTIES TIMEOUT 30)

# ---- BER fuzz (in-tree) ---------------------------------------------------
# Wire-level corruption sweep using BerCorruptor against the asn1cpp BER
# decoder. Self-contained — no asn1c dependency, no etsitools/ binaries.
set(FUZZ_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_fuzz_test)
set(FUZZ_TYPES Inner Pick Bag BagItems)
set(_fuzz_outputs)
foreach(t IN LISTS FUZZ_TYPES)
    list(APPEND _fuzz_outputs
        ${FUZZ_GEN_DIR}/${t}.hpp
        ${FUZZ_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_fuzz_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${FUZZ_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/fuzz_test.asn1
                                   -o ${FUZZ_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/fuzz_test.asn1
    COMMENT "Generating C++ from fuzz_test.asn1"
)
set(_fuzz_cpps)
foreach(t IN LISTS FUZZ_TYPES)
    list(APPEND _fuzz_cpps ${FUZZ_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_fuzz_ber
    seq/test_fuzz_ber.cpp
    ${_fuzz_cpps}
)
target_include_directories(test_fuzz_ber PRIVATE ${FUZZ_GEN_DIR})
target_link_libraries(test_fuzz_ber PRIVATE asn1cpp_runtime)
add_test(NAME fuzz_ber COMMAND test_fuzz_ber)
set_tests_properties(fuzz_ber PROPERTIES TIMEOUT 60)

# ---- BER/XER gap coverage tests -------------------------------------------
set(BER_GAPS_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_ber_gaps_test)
set(BER_GAPS_TYPES HasDefault HasOptChoice OuterChoice LeafChoice
                   HasExtChoice ExtChoice HasEnum SimpleEnum HasSeqOf HasSeqOfItems)
set(_bg_outputs)
foreach(t IN LISTS BER_GAPS_TYPES)
    list(APPEND _bg_outputs ${BER_GAPS_GEN_DIR}/${t}.hpp ${BER_GAPS_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_bg_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${BER_GAPS_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/ber_gaps_test.asn1
                                   -o ${BER_GAPS_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/ber_gaps_test.asn1
    COMMENT "Generating C++ from ber_gaps_test.asn1"
)
set(_bg_cpps)
foreach(t IN LISTS BER_GAPS_TYPES)
    list(APPEND _bg_cpps ${BER_GAPS_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_ber_gaps
    seq/test_ber_gaps.cpp
    ${_bg_cpps}
)
target_include_directories(test_ber_gaps PRIVATE ${BER_GAPS_GEN_DIR})
target_link_libraries(test_ber_gaps PRIVATE asn1cpp_runtime)
add_test(NAME ber_gaps COMMAND test_ber_gaps)
set_tests_properties(ber_gaps PROPERTIES TIMEOUT 30)

# test_set — SET and SET OF BER/XER round-trip (issue #23)
set(SET_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_set_test)
set(SET_TYPES Point Config IntSet Pair PairSet ExtPoint)
set(_st_outputs)
foreach(t IN LISTS SET_TYPES)
    list(APPEND _st_outputs ${SET_GEN_DIR}/${t}.hpp ${SET_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_st_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SET_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/set_test.asn1
                                   -o ${SET_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/set_test.asn1
    COMMENT "Generating C++ from set_test.asn1"
)
set(_st_cpps)
foreach(t IN LISTS SET_TYPES)
    list(APPEND _st_cpps ${SET_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_set
    seq/test_set.cpp
    ${_st_cpps}
)
target_include_directories(test_set PRIVATE ${SET_GEN_DIR})
target_link_libraries(test_set PRIVATE asn1cpp_runtime)
add_test(NAME set COMMAND test_set)
set_tests_properties(set PROPERTIES TIMEOUT 30)

# test_default — DEFAULT suppress/fill for INTEGER / BOOLEAN / ENUMERATED (issue #24)
set(DEFAULT_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_default_test)
set(DEFAULT_TYPES Primitive Config Mixed Level)
set(_df_outputs)
foreach(t IN LISTS DEFAULT_TYPES)
    list(APPEND _df_outputs ${DEFAULT_GEN_DIR}/${t}.hpp ${DEFAULT_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_df_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DEFAULT_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/default_test.asn1
                                   -o ${DEFAULT_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/default_test.asn1
    COMMENT "Generating C++ from default_test.asn1"
)
set(_df_cpps)
foreach(t IN LISTS DEFAULT_TYPES)
    list(APPEND _df_cpps ${DEFAULT_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_default
    seq/test_default.cpp
    ${_df_cpps}
)
target_include_directories(test_default PRIVATE ${DEFAULT_GEN_DIR})
target_link_libraries(test_default PRIVATE asn1cpp_runtime)
add_test(NAME default_values COMMAND test_default)
set_tests_properties(default_values PROPERTIES TIMEOUT 30)

# test_recursive — recursive type BER/XER round-trip (issue #25)
set(RECURSIVE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_recursive_test)
set(RECURSIVE_TYPES Node Tree Even Odd)
set(_rt_outputs)
foreach(t IN LISTS RECURSIVE_TYPES)
    list(APPEND _rt_outputs ${RECURSIVE_GEN_DIR}/${t}.hpp ${RECURSIVE_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_rt_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RECURSIVE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/recursive_test.asn1
                                   -o ${RECURSIVE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/recursive_test.asn1
    COMMENT "Generating C++ from recursive_test.asn1"
)
set(_rt_cpps)
foreach(t IN LISTS RECURSIVE_TYPES)
    list(APPEND _rt_cpps ${RECURSIVE_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_recursive
    seq/test_recursive.cpp
    ${_rt_cpps}
)
target_include_directories(test_recursive PRIVATE ${RECURSIVE_GEN_DIR})
target_link_libraries(test_recursive PRIVATE asn1cpp_runtime)
add_test(NAME recursive COMMAND test_recursive)
set_tests_properties(recursive PROPERTIES TIMEOUT 30)
