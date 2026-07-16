enable_testing()

# ---- BerProjection trie tests -----------------------------------------------
add_executable(test_ber_projection_trie ber/test_ber_projection_trie.cpp)
target_link_libraries(test_ber_projection_trie PRIVATE asn1cpp_runtime)
add_test(NAME ber_projection_trie COMMAND test_ber_projection_trie)

# ---- BerProjectionResult tests (#173) ----------------------------------------
add_executable(test_ber_projection_result ber/test_ber_projection_result.cpp)
target_link_libraries(test_ber_projection_result PRIVATE asn1cpp_runtime)
add_test(NAME ber_projection_result COMMAND test_ber_projection_result)

# ---- BerInspect tests (#174) ------------------------------------------------
add_executable(test_ber_inspect ber/test_ber_inspect.cpp)
target_link_libraries(test_ber_inspect PRIVATE asn1cpp_runtime)
add_test(NAME ber_inspect COMMAND test_ber_inspect)

# ---- BerProjectionResult stress test (#175) ---------------------------------
add_executable(test_ber_projection_stress ber/test_ber_projection_stress.cpp)
target_link_libraries(test_ber_projection_stress PRIVATE asn1cpp_runtime)
add_test(NAME ber_projection_stress COMMAND test_ber_projection_stress)

# ---- BerProjection end-to-end test with real PS_PDU (#175) -----------------
set(ETSI_E2E_FRAME "${CMAKE_SOURCE_DIR}/../pdu-00000001.etsi")
if(EXISTS "${ETSI_E2E_FRAME}")
    set(ETSI_GEN_DIR "${CMAKE_SOURCE_DIR}/examples/sample.source.ETSI-LI-PS-PDU/gen")
    set(ETSI_LIB     "${CMAKE_SOURCE_DIR}/examples/sample.source.ETSI-LI-PS-PDU/lib/libasn1cpp_etsi.a")
    if(EXISTS "${ETSI_LIB}")
        add_executable(test_ber_projection_e2e ber/test_ber_projection_e2e.cpp)
        target_include_directories(test_ber_projection_e2e PRIVATE ${ETSI_GEN_DIR})
        target_link_libraries(test_ber_projection_e2e PRIVATE asn1cpp_runtime ${ETSI_LIB})
        add_test(NAME ber_projection_e2e
            COMMAND test_ber_projection_e2e "${ETSI_E2E_FRAME}")
    endif()
endif()

# ---- BerCursor / BerLayer / BerMutableCursor tests -------------------------
add_executable(test_ber_cursor ber/test_ber_cursor.cpp)
target_link_libraries(test_ber_cursor PRIVATE asn1cpp_runtime)
add_test(NAME ber_cursor COMMAND test_ber_cursor)

# ---- Asn1Optional<T> layout tests ------------------------------------------
add_executable(test_asn1_optional ber/test_asn1_optional.cpp)
target_link_libraries(test_asn1_optional PRIVATE asn1cpp_runtime)
add_test(NAME asn1_optional COMMAND test_asn1_optional)

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

# ---- TypedVisitor / TypedMutator (object-tree callback walker) --------------
set(TYPED_VISITOR_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_typed_visitor)
add_custom_command(
    OUTPUT  ${TYPED_VISITOR_GEN_DIR}/Coord.hpp     ${TYPED_VISITOR_GEN_DIR}/Coord.cpp
            ${TYPED_VISITOR_GEN_DIR}/Payload.hpp   ${TYPED_VISITOR_GEN_DIR}/Payload.cpp
            ${TYPED_VISITOR_GEN_DIR}/Item.hpp      ${TYPED_VISITOR_GEN_DIR}/Item.cpp
            ${TYPED_VISITOR_GEN_DIR}/ItemList.hpp  ${TYPED_VISITOR_GEN_DIR}/ItemList.cpp
            ${TYPED_VISITOR_GEN_DIR}/Container.hpp ${TYPED_VISITOR_GEN_DIR}/Container.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${TYPED_VISITOR_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/typed_visitor_test.asn1
                                   -o ${TYPED_VISITOR_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/typed_visitor_test.asn1
    COMMENT "Generating C++ from typed_visitor_test.asn1"
)
add_executable(test_typed_visitor
    ber/test_typed_visitor.cpp
    ${TYPED_VISITOR_GEN_DIR}/Coord.cpp
    ${TYPED_VISITOR_GEN_DIR}/Payload.cpp
    ${TYPED_VISITOR_GEN_DIR}/Item.cpp
    ${TYPED_VISITOR_GEN_DIR}/ItemList.cpp
    ${TYPED_VISITOR_GEN_DIR}/Container.cpp
)
target_include_directories(test_typed_visitor PRIVATE ${TYPED_VISITOR_GEN_DIR})
target_link_libraries(test_typed_visitor PRIVATE asn1cpp_runtime)
add_test(NAME typed_visitor COMMAND test_typed_visitor)

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
            ${STRINGS_TEST_GEN_DIR}/HexCharType.hpp        ${STRINGS_TEST_GEN_DIR}/HexCharType.cpp
            ${STRINGS_TEST_GEN_DIR}/YesNoCharType.hpp      ${STRINGS_TEST_GEN_DIR}/YesNoCharType.cpp
            ${STRINGS_TEST_GEN_DIR}/VowelType.hpp          ${STRINGS_TEST_GEN_DIR}/VowelType.cpp
            ${STRINGS_TEST_GEN_DIR}/OutOfOrderType.hpp     ${STRINGS_TEST_GEN_DIR}/OutOfOrderType.cpp
            ${STRINGS_TEST_GEN_DIR}/HasHexStr.hpp          ${STRINGS_TEST_GEN_DIR}/HasHexStr.cpp
            ${STRINGS_TEST_GEN_DIR}/HasYesNoStr.hpp        ${STRINGS_TEST_GEN_DIR}/HasYesNoStr.cpp
            ${STRINGS_TEST_GEN_DIR}/HasVowelStr.hpp        ${STRINGS_TEST_GEN_DIR}/HasVowelStr.cpp
            ${STRINGS_TEST_GEN_DIR}/HasOutOfOrder.hpp      ${STRINGS_TEST_GEN_DIR}/HasOutOfOrder.cpp
            ${STRINGS_TEST_GEN_DIR}/SizedIa5.hpp           ${STRINGS_TEST_GEN_DIR}/SizedIa5.cpp
            ${STRINGS_TEST_GEN_DIR}/SizedVis.hpp           ${STRINGS_TEST_GEN_DIR}/SizedVis.cpp
            ${STRINGS_TEST_GEN_DIR}/SizedNum.hpp           ${STRINGS_TEST_GEN_DIR}/SizedNum.cpp
            ${STRINGS_TEST_GEN_DIR}/SizedPrt.hpp           ${STRINGS_TEST_GEN_DIR}/SizedPrt.cpp
            ${STRINGS_TEST_GEN_DIR}/HasSizedIa5.hpp        ${STRINGS_TEST_GEN_DIR}/HasSizedIa5.cpp
            ${STRINGS_TEST_GEN_DIR}/HasSizedVis.hpp        ${STRINGS_TEST_GEN_DIR}/HasSizedVis.cpp
            ${STRINGS_TEST_GEN_DIR}/HasSizedNum.hpp        ${STRINGS_TEST_GEN_DIR}/HasSizedNum.cpp
            ${STRINGS_TEST_GEN_DIR}/HasSizedPrt.hpp        ${STRINGS_TEST_GEN_DIR}/HasSizedPrt.cpp
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
    ${STRINGS_TEST_GEN_DIR}/HexCharType.cpp
    ${STRINGS_TEST_GEN_DIR}/YesNoCharType.cpp
    ${STRINGS_TEST_GEN_DIR}/VowelType.cpp
    ${STRINGS_TEST_GEN_DIR}/OutOfOrderType.cpp
    ${STRINGS_TEST_GEN_DIR}/HasHexStr.cpp
    ${STRINGS_TEST_GEN_DIR}/HasYesNoStr.cpp
    ${STRINGS_TEST_GEN_DIR}/HasVowelStr.cpp
    ${STRINGS_TEST_GEN_DIR}/HasOutOfOrder.cpp
    ${STRINGS_TEST_GEN_DIR}/SizedIa5.cpp
    ${STRINGS_TEST_GEN_DIR}/SizedVis.cpp
    ${STRINGS_TEST_GEN_DIR}/SizedNum.cpp
    ${STRINGS_TEST_GEN_DIR}/SizedPrt.cpp
    ${STRINGS_TEST_GEN_DIR}/HasSizedIa5.cpp
    ${STRINGS_TEST_GEN_DIR}/HasSizedVis.cpp
    ${STRINGS_TEST_GEN_DIR}/HasSizedNum.cpp
    ${STRINGS_TEST_GEN_DIR}/HasSizedPrt.cpp
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
#
# Known failures are maintained in parser_known_failures.txt (one basename per
# line; lines starting with '#' are comments).  CMakeLists and validate_parser.py
# both read the same file, so the list cannot drift between the two.
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/parser_known_failures.txt _parser_known_failures
     REGEX "^[^#]")

set(_parser_test_args
    ${CMAKE_CURRENT_SOURCE_DIR}/run_parser_tests.py
    --asn1cpp $<TARGET_FILE:asn1cpp>
    --test-dir ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler
)
if(_parser_known_failures)
    list(APPEND _parser_test_args --known-failures ${_parser_known_failures})
endif()

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

    add_executable(test_jer_validate
        jer/test_jer_validate.cpp
        ${_validate_cpps}
    )
    target_include_directories(test_jer_validate PRIVATE ${VALIDATE_GEN_DIR})
    target_link_libraries(test_jer_validate PRIVATE asn1cpp_runtime)
    add_test(NAME jer_validate COMMAND test_jer_validate)
    set_tests_properties(jer_validate PROPERTIES LABELS "jer")
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

# ---- asn1c PER vector suite: data-119 (119-per-strings-OK.asn1) -------------
# Mirrors asn1c check-119.c: XER decode → UPER encode → UPER decode → XER encode.
# (none): round-trip output must equal input (whitespace-stripped).
# -P: PER-incompatible (constraint violations); skipped — see KNOWN_SKIP in test file.
set(XER_VEC_119_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_vectors_119)
add_custom_command(
    OUTPUT  ${XER_VEC_119_GEN_DIR}/PDU.hpp    ${XER_VEC_119_GEN_DIR}/PDU.cpp
            ${XER_VEC_119_GEN_DIR}/PDUMany.hpp ${XER_VEC_119_GEN_DIR}/PDUMany.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_VEC_119_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/119-per-strings-OK.asn1
            -o ${XER_VEC_119_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/119-per-strings-OK.asn1
    COMMENT "Generating C++ from 119-per-strings-OK.asn1"
)
add_executable(test_xer_vectors_119
    seq/test_xer_vectors_119.cpp
    ${XER_VEC_119_GEN_DIR}/PDU.cpp
    ${XER_VEC_119_GEN_DIR}/PDUMany.cpp
)
target_include_directories(test_xer_vectors_119 PRIVATE ${XER_VEC_119_GEN_DIR})
target_link_libraries(test_xer_vectors_119 PRIVATE asn1cpp_runtime)
add_test(NAME xer_vectors_119 COMMAND test_xer_vectors_119
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-119)
set_tests_properties(xer_vectors_119 PROPERTIES TIMEOUT 30)

# ---- asn1c PER vector suite: data-126 (126-per-extensions-OK.asn1) ----------
# Mirrors asn1c check-126.-gen-UPER.c: XER decode → UPER encode → binary compare
# → UPER decode → XER re-encode compare.
# (none): binary must equal .out; XER round-trip must equal .in.
# -C: binary may differ (schema-version delta); XER round-trip must equal .in.
# -P: UPER decode of .out must fail; our own round-trip must succeed.
# -X: binary must equal .out; XER round-trip must differ from .in.
set(XER_VEC_126_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_vectors_126)
add_custom_command(
    OUTPUT  ${XER_VEC_126_GEN_DIR}/PDU.hpp    ${XER_VEC_126_GEN_DIR}/PDU.cpp
            ${XER_VEC_126_GEN_DIR}/PDU_2.hpp  ${XER_VEC_126_GEN_DIR}/PDU_2.cpp
            ${XER_VEC_126_GEN_DIR}/Singleton.hpp ${XER_VEC_126_GEN_DIR}/Singleton.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_VEC_126_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/126-per-extensions-OK.asn1
            -o ${XER_VEC_126_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/126-per-extensions-OK.asn1
    COMMENT "Generating C++ from 126-per-extensions-OK.asn1"
)
add_executable(test_xer_vectors_126
    seq/test_xer_vectors_126.cpp
    ${XER_VEC_126_GEN_DIR}/PDU.cpp
    ${XER_VEC_126_GEN_DIR}/PDU_2.cpp
    ${XER_VEC_126_GEN_DIR}/Singleton.cpp
)
target_include_directories(test_xer_vectors_126 PRIVATE ${XER_VEC_126_GEN_DIR})
target_link_libraries(test_xer_vectors_126 PRIVATE asn1cpp_runtime)
add_test(NAME xer_vectors_126 COMMAND test_xer_vectors_126
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-126)
set_tests_properties(xer_vectors_126 PROPERTIES TIMEOUT 30)

# ---- asn1c XER vector suite: data-202 (202-XIOTCertificate-OK.asn1) --------
# Single vector s1.xer: X.509-style certificate with BIT STRING in hex XER format.
# Verifies XER decode, field values, and BER round-trip.
set(XER_VEC_202_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_vectors_202)
set(XER_VEC_202_TYPES
    AlgorithmIdentifier Certificate CommonName DistinguishedName
    Extension Extensions Name SignatureIdentifier SubjectPublicKeyInfo
    TBSCertificate Validity
    ansi_X9_62 ecdsa_with_SHA256 id_at_commonName id_ecPublicKey prime256v1
)
set(_xv202_outputs)
foreach(t IN LISTS XER_VEC_202_TYPES)
    list(APPEND _xv202_outputs ${XER_VEC_202_GEN_DIR}/${t}.hpp ${XER_VEC_202_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_xv202_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_VEC_202_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/202-XIOTCertificate-OK.asn1
            -o ${XER_VEC_202_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/tests-asn1c-compiler/202-XIOTCertificate-OK.asn1
    COMMENT "Generating C++ from 202-XIOTCertificate-OK.asn1"
)
set(_xv202_cpps)
foreach(t IN LISTS XER_VEC_202_TYPES)
    list(APPEND _xv202_cpps ${XER_VEC_202_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_xer_vectors_202
    seq/test_xer_vectors_202.cpp
    ${_xv202_cpps}
)
target_include_directories(test_xer_vectors_202 PRIVATE ${XER_VEC_202_GEN_DIR})
target_link_libraries(test_xer_vectors_202 PRIVATE asn1cpp_runtime)
add_test(NAME xer_vectors_202 COMMAND test_xer_vectors_202
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-202)
set_tests_properties(xer_vectors_202 PROPERTIES TIMEOUT 30)

# ---- PER extension members (issue #13) ------------------------------------
# Verifies SEQUENCE and CHOICE extension member encode/decode in UPER:
#   root-only (ext flag=0), one extension present, both present, CHOICE ext alt.
# Cross-validated against asn1c converter during development.
set(PER_EXT_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_per_ext_test)
set(PER_EXT_TYPES SeqWithExt ChoiceWithExt InnerSeq SeqDeepExt SeqDeepExtRootOnly)
set(_pe_outputs)
foreach(t IN LISTS PER_EXT_TYPES)
    list(APPEND _pe_outputs ${PER_EXT_GEN_DIR}/${t}.hpp ${PER_EXT_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_pe_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PER_EXT_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/asn1/per_ext_test.asn1
            -o ${PER_EXT_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/per_ext_test.asn1
    COMMENT "Generating C++ from per_ext_test.asn1"
)
set(_pe_cpps)
foreach(t IN LISTS PER_EXT_TYPES)
    list(APPEND _pe_cpps ${PER_EXT_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_per_ext seq/test_per_ext.cpp ${_pe_cpps})
target_include_directories(test_per_ext PRIVATE ${PER_EXT_GEN_DIR})
target_link_libraries(test_per_ext PRIVATE asn1cpp_runtime)
add_test(NAME per_ext COMMAND test_per_ext)
set_tests_properties(per_ext PROPERTIES TIMEOUT 30)

# ---- -fprefix namespace test (issue #16) ------------------------------------
# Verifies that -fprefix=<name> wraps generated types in namespace <name>.
# Uses per_ext_test.asn1 (already available) regenerated with -fprefix=testns.
# test_fprefix.cpp accesses types as testns::SeqWithExt to confirm the wrapper.
set(FPREFIX_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_fprefix_test)
set(FPREFIX_TYPES SeqWithExt ChoiceWithExt InnerSeq SeqDeepExt SeqDeepExtRootOnly)
set(_fp_outputs)
foreach(t IN LISTS FPREFIX_TYPES)
    list(APPEND _fp_outputs ${FPREFIX_GEN_DIR}/${t}.hpp ${FPREFIX_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_fp_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${FPREFIX_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/asn1/per_ext_test.asn1
            -fprefix=testns -o ${FPREFIX_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/per_ext_test.asn1
    COMMENT "Generating C++ from per_ext_test.asn1 with -fprefix=testns"
)
set(_fp_cpps)
foreach(t IN LISTS FPREFIX_TYPES)
    list(APPEND _fp_cpps ${FPREFIX_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_fprefix seq/test_fprefix.cpp ${_fp_cpps})
target_include_directories(test_fprefix PRIVATE ${FPREFIX_GEN_DIR})
target_link_libraries(test_fprefix PRIVATE asn1cpp_runtime)
add_test(NAME fprefix COMMAND test_fprefix)
set_tests_properties(fprefix PROPERTIES TIMEOUT 30)

# ---- ns_recursive_seqof: self-referential SeqOf in namespace mode (issue #109) ---
# Regression for the bug where post-class deferred includes landed before the
# `namespace X {` opener instead of after `} // namespace X`.
set(NS_RECURSIVE_SEQOF_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_ns_recursive_seqof)
add_custom_command(
    OUTPUT  ${NS_RECURSIVE_SEQOF_GEN_DIR}/Tree.hpp
            ${NS_RECURSIVE_SEQOF_GEN_DIR}/Tree.cpp
            ${NS_RECURSIVE_SEQOF_GEN_DIR}/TreeChildren.hpp
            ${NS_RECURSIVE_SEQOF_GEN_DIR}/TreeChildren.cpp
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NS_RECURSIVE_SEQOF_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/asn1/ns_recursive_seqof_test.asn1
            -fprefix=testns -o ${NS_RECURSIVE_SEQOF_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/ns_recursive_seqof_test.asn1
    COMMENT "Generating C++ from ns_recursive_seqof_test.asn1 with -fprefix=testns"
)
add_executable(test_ns_recursive_seqof
    seq/test_ns_recursive_seqof.cpp
    ${NS_RECURSIVE_SEQOF_GEN_DIR}/Tree.cpp
    ${NS_RECURSIVE_SEQOF_GEN_DIR}/TreeChildren.cpp
)
target_include_directories(test_ns_recursive_seqof PRIVATE ${NS_RECURSIVE_SEQOF_GEN_DIR})
target_link_libraries(test_ns_recursive_seqof PRIVATE asn1cpp_runtime)
add_test(NAME ns_recursive_seqof COMMAND test_ns_recursive_seqof)
set_tests_properties(ns_recursive_seqof PROPERTIES TIMEOUT 30)

# ---- BER fuzz (in-tree) ---------------------------------------------------
# Wire-level corruption sweep using BerCorruptor against the asn1cpp BER
# decoder. Self-contained — no asn1c dependency, no etsitools/ binaries.
set(FUZZ_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_fuzz_test)
set(FUZZ_TYPES Inner Pick Color Mode Bag BagItems)
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

# test_per_size_range — UPER SIZE range constraint rejection (issue #114)
set(PER_SIZE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_per_size_range)
set(PER_SIZE_TYPES HasFixed HasRange14 HasRange8b HasRange1b HasFromSize
                   MyFixed3 MyRange14 MyRange0_180 MyRange180_181 MyFromSize)
set(_ps_outputs)
foreach(t IN LISTS PER_SIZE_TYPES)
    list(APPEND _ps_outputs ${PER_SIZE_GEN_DIR}/${t}.hpp ${PER_SIZE_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_ps_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PER_SIZE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/size_string_test.asn1
                                   -o ${PER_SIZE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/size_string_test.asn1
    COMMENT "Generating C++ from size_string_test.asn1"
)
set(_ps_cpps)
foreach(t IN LISTS PER_SIZE_TYPES)
    list(APPEND _ps_cpps ${PER_SIZE_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_per_size_range
    seq/test_per_size_range.cpp
    ${_ps_cpps}
)
target_include_directories(test_per_size_range PRIVATE ${PER_SIZE_GEN_DIR})
target_link_libraries(test_per_size_range PRIVATE asn1cpp_runtime)
add_test(NAME per_size_range COMMAND test_per_size_range)
set_tests_properties(per_size_range PROPERTIES TIMEOUT 30)

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

# test_cross_module_value — cross-module named-value constraint bounds resolved correctly (issue #89)
set(CROSS_MOD_VAL_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_cross_module_value_test)
set(CROSS_MOD_VAL_TYPES CountedField)
set(_cmv_outputs)
foreach(t IN LISTS CROSS_MOD_VAL_TYPES)
    list(APPEND _cmv_outputs ${CROSS_MOD_VAL_GEN_DIR}/${t}.hpp ${CROSS_MOD_VAL_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_cmv_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CROSS_MOD_VAL_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/cross_module_value_test.asn1
                                   -o ${CROSS_MOD_VAL_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/cross_module_value_test.asn1
    COMMENT "Generating C++ from cross_module_value_test.asn1"
)
set(_cmv_cpps)
foreach(t IN LISTS CROSS_MOD_VAL_TYPES)
    list(APPEND _cmv_cpps ${CROSS_MOD_VAL_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_cross_module_value
    seq/test_cross_module_value.cpp
    ${_cmv_cpps}
)
target_include_directories(test_cross_module_value PRIVATE ${CROSS_MOD_VAL_GEN_DIR})
target_link_libraries(test_cross_module_value PRIVATE asn1cpp_runtime)
add_test(NAME cross_module_value COMMAND test_cross_module_value)
set_tests_properties(cross_module_value PROPERTIES TIMEOUT 30)

# test_xer_encoding_instr — XER encoding instruction [BASE64] on OCTET STRING (issue #68)
set(XER_ENC_INSTR_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_xer_encoding_instr_test)
set(XER_ENC_INSTR_TYPES InlineTest Base64Payload PayloadWrapper)
set(_xei_outputs)
foreach(t IN LISTS XER_ENC_INSTR_TYPES)
    list(APPEND _xei_outputs ${XER_ENC_INSTR_GEN_DIR}/${t}.hpp ${XER_ENC_INSTR_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_xei_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${XER_ENC_INSTR_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/xer_encoding_instr_test.asn1
                                   -o ${XER_ENC_INSTR_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/xer_encoding_instr_test.asn1
    COMMENT "Generating C++ from xer_encoding_instr_test.asn1"
)
set(_xei_cpps)
foreach(t IN LISTS XER_ENC_INSTR_TYPES)
    list(APPEND _xei_cpps ${XER_ENC_INSTR_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_xer_encoding_instr
    seq/test_xer_encoding_instr.cpp
    ${_xei_cpps}
)
target_include_directories(test_xer_encoding_instr PRIVATE ${XER_ENC_INSTR_GEN_DIR})
target_link_libraries(test_xer_encoding_instr PRIVATE asn1cpp_runtime)
add_test(NAME xer_encoding_instr COMMAND test_xer_encoding_instr)
set_tests_properties(xer_encoding_instr PROPERTIES TIMEOUT 30)

# test_recursive_choice — indirect recursive CHOICE via SEQUENCE OPTIONAL (issue #43)
set(REC_CHOICE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_recursive_choice_test)
set(REC_CHOICE_TYPES Expr ExprSeq)
set(_rc_outputs)
foreach(t IN LISTS REC_CHOICE_TYPES)
    list(APPEND _rc_outputs ${REC_CHOICE_GEN_DIR}/${t}.hpp ${REC_CHOICE_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_rc_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${REC_CHOICE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/recursive_choice_test.asn1
                                   -o ${REC_CHOICE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/recursive_choice_test.asn1
    COMMENT "Generating C++ from recursive_choice_test.asn1"
)
set(_rc_cpps)
foreach(t IN LISTS REC_CHOICE_TYPES)
    list(APPEND _rc_cpps ${REC_CHOICE_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_recursive_choice
    seq/test_recursive_choice.cpp
    ${_rc_cpps}
)
target_include_directories(test_recursive_choice PRIVATE ${REC_CHOICE_GEN_DIR})
target_link_libraries(test_recursive_choice PRIVATE asn1cpp_runtime)
add_test(NAME recursive_choice COMMAND test_recursive_choice)
set_tests_properties(recursive_choice PROPERTIES TIMEOUT 30)

# test_random_roundtrip — randomised BER/XER round-trip for all primitive types (issue #29)
set(ROUNDTRIP_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_roundtrip_test)
set(ROUNDTRIP_TYPES Container ContainerItems Primitives Item PrimEnum)
set(_rrt_outputs)
foreach(t IN LISTS ROUNDTRIP_TYPES)
    list(APPEND _rrt_outputs ${ROUNDTRIP_GEN_DIR}/${t}.hpp ${ROUNDTRIP_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_rrt_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${ROUNDTRIP_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> ${CMAKE_CURRENT_SOURCE_DIR}/asn1/roundtrip_test.asn1
                                   -o ${ROUNDTRIP_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/roundtrip_test.asn1
    COMMENT "Generating C++ from roundtrip_test.asn1"
)
set(_rrt_cpps)
foreach(t IN LISTS ROUNDTRIP_TYPES)
    list(APPEND _rrt_cpps ${ROUNDTRIP_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_random_roundtrip
    seq/test_random_roundtrip.cpp
    ${_rrt_cpps}
)
target_include_directories(test_random_roundtrip PRIVATE ${ROUNDTRIP_GEN_DIR})
target_link_libraries(test_random_roundtrip PRIVATE asn1cpp_runtime)
add_test(NAME random_roundtrip COMMAND test_random_roundtrip)
set_tests_properties(random_roundtrip PROPERTIES TIMEOUT 60)

# ---- BER fuzz harness / corpus-replay (data-62, issue #30) -----------------
# fuzz_ber_corpus_replay: standalone replay binary that feeds all data-62
# .ber files into the BER decoder and asserts no crash.  Always built.
#
# fuzz_ber_decode: libfuzzer target for continuous fuzzing.  Only built when
# LIBFUZZER_AVAILABLE=ON (requires clang with -fsanitize=fuzzer,address).
set(FUZZ_BER_SOURCES
    fuzz/fuzz_ber_decode.cpp
    ${_bv62_cpps}
)

add_executable(fuzz_ber_corpus_replay ${FUZZ_BER_SOURCES})
target_include_directories(fuzz_ber_corpus_replay PRIVATE ${BER_VEC_62_GEN_DIR})
target_link_libraries(fuzz_ber_corpus_replay PRIVATE asn1cpp_runtime)
add_test(NAME fuzz_ber_corpus_replay COMMAND fuzz_ber_corpus_replay
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-62)
set_tests_properties(fuzz_ber_corpus_replay PROPERTIES TIMEOUT 30)

option(LIBFUZZER_AVAILABLE "Build libfuzzer fuzz targets (requires clang -fsanitize=fuzzer,address)" OFF)
if(LIBFUZZER_AVAILABLE)
    add_executable(fuzz_ber_decode ${FUZZ_BER_SOURCES})
    target_include_directories(fuzz_ber_decode PRIVATE ${BER_VEC_62_GEN_DIR})
    target_link_libraries(fuzz_ber_decode PRIVATE asn1cpp_runtime)
    target_compile_definitions(fuzz_ber_decode PRIVATE FUZZ_DRIVER)
    target_compile_options(fuzz_ber_decode PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_ber_decode PRIVATE -fsanitize=fuzzer,address)
endif()

# ---- XER fuzz harness / corpus-replay (data-70, issue #30) -----------------
set(FUZZ_XER_SOURCES
    fuzz/fuzz_xer_decode.cpp
    ${_xv70_cpps}
)

add_executable(fuzz_xer_corpus_replay ${FUZZ_XER_SOURCES})
target_include_directories(fuzz_xer_corpus_replay PRIVATE ${XER_VEC_70_GEN_DIR})
target_link_libraries(fuzz_xer_corpus_replay PRIVATE asn1cpp_runtime)
add_test(NAME fuzz_xer_corpus_replay COMMAND fuzz_xer_corpus_replay
    ${CMAKE_CURRENT_SOURCE_DIR}/tests-c-compiler/data-70)
set_tests_properties(fuzz_xer_corpus_replay PROPERTIES TIMEOUT 30)

if(LIBFUZZER_AVAILABLE)
    add_executable(fuzz_xer_decode ${FUZZ_XER_SOURCES})
    target_include_directories(fuzz_xer_decode PRIVATE ${XER_VEC_70_GEN_DIR})
    target_link_libraries(fuzz_xer_decode PRIVATE asn1cpp_runtime)
    target_compile_definitions(fuzz_xer_decode PRIVATE FUZZ_DRIVER)
    target_compile_options(fuzz_xer_decode PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_xer_decode PRIVATE -fsanitize=fuzzer,address)
endif()

# ---- -pdu= dependency filter test (issue #14) --------------------------------
# Generates from pdu_filter_test.asn1 with -pdu=RootType.
# Only RootType, Dep1, Dep2 should be generated; Unrelated should be absent.
# Two tests: (1) BER round-trip for generated types; (2) cmake check for absence.
set(PDU_FILTER_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_pdu_filter_test)
set(PDU_FILTER_TYPES RootType Dep1 Dep2)
set(_pf_outputs)
foreach(t IN LISTS PDU_FILTER_TYPES)
    list(APPEND _pf_outputs ${PDU_FILTER_GEN_DIR}/${t}.hpp ${PDU_FILTER_GEN_DIR}/${t}.cpp)
endforeach()
add_custom_command(
    OUTPUT  ${_pf_outputs}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PDU_FILTER_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp>
            ${CMAKE_CURRENT_SOURCE_DIR}/asn1/pdu_filter_test.asn1
            -pdu=RootType -o ${PDU_FILTER_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/pdu_filter_test.asn1
    COMMENT "Generating C++ from pdu_filter_test.asn1 with -pdu=RootType"
)
set(_pf_cpps)
foreach(t IN LISTS PDU_FILTER_TYPES)
    list(APPEND _pf_cpps ${PDU_FILTER_GEN_DIR}/${t}.cpp)
endforeach()
add_executable(test_pdu_filter seq/test_1001_pdu_filter.cpp ${_pf_cpps})
target_include_directories(test_pdu_filter PRIVATE ${PDU_FILTER_GEN_DIR})
target_link_libraries(test_pdu_filter PRIVATE asn1cpp_runtime)
add_test(NAME pdu_filter COMMAND test_pdu_filter)
set_tests_properties(pdu_filter PROPERTIES TIMEOUT 30)

# Verify Unrelated.hpp was NOT generated (must run after codegen step).
add_test(NAME pdu_filter_absent
    COMMAND ${CMAKE_COMMAND}
            -DFILE=${PDU_FILTER_GEN_DIR}/Unrelated.hpp
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_file_absent.cmake)
set_tests_properties(pdu_filter_absent PROPERTIES DEPENDS pdu_filter)

# ---- JER basic-type unit test (#156) ----------------------------------------
add_executable(test_jer_basic jer/test_jer_basic.cpp)
target_link_libraries(test_jer_basic PRIVATE asn1cpp_runtime)
add_test(NAME jer_basic COMMAND test_jer_basic)
set_tests_properties(jer_basic PROPERTIES TIMEOUT 30 LABELS "jer")

# ---- JER SEQUENCE / CHOICE test (#157) ----------------------------------------
add_executable(test_jer_composite
    jer/test_jer_composite.cpp
    ${CHOICE_GEN_DIR}/HasAlt2.cpp
    ${CHOICE_GEN_DIR}/HasAlt4.cpp
    ${CHOICE_GEN_DIR}/Alt2.cpp
    ${CHOICE_GEN_DIR}/Alt4.cpp
    ${CHOICE_GEN_DIR}/MyByte.cpp
    ${CHOICE_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_jer_composite PRIVATE ${CHOICE_GEN_DIR})
target_link_libraries(test_jer_composite PRIVATE asn1cpp_runtime)
add_test(NAME jer_composite COMMAND test_jer_composite)
set_tests_properties(jer_composite PROPERTIES TIMEOUT 30 LABELS "jer")

# ---- JER SEQUENCE OF test (#157/#158) -----------------------------------------
add_executable(test_jer_seqof
    jer/test_jer_seqof.cpp
    ${SEQ_OF_GEN_DIR}/ByteList.cpp
    ${SEQ_OF_GEN_DIR}/StrList.cpp
    ${SEQ_OF_GEN_DIR}/MyByte.cpp
    ${SEQ_OF_GEN_DIR}/MyStr.cpp
)
target_include_directories(test_jer_seqof PRIVATE ${SEQ_OF_GEN_DIR})
target_link_libraries(test_jer_seqof PRIVATE asn1cpp_runtime)
add_test(NAME jer_seqof COMMAND test_jer_seqof)
set_tests_properties(jer_seqof PROPERTIES TIMEOUT 30 LABELS "jer")

# ---- JER test harness (#154 / #155) ----------------------------------------
# #155: type-bundle round-trip (JER→XER vs asn1c XER fixture)
# Still WILL_FAIL — requires jer-to-xer tool (not yet built; needs generic schema compilation)
add_test(NAME jer_bundle_roundtrip
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/jer/run_jer_tests.py
            --verbose)
set_tests_properties(jer_bundle_roundtrip PROPERTIES
    WILL_FAIL TRUE
    TIMEOUT   60
    LABELS    "jer")

# #154 / #159: ETSI-LI JSON xval smoke test — was GREEN (#159) in local dev
# only. Removed from ctest (#292): compare_json.py lives at
# ${CMAKE_SOURCE_DIR}/../asn1cpp-validation-tools/, a sibling directory
# outside this repo that only exists in the local umbrella `etsi/` checkout
# — CI checks out gambas-asn1 alone, so this path never existed there and
# the test failed unconditionally in every CI run. #292 tracks re-adding it
# in a CI-compatible way (vendor the script, or check out the sibling repo
# in CI, or guard registration behind a path-exists check).

# ---- Backend naming interface: CppBackend vs RustBackend (#216/#217/#226/#234) --
add_executable(test_backend_naming
    codegen/test_backend_naming.cpp
    ${CMAKE_SOURCE_DIR}/compiler/src/codegen/CppBackend.cpp
    ${CMAKE_SOURCE_DIR}/compiler/src/codegen/RustBackend.cpp)
target_include_directories(test_backend_naming PRIVATE
    ${CMAKE_SOURCE_DIR}/compiler/src
    ${CMAKE_SOURCE_DIR}/runtime/include)
add_test(NAME backend_naming COMMAND test_backend_naming)

# ---- RustBackend output compile-check (gambas-asn1#258) --------------------
if(WITH_RUST_COMPILE_CHECK)
    add_test(NAME rust_compile_check
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/rust/run_rust_tests.py
                --rustc ${RUSTC_EXECUTABLE})
    set_tests_properties(rust_compile_check PROPERTIES TIMEOUT 60 LABELS "rust")
endif()

# ---- rust-runtime/ber cargo test (gambas-asn1#218) -------------------------
if(WITH_BER_RUNTIME_TEST)
    add_test(NAME ber_runtime_cargo_test
        COMMAND ${CARGO_EXECUTABLE} test --manifest-path
                ${CMAKE_SOURCE_DIR}/rust-runtime/ber/Cargo.toml)
    set_tests_properties(ber_runtime_cargo_test PROPERTIES TIMEOUT 120 LABELS "rust")
endif()

# ---- codegen -> asn1cpp-ber roundtrip (gambas-asn1#219) --------------------
#   Real asn1cpp --target=rust output (Point, from simple_seq.asn1) compiled
#   and roundtrip-tested against the real asn1cpp-ber crate — not a hand-
#   written stand-in. Reuses the exact same generation pattern as
#   SIMPLE_SEQ_GEN_DIR/test_seq_simple above (add_custom_command running the
#   compiler, output consumed by an ALL target so `cmake --build` always
#   keeps it current) and the same cross-validated BER test vectors as
#   seq/test_seq_simple.cpp — same schema, same test data, both languages.
set(RUST_SIMPLE_SEQ_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_rust_simple_seq)
add_custom_command(
    OUTPUT  ${RUST_SIMPLE_SEQ_GEN_DIR}/Point.rs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RUST_SIMPLE_SEQ_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> --target=rust
                                   ${CMAKE_CURRENT_SOURCE_DIR}/asn1/simple_seq.asn1
                                   -o ${RUST_SIMPLE_SEQ_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/simple_seq.asn1
    COMMENT "Generating Rust from simple_seq.asn1"
)

# gambas-asn1#282: broaden Rust SEQUENCE codegen past INTEGER-only (Point) to
# a mixed-type flat SEQUENCE (bool/OCTET STRING/IA5String members). Own
# output directory, not RUST_SIMPLE_SEQ_GEN_DIR — each asn1cpp invocation
# deletes any .rs file in its out-dir that its own run didn't produce
# (Generator::remove_stale_files, keeps generated dirs free of orphans from
# renamed/removed types); two separate compiler invocations sharing one
# out-dir would race to delete each other's output. build.rs
# (tests/rust/roundtrip) copies Point.rs from RUST_SIMPLE_SEQ_GEN_DIR and
# Widget.rs from this directory separately.
set(RUST_WIDE_TYPES_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_rust_wide_types)
add_custom_command(
    OUTPUT  ${RUST_WIDE_TYPES_GEN_DIR}/Widget.rs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RUST_WIDE_TYPES_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> --target=rust
                                   ${CMAKE_CURRENT_SOURCE_DIR}/asn1/rust_wide_types_test.asn1
                                   -o ${RUST_WIDE_TYPES_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/rust_wide_types_test.asn1
    COMMENT "Generating Rust from rust_wide_types_test.asn1"
)

# gambas-asn1#284: table-driven Rust CHOICE codegen. Own output directory,
# same reason as RUST_WIDE_TYPES_GEN_DIR above (separate compiler
# invocations can't share one out-dir).
set(RUST_CHOICE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen_rust_choice)
add_custom_command(
    OUTPUT  ${RUST_CHOICE_GEN_DIR}/Selector.rs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RUST_CHOICE_GEN_DIR}
    COMMAND $<TARGET_FILE:asn1cpp> --target=rust
                                   ${CMAKE_CURRENT_SOURCE_DIR}/asn1/rust_choice_test.asn1
                                   -o ${RUST_CHOICE_GEN_DIR}
    DEPENDS asn1cpp ${CMAKE_CURRENT_SOURCE_DIR}/asn1/rust_choice_test.asn1
    COMMENT "Generating Rust from rust_choice_test.asn1"
)

add_custom_target(gen_rust_simple_seq ALL DEPENDS
    ${RUST_SIMPLE_SEQ_GEN_DIR}/Point.rs
    ${RUST_WIDE_TYPES_GEN_DIR}/Widget.rs
    ${RUST_CHOICE_GEN_DIR}/Selector.rs)

if(WITH_BER_RUNTIME_TEST)
    add_test(NAME rust_roundtrip_test
        COMMAND ${CARGO_EXECUTABLE} test --manifest-path
                ${CMAKE_CURRENT_SOURCE_DIR}/rust/roundtrip/Cargo.toml)
    set_tests_properties(rust_roundtrip_test PROPERTIES
        TIMEOUT 60 LABELS "rust"
        ENVIRONMENT "ASN1CPP_RUST_GEN_DIR=${RUST_SIMPLE_SEQ_GEN_DIR};ASN1CPP_RUST_WIDE_GEN_DIR=${RUST_WIDE_TYPES_GEN_DIR};ASN1CPP_RUST_CHOICE_GEN_DIR=${RUST_CHOICE_GEN_DIR}")
endif()

# gambas-asn1#309: Rust-codegen sweep across tests/asn1/*.asn1 — the Rust
# equivalent of validate_parser.py's C++ parser-conformance sweep (that one
# lives outside this repo, asn1cpp-validation-tools/, because it also needs
# asn1c; this one only needs asn1cpp + cargo, so it's wired into this repo's
# own ctest like every other Rust check here). No requirement that every
# fixture passes — validate_rust_codegen.py itself only exits non-zero on a
# real codegen crash, never on a "construct not yet supported" compile
# failure, so this test stays green as coverage gaps get found and fixed
# incrementally rather than gating the build on 100% coverage.
if(WITH_BER_RUNTIME_TEST)
    add_test(NAME rust_codegen_sweep
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/rust/validate_rust_codegen.py
                --asn1cpp-bin $<TARGET_FILE:asn1cpp>
                --cargo ${CARGO_EXECUTABLE})
    set_tests_properties(rust_codegen_sweep PROPERTIES
        TIMEOUT 300 LABELS "rust")
endif()

# ---- Smoke matrix: 17 types × 4 flag combos (issue #27) --------------------
# Enable with: cmake -DWITH_SMOKE_MATRIX=ON  (default OFF; see Release Testing in doc/book.md)
if(WITH_SMOKE_MATRIX)
    add_test(NAME smoke_matrix
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/run_smoke_matrix.py
                --compiler $<TARGET_FILE:asn1cpp>
                --runtime-inc ${CMAKE_SOURCE_DIR}/runtime/include)
    set_tests_properties(smoke_matrix PROPERTIES TIMEOUT 300)
endif()
