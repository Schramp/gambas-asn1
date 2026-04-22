enable_testing()

# ---- BER primitive unit tests ----------------------------------------------
add_executable(test_ber_primitives ber/test_primitives.cpp)
target_link_libraries(test_ber_primitives PRIVATE asn1cpp_runtime)
add_test(NAME ber_primitives COMMAND test_ber_primitives)

# ---- BER SEQUENCE / CHOICE tests ------------------------------------------
add_executable(test_ber_sequence ber/test_sequence.cpp)
target_link_libraries(test_ber_sequence PRIVATE asn1cpp_runtime)
add_test(NAME ber_sequence COMMAND test_ber_sequence)
