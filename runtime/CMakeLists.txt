add_library(asn1cpp_runtime INTERFACE)
target_include_directories(asn1cpp_runtime INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(asn1cpp_runtime INTERFACE cxx_std_20)
