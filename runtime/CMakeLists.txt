add_library(asn1cpp_runtime STATIC
    src/BerCodec.cpp
    src/XerCodec.cpp
    src/PerCodec.cpp
)
target_include_directories(asn1cpp_runtime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(asn1cpp_runtime PUBLIC cxx_std_20)
