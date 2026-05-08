add_library(asn1cpp_runtime STATIC
    src/BerCodec.cpp
    src/XerCodec.cpp
    src/PerCodec.cpp
    src/RandomFiller.cpp
)
target_include_directories(asn1cpp_runtime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(asn1cpp_runtime PUBLIC cxx_std_20)

if(ASN1CPP_VALIDATE)
    target_compile_definitions(asn1cpp_runtime PUBLIC ASN1CPP_VALIDATE=1)
endif()
if(ASN1CPP_VALIDATE_ON_ENCODE)
    target_compile_definitions(asn1cpp_runtime PUBLIC ASN1CPP_VALIDATE_ON_ENCODE=1)
endif()
if(ASN1CPP_VALIDATE_ON_SET)
    target_compile_definitions(asn1cpp_runtime PUBLIC ASN1CPP_VALIDATE_ON_SET=1)
endif()
if(ASN1CPP_VALIDATE_REPORT)
    target_compile_definitions(asn1cpp_runtime PUBLIC ASN1CPP_VALIDATE_REPORT=1)
endif()
