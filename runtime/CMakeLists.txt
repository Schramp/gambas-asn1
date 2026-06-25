# ---- Compile flags / validate definitions (shared by both build modes) -----

add_library(asn1cpp_runtime_iface INTERFACE)
target_include_directories(asn1cpp_runtime_iface INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(asn1cpp_runtime_iface INTERFACE cxx_std_20)
if(fmt_FOUND)
    target_link_libraries(asn1cpp_runtime_iface INTERFACE fmt::fmt)
endif()

if(ASN1CPP_VALIDATE)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE ASN1CPP_VALIDATE=1)
endif()
if(ASN1CPP_VALIDATE_ON_ENCODE)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE ASN1CPP_VALIDATE_ON_ENCODE=1)
endif()
if(ASN1CPP_VALIDATE_ON_DECODE)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE ASN1CPP_VALIDATE_ON_DECODE=1)
endif()
if(ASN1CPP_VALIDATE_ON_SET)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE ASN1CPP_VALIDATE_ON_SET=1)
endif()
if(ASN1CPP_VALIDATE_REPORT)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE ASN1CPP_VALIDATE_REPORT=1)
endif()

# ---- Object library (compiled once, used by both paths below) --------------

add_library(asn1cpp_runtime_objs OBJECT
    src/BerCodec.cpp
    src/XerCodec.cpp
    src/PerCodec.cpp
    src/RandomFiller.cpp
    src/BuiltinTypes.cpp
    src/DeepCopy.cpp
)
target_link_libraries(asn1cpp_runtime_objs PUBLIC asn1cpp_runtime_iface)

# ---- Static library --------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    # Partial-link: resolve all LTO passes across TUs into a single native
    # object, then archive it. Consumers do not need -flto to link the result.
    set(_LTO_OBJ ${CMAKE_CURRENT_BINARY_DIR}/asn1cpp_runtime_lto.o)
    set(_ARCHIVE  ${CMAKE_CURRENT_BINARY_DIR}/libasn1cpp_runtime.a)

    add_custom_command(
        OUTPUT ${_LTO_OBJ}
        COMMAND ${CMAKE_CXX_COMPILER}
                -flto -O3 -r -nostdlib -o ${_LTO_OBJ}
                $<TARGET_OBJECTS:asn1cpp_runtime_objs>
        DEPENDS $<TARGET_OBJECTS:asn1cpp_runtime_objs>
        COMMAND_EXPAND_LISTS
        COMMENT "Partial-linking asn1cpp_runtime (resolving LTO)"
    )
    add_custom_command(
        OUTPUT ${_ARCHIVE}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${_ARCHIVE}
        COMMAND ${CMAKE_AR} qcs ${_ARCHIVE} ${_LTO_OBJ}
        DEPENDS ${_LTO_OBJ}
        COMMENT "Archiving LTO-resolved asn1cpp_runtime"
    )
    add_custom_target(asn1cpp_runtime_archive ALL DEPENDS ${_ARCHIVE})

    add_library(asn1cpp_runtime STATIC IMPORTED GLOBAL)
    set_target_properties(asn1cpp_runtime PROPERTIES
        IMPORTED_LOCATION ${_ARCHIVE}
    )
    add_dependencies(asn1cpp_runtime asn1cpp_runtime_archive)
    target_link_libraries(asn1cpp_runtime INTERFACE asn1cpp_runtime_iface)
else()
    # Debug: plain static library, no LTO resolution needed.
    add_library(asn1cpp_runtime STATIC $<TARGET_OBJECTS:asn1cpp_runtime_objs>)
    target_link_libraries(asn1cpp_runtime PUBLIC asn1cpp_runtime_iface)
endif()
