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
# PER decode limit on list items encoded in zero bits (codec/DecodeDepth.hpp);
# empty keeps the header's default.
set(ASN1CPP_MAX_ZERO_WIDTH_ITEMS "" CACHE STRING
    "PER: most SEQUENCE OF items encoded in zero bits (empty: 200)")
if(ASN1CPP_MAX_ZERO_WIDTH_ITEMS)
    target_compile_definitions(asn1cpp_runtime_iface INTERFACE
        ASN1CPP_MAX_ZERO_WIDTH_ITEMS=${ASN1CPP_MAX_ZERO_WIDTH_ITEMS})
endif()

# ---- Object library (compiled once, used by both paths below) --------------

add_library(asn1cpp_runtime_objs OBJECT
    src/BerCursor.cpp
    src/BerProjection.cpp
    src/BerInspect.cpp
    src/BerCodec.cpp
    src/XerCodec.cpp
    src/JerCodec.cpp
    src/PerCodec.cpp
    src/RandomFiller.cpp
    src/BuiltinTypes.cpp
    src/Real.cpp
    src/DeepCopy.cpp
    src/Contained.cpp
    src/TableDump.cpp
    src/Version.cpp
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
    # The object files are inputs of the partial link above; a file-level
    # DEPENDS on them does not order the target that builds them.
    add_dependencies(asn1cpp_runtime_archive asn1cpp_runtime_objs)

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

# ---- install: headers, libasn1cpp_runtime.a, find_package(asn1cpp) config
install(DIRECTORY include/asn1cpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES $<TARGET_FILE:asn1cpp_runtime> DESTINATION ${CMAKE_INSTALL_LIBDIR})

get_target_property(ASN1CPP_RUNTIME_DEFINITIONS asn1cpp_runtime_iface INTERFACE_COMPILE_DEFINITIONS)
if(NOT ASN1CPP_RUNTIME_DEFINITIONS)
    set(ASN1CPP_RUNTIME_DEFINITIONS "")
endif()
if(fmt_FOUND)
    set(ASN1CPP_USES_FMT TRUE)
else()
    set(ASN1CPP_USES_FMT FALSE)
endif()
include(CMakePackageConfigHelpers)
set(_asn1cpp_cmake_dir ${CMAKE_INSTALL_LIBDIR}/cmake/asn1cpp)
configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/asn1cppConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/asn1cppConfig.cmake
    INSTALL_DESTINATION ${_asn1cpp_cmake_dir}
    PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_BINDIR)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/asn1cppConfigVersion.cmake
    COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asn1cppConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/asn1cppConfigVersion.cmake
        DESTINATION ${_asn1cpp_cmake_dir})

# The Rust runtime crate, as source: a Cargo path dependency on
# <prefix>/share/asn1cpp/rust-runtime/wire.
install(DIRECTORY ${PROJECT_SOURCE_DIR}/rust-runtime/wire/
        DESTINATION ${CMAKE_INSTALL_DATADIR}/asn1cpp/rust-runtime/wire
        PATTERN target EXCLUDE
        PATTERN tests EXCLUDE)
