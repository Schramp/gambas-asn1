# Called by ctest: pass -DGEN_ROOT=<dir>
# Scans the generated C++ sources below GEN_ROOT. A namespace-scope table
# whose initializer reads a member of another descriptor (asn_DEF_X.field)
# is dynamically initialized, in an order across translation units that C++
# leaves unspecified, so it may read the other descriptor before it is set.
# Generated descriptors must only take addresses (&asn_DEF_X) and point at
# the runtime's constexpr tables. Fails on the first such initializer line.
if(NOT DEFINED GEN_ROOT)
    message(FATAL_ERROR "check_static_init.cmake: GEN_ROOT not set")
endif()
file(GLOB_RECURSE _sources "${GEN_ROOT}/gen_*/*.cpp")
list(LENGTH _sources _count)
if(_count EQUAL 0)
    message(FATAL_ERROR "check_static_init.cmake: no generated sources below ${GEN_ROOT}")
endif()
set(_bad "")
foreach(_f IN LISTS _sources)
    file(STRINGS "${_f}" _lines REGEX "/\\* constraints \\*/")
    foreach(_l IN LISTS _lines)
        if(_l MATCHES "asn_DEF[A-Za-z0-9_]*\\.")
            string(APPEND _bad "  ${_f}: ${_l}\n")
        endif()
    endforeach()
endforeach()
if(_bad)
    message(FATAL_ERROR "constraints initialized from another descriptor's members:\n${_bad}")
endif()
message(STATUS "checked ${_count} generated sources: no constraints read from another descriptor")
