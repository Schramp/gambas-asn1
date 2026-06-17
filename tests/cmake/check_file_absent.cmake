# Called by ctest: pass -DFILE=<path>
# Succeeds (exit 0) if FILE does not exist.
# Fails  (exit 1) if FILE exists.
if(NOT DEFINED FILE)
    message(FATAL_ERROR "check_file_absent.cmake: FILE not set")
endif()
if(EXISTS "${FILE}")
    message(FATAL_ERROR "Expected file to be absent but found: ${FILE}")
else()
    message(STATUS "Confirmed absent: ${FILE}")
endif()
