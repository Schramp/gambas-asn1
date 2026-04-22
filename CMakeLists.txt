cmake_minimum_required(VERSION 3.20)
project(asn1cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(BISON 3.8 REQUIRED)
find_program(REFLEX_EXECUTABLE reflex
    PATHS /usr/local/bin
    NO_DEFAULT_PATH
    REQUIRED)

add_subdirectory(runtime)
add_subdirectory(compiler)
add_subdirectory(tests)
