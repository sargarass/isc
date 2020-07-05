project(isc C CXX ASM)
cmake_minimum_required(VERSION 3.8)

add_subdirectory(src)

option(BUILD_ISC_EXAMPLES "Build isc's examples" OFF)

if(BUILD_ISC_EXAMPLES)
    add_subdirectory(examples)
endif()
