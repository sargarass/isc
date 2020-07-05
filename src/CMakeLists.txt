include(cmake/TargetArch.cmake)

target_architecture(TARGET_ARCH)

add_subdirectory(asm)

add_library(isc STATIC isc.cpp syscall.cpp)
target_include_directories(isc PUBLIC ../include)
target_compile_definitions(isc PRIVATE ${TARGET_ARCH} _GNU_SOURCE)
target_compile_options(isc PRIVATE -O3 -W)
target_link_libraries(isc PRIVATE pthread isc_asm)
add_library(isc::isc ALIAS isc)

set_target_properties(isc PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
)
