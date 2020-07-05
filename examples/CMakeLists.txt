add_executable(example_isc main.cpp)
target_link_libraries(example_isc isc::isc)

set_target_properties(example_isc PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
) 
