add_subdirectory(base)
add_subdirectory(child)

add_executable(inheritance main.cpp)

target_link_libraries(inheritance upper_case_processor)