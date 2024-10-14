add_library(child_activity STATIC ChildActivity.cpp)

target_include_directories(child_activity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(child_activity PUBLIC activity)
