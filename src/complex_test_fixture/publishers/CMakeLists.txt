add_library(publishers STATIC PublisherA.cpp PublisherB.cpp)

target_link_libraries(publishers PUBLIC metrics)

target_include_directories(publishers PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})