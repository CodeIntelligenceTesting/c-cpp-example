add_library(data_processor STATIC data_processor.cpp)

target_include_directories(data_processor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})