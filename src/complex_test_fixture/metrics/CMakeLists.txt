add_library(metrics STATIC metricA.cpp metricB.cpp)

target_include_directories(metrics PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})