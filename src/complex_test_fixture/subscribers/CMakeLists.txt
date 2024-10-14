add_library(subscribers STATIC SubscriberA.cpp)

target_include_directories(subscribers PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})