cmake_minimum_required(VERSION 3.16)

project(cpp-demo)
# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(ABSL_PROPAGATE_CXX_STD ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_testing()
include(GoogleTest)
include(protobuf)
include(libprotobuf-mutator)
enable_fuzz_testing()

add_subdirectory(src/simple_examples)
add_subdirectory(src/state_example)
add_subdirectory(src/advanced_examples)
