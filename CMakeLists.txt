cmake_minimum_required(VERSION 3.16)

project(cpp-demo)
# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(ABSL_PROPAGATE_CXX_STD ON)

# External dependencies
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

enable_testing()
include(googletest)
include(protobuf)
include(libprotobuf-mutator)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()

add_subdirectory(src/simple_examples)
add_subdirectory(src/state_example)
add_subdirectory(src/advanced_examples)
