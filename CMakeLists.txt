cmake_minimum_required(VERSION 3.16)

project(cpp-demo)
option(LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF
        "Automatically download working protobuf" OFF)
# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# External dependencies
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

enable_testing()
include(googletest)
include(libprotobuf-mutator)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()

add_subdirectory(src/simple_examples)
add_subdirectory(src/automotive)
add_subdirectory(src/advanced_examples)
