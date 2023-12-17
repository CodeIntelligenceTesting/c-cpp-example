cmake_minimum_required(VERSION 3.16)

project(cpp-demo)

# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# External dependencies
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

enable_testing()
include(googletest)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()

add_subdirectory(src/explore_me)
add_subdirectory(src/automotive)
