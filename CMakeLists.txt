cmake_minimum_required(VERSION 3.16)

project(cpp-demo)

# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_testing()
include(GoogleTest)
enable_fuzz_testing()

set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER clang)
add_compile_options("-fsanitize=fuzzer,address")

add_subdirectory(src/simple_examples)
