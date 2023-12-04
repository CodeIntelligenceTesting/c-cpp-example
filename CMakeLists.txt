cmake_minimum_required(VERSION 3.16)

project(AUTOMOTIVE-FUZZING-EXAMPLE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()

add_library(AUTOMOTIVE-FUZZING-EXAMPLE
    modules/crypto_module/src/crypto_module_1.c
    modules/crypto_module/src/crypto_module_2.c
    modules/time_module/src/time_module_1.c
    modules/GPS_module/src/GPS_module_1.c
    modules/key_management_module/src/key_management_module_1.c
)

target_include_directories(AUTOMOTIVE-FUZZING-EXAMPLE PRIVATE
    modules/crypto_module/src
    modules/time_module/src
    modules/key_management_module/src
    modules/GPS_module/src
)

add_fuzz_test(module_fuzzer fuzz_test.cpp mocks.cpp)
target_link_libraries(module_fuzzer PRIVATE AUTOMOTIVE-FUZZING-EXAMPLE)
target_include_directories(module_fuzzer PRIVATE
    modules/crypto_module/src
    modules/time_module/src
    modules/key_management_module/src
    modules/GPS_module/src
)
