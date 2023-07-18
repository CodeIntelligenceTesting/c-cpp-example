cmake_minimum_required(VERSION 3.10)

project(AUTOMOTIVE-FUZZING-EXAMPLE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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