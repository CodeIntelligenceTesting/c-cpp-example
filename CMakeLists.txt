cmake_minimum_required(VERSION 3.16)

project(AUTOMOTIVE-FUZZING-TESTSUITE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()
add_subdirectory(googletest)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_library(AUTOMOTIVE-FUZZING-TESTSUITE
        modules/crypto_module/src/crypto_module_1.c
        modules/crypto_module/src/crypto_module_2.c
        modules/time_module/src/time_module_1.c
        modules/GPS_module/src/GPS_module_1.c
        modules/key_management_module/src/key_management_module_1.c
        modules/simple_module/src/person/person.c
        modules/simple_module/src/person/person.h
        modules/simple_module/src/buffer_copy/buffer_copy.c
        modules/simple_module/src/buffer_copy/buffer_copy.h
)

target_include_directories(AUTOMOTIVE-FUZZING-TESTSUITE PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
)

add_fuzz_test(module_fuzzer test/generated_fuzz_test.cpp test/mocks.cpp)
target_link_libraries(module_fuzzer PRIVATE AUTOMOTIVE-FUZZING-TESTSUITE)
target_include_directories(module_fuzzer PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
)

add_executable(
        person_tests
        test/person_tests.cpp
)
target_link_libraries(
        person_tests
        GTest::gtest_main
)
target_include_directories(person_tests PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
        modules/simple_module/src/person
        googletest/googletest/include
)

add_fuzz_test(person_fuzzer test/person_tests.cpp)
target_link_libraries(
        person_tests
)
target_include_directories(person_fuzzer PRIVATE
        modules/simple_module/src/person
        googletest/googletest/include
)

add_executable(
        buffer_copy_tests
        test/buffer_copy_tests.cpp
)
target_link_libraries(
        buffer_copy_tests
        GTest::gtest_main
)
target_include_directories(buffer_copy_tests PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
        modules/simple_module/src/buffer_copy
        googletest/googletest/include
)

add_fuzz_test(buffer_copy_fuzzer test/buffer_copy_fuzz_test.cpp)
target_link_libraries(
        buffer_copy_tests
)
target_include_directories(buffer_copy_fuzzer PRIVATE
        modules/simple_module/src/buffer_copy
        googletest/googletest/include
)

include(GoogleTest)
gtest_discover_tests(person_tests)
gtest_discover_tests(buffer_copy_tests)